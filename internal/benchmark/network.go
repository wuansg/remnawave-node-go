package benchmark

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func parseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || len(raw) > 2048 {
		return nil, errors.New("target must be an HTTP(S) URL without credentials")
	}
	if u.Port() != "" && u.Port() != "443" && u.Port() != "8443" && u.Port() != "80" {
		return nil, errors.New("target port is not allowed")
	}
	return u, nil
}
func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, s := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "2001::/23", "2002::/16", "3fff::/20", "64:ff9b::/96", "64:ff9b:1::/48", "::/96"} {
		if netip.MustParsePrefix(s).Contains(ip) {
			return false
		}
	}
	return true
}

var makeClient = pinnedClient
var lookupTargetIPs = net.DefaultResolver.LookupNetIP

func sourceAddress(req Request) (*net.TCPAddr, error) {
	raw := req.SourceIP
	if req.Interface != "" {
		iface, err := net.InterfaceByName(req.Interface)
		if err != nil {
			return nil, err
		}
		as, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range as {
			ip, _, err := net.ParseCIDR(a.String())
			if err == nil && ((req.Family == "IPv4") == (ip.To4() != nil)) && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				raw = ip.String()
				break
			}
		}
		if raw == "" {
			return nil, errors.New("interface has no address of selected family")
		}
	}
	if raw == "" {
		return nil, nil
	}
	ip := net.ParseIP(raw)
	if ip == nil || ((req.Family == "IPv4") != (ip.To4() != nil)) {
		return nil, errors.New("source IP family does not match")
	}
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, a := range as {
		local, _, _ := net.ParseCIDR(a.String())
		if local.Equal(ip) {
			return &net.TCPAddr{IP: ip}, nil
		}
	}
	return nil, errors.New("source IP is not assigned to node")
}
func pinnedClient(ctx context.Context, req Request, raw string) (*http.Client, string, *net.Dialer, error) {
	u, err := parseURL(raw)
	if err != nil {
		return nil, "", nil, err
	}
	local, err := sourceAddress(req)
	if err != nil {
		return nil, "", nil, err
	}
	ips, err := lookupTargetIPs(ctx, "ip", u.Hostname())
	if err != nil {
		return nil, "", nil, errors.New("target DNS lookup failed")
	}
	var selected netip.Addr
	for _, ip := range ips {
		if !publicIP(ip) {
			return nil, "", nil, errors.New("target DNS contains a non-public address")
		}
		if !selected.IsValid() && ((req.Family == "IPv4") == ip.Unmap().Is4()) {
			selected = ip.Unmap()
		}
	}
	if !selected.IsValid() {
		return nil, "", nil, errors.New("target does not support selected address family")
	}
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	addr := net.JoinHostPort(selected.String(), port)
	dialer := &net.Dialer{Timeout: 3 * time.Second, LocalAddr: local}
	if req.Interface != "" {
		dialer.Control = func(_, _ string, socket syscall.RawConn) error {
			var bindErr error
			if err := socket.Control(func(fd uintptr) {
				bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, req.Interface)
			}); err != nil {
				return err
			}
			return bindErr
		}
	}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, MaxIdleConnsPerHost: 2, TLSHandshakeTimeout: 4 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DialContext: func(c context.Context, _, address string) (net.Conn, error) {
		if address != net.JoinHostPort(u.Hostname(), port) {
			return nil, errors.New("cross-host request denied")
		}
		return dialer.DialContext(c, "tcp", addr)
	}}
	return &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("target redirects are not allowed") }}, addr, dialer, nil
}

type countReader struct {
	r io.Reader
	n atomic.Int64
}

func (c *countReader) Read(b []byte) (int, error) {
	n, e := c.r.Read(b)
	c.n.Add(int64(n))
	return n, e
}
func transfer(ctx context.Context, req Request, raw string, upload bool) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(req.Seconds)*time.Second)
	defer cancel()
	client, addr, _, err := makeClient(ctx, req, raw)
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()
	u, _ := url.Parse(raw)
	q := u.Query()
	q.Set("r", strconv.FormatInt(time.Now().UnixNano(), 10))
	u.RawQuery = q.Encode()
	method := http.MethodGet
	var body *countReader
	var reader io.Reader
	if upload {
		method = http.MethodPost
		body = &countReader{r: io.LimitReader(rand.Reader, req.BytesPerDirection)}
		reader = body
	}
	request, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("User-Agent", "Remnanode-Benchmark/1")
	request.Header.Set("Accept-Encoding", "identity")
	if upload {
		request.ContentLength = req.BytesPerDirection
		request.Header.Set("Content-Type", "application/octet-stream")
	} else {
		request.Header.Set("Range", fmt.Sprintf("bytes=0-%d", req.BytesPerDirection-1))
	}
	start := time.Now()
	response, err := client.Do(request)
	var n int64
	if response != nil {
		defer response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return nil, fmt.Errorf("test endpoint HTTP %d", response.StatusCode)
		}
		if !upload {
			if strings.Contains(response.Header.Get("Content-Type"), "text/html") {
				return nil, errors.New("endpoint returned HTML instead of test data")
			}
			n, err = io.Copy(io.Discard, io.LimitReader(response.Body, req.BytesPerDirection))
		} else {
			_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		}
	}
	if body != nil {
		n = body.n.Load()
	}
	seconds := time.Since(start).Seconds()
	metrics := map[string]any{"bytes": n, "durationSeconds": seconds, "mbps": float64(n) * 8 / seconds / 1e6, "remoteAddress": addr, "sample": "bounded HTTP throughput including connection setup"}
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded && n > 0 {
			metrics["timeLimited"] = true
			return metrics, nil
		}
		return metrics, errors.New("network transfer failed or was cancelled")
	}
	if upload && n != req.BytesPerDirection {
		return metrics, errors.New("upload endpoint did not consume the complete request")
	}
	if n == 0 {
		return metrics, errors.New("endpoint returned no test data")
	}
	return metrics, nil
}
func networkTest(ctx context.Context, req Request, t Target) Item {
	result := Item{Name: t.City, Status: "COMPLETED", Metrics: map[string]any{"target": t, "family": req.Family}}
	for _, item := range req.Items {
		if ctx.Err() != nil {
			return result
		}
		var metrics map[string]any
		var err error
		switch item {
		case "latency":
			phase, cancel := context.WithTimeout(ctx, time.Duration(req.Seconds)*time.Second)
			client, addr, dialer, e := pinnedClient(phase, req, t.DownloadURL)
			err = e
			if err == nil {
				client.CloseIdleConnections()
				samples := []float64{}
				failed := 0
				attempted := 0
				for i := 0; i < 5 && phase.Err() == nil; i++ {
					attempted++
					start := time.Now()
					conn, e := dialer.DialContext(phase, "tcp", addr)
					if e != nil {
						failed++
					} else {
						samples = append(samples, float64(time.Since(start).Microseconds())/1000)
						conn.Close()
					}
				}
				sort.Float64s(samples)
				metrics = map[string]any{"samples": len(samples), "attempts": attempted, "failures": failed, "remoteAddress": addr}
				if attempted > 0 {
					metrics["tcpFailurePercent"] = float64(failed) * 100 / float64(attempted)
				}
				if len(samples) > 0 {
					metrics["p50Ms"] = samples[(len(samples)-1)/2]
					metrics["p95Ms"] = samples[len(samples)-1]
					metrics["spreadMs"] = samples[len(samples)-1] - samples[0]
				} else {
					err = errors.New("all TCP latency samples failed")
				}
			}
			cancel()
		case "download":
			metrics, err = transfer(ctx, req, t.DownloadURL, false)
		case "upload":
			if t.UploadURL == "" {
				result.Metrics[item] = map[string]any{"status": "UNSUPPORTED", "message": "Endpoint does not offer upload testing"}
				continue
			}
			metrics, err = transfer(ctx, req, t.UploadURL, true)
		}
		if err != nil {
			result.Status = "FAILED"
			if metrics == nil {
				metrics = map[string]any{}
			}
			metrics["status"] = "FAILED"
			metrics["message"] = err.Error()
			result.Metrics[item] = metrics
		} else {
			result.Metrics[item] = metrics
		}
	}
	return result
}
