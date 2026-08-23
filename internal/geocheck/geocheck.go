package geocheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"
)

const (
	DefaultBinaryPath = "/usr/local/bin/geocheck"
	DefaultTimeout    = 45 * time.Second
	MaxOutputBytes    = 32 * 1024 * 1024
	maxErrorBytes     = 64 * 1024
)

var ErrAlreadyRunning = errors.New("geocheck: a run is already in progress")

type Request struct {
	IP        string `json:"ip,omitempty"`
	Interface string `json:"interface,omitempty"`
}

type Runner struct {
	binary  string
	running atomic.Bool
}

func New(binary string) *Runner {
	if strings.TrimSpace(binary) == "" {
		binary = DefaultBinaryPath
	}
	return &Runner{binary: binary}
}

func (r *Runner) Run(ctx context.Context, request Request) (map[string]any, error) {
	bindTo, err := validateRequest(request)
	if err != nil {
		return nil, err
	}
	if !r.running.CompareAndSwap(false, true) {
		return nil, ErrAlreadyRunning
	}
	defer r.running.Store(false)

	if info, err := os.Stat(r.binary); err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		if err == nil {
			err = errors.New("binary is not executable")
		}
		return nil, fmt.Errorf("geocheck binary %q is unavailable: %w", r.binary, err)
	}

	runCtx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()
	args := make([]string, 0, 6)
	if bindTo != "" {
		args = append(args, "--interface", bindTo)
	}
	args = append(args, "--json", "--svg-base64", "--quiet")

	stdout := newLimitBuffer(MaxOutputBytes)
	stderr := newLimitBuffer(maxErrorBytes)
	cmd := exec.CommandContext(runCtx, r.binary, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("geocheck exceeded %s", DefaultTimeout)
		}
		message := strings.TrimSpace(stderr.String())
		if message != "" {
			return nil, fmt.Errorf("geocheck failed: %w: %s", err, message)
		}
		return nil, fmt.Errorf("geocheck failed: %w", err)
	}

	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return nil, fmt.Errorf("decode geocheck report: %w", err)
	}
	image, ok := report["image"].(map[string]any)
	if !ok || image["format"] != "svg" || image["media_type"] != "image/svg+xml" || image["encoding"] != "base64" {
		return nil, errors.New("geocheck report carries an invalid SVG image descriptor")
	}
	data, ok := image["data"].(string)
	if !ok || data == "" {
		return nil, errors.New("geocheck report carries no image")
	}
	return report, nil
}

func validateRequest(request Request) (string, error) {
	ip := strings.TrimSpace(request.IP)
	ifaceName := strings.TrimSpace(request.Interface)
	if ip != "" && ifaceName != "" {
		return "", errors.New("geocheck accepts either ip or interface, not both")
	}
	if ip != "" {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return "", fmt.Errorf("geocheck IP %q is invalid", ip)
		}
		assigned, err := isLocalIP(parsed)
		if err != nil {
			return "", fmt.Errorf("inspect local addresses: %w", err)
		}
		if !assigned {
			return "", fmt.Errorf("geocheck IP %q is not assigned to this node", ip)
		}
		return ip, nil
	}
	if ifaceName != "" {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return "", fmt.Errorf("geocheck interface %q does not exist", ifaceName)
		}
		if iface.Flags&net.FlagUp == 0 {
			return "", fmt.Errorf("geocheck interface %q is down", ifaceName)
		}
		return ifaceName, nil
	}
	return "", nil
}

func isLocalIP(target net.IP) (bool, error) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return false, err
	}
	for _, address := range addresses {
		var candidate net.IP
		switch value := address.(type) {
		case *net.IPNet:
			candidate = value.IP
		case *net.IPAddr:
			candidate = value.IP
		}
		if candidate != nil && candidate.Equal(target) {
			return true, nil
		}
	}
	return false, nil
}

type limitBuffer struct {
	buffer bytes.Buffer
	max    int
}

func newLimitBuffer(max int) *limitBuffer { return &limitBuffer{max: max} }

func (b *limitBuffer) Write(p []byte) (int, error) {
	if b.buffer.Len()+len(p) > b.max {
		remaining := b.max - b.buffer.Len()
		if remaining > 0 {
			_, _ = b.buffer.Write(p[:remaining])
		}
		return len(p), fmt.Errorf("geocheck output exceeds %d bytes", b.max)
	}
	return b.buffer.Write(p)
}

func (b *limitBuffer) Bytes() []byte  { return b.buffer.Bytes() }
func (b *limitBuffer) String() string { return b.buffer.String() }
