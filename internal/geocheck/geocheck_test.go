package geocheck

import (
	"net"
	"testing"
)

func TestValidateRequestRejectsConflictingBinding(t *testing.T) {
	if _, err := validateRequest(Request{IP: "127.0.0.1", Interface: "lo"}); err == nil {
		t.Fatal("expected conflicting ip and interface to fail")
	}
}

func TestValidateRequestRejectsInvalidIP(t *testing.T) {
	if _, err := validateRequest(Request{IP: "not-an-ip"}); err == nil {
		t.Fatal("expected invalid ip to fail")
	}
}

func TestValidateRequestAcceptsAssignedIP(t *testing.T) {
	addresses, err := net.InterfaceAddrs()
	if err != nil || len(addresses) == 0 {
		t.Skip("no local interface addresses")
	}
	var ip net.IP
	for _, address := range addresses {
		if network, ok := address.(*net.IPNet); ok {
			ip = network.IP
			break
		}
	}
	if ip == nil {
		t.Skip("no usable local address")
	}
	if value, err := validateRequest(Request{IP: ip.String()}); err != nil || value != ip.String() {
		t.Fatalf("expected assigned IP to pass, value=%q err=%v", value, err)
	}
}

func TestLimitBufferCapsOutput(t *testing.T) {
	buffer := newLimitBuffer(4)
	if _, err := buffer.Write([]byte("12345")); err == nil {
		t.Fatal("expected oversized write to fail")
	}
	if got := buffer.String(); got != "1234" {
		t.Fatalf("unexpected buffer contents %q", got)
	}
}
