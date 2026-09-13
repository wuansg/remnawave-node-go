package system

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNetworkAddressUsesStableWireFieldNames(t *testing.T) {
	encoded, err := json.Marshal(NetworkAddress{
		Address:      "2001:db8::1",
		PrefixLength: 64,
		Family:       "IPv6",
	})
	if err != nil {
		t.Fatal(err)
	}
	wire := string(encoded)
	if !strings.Contains(wire, `"prefix":64`) {
		t.Fatalf("network prefix is missing from wire response: %s", wire)
	}
	if strings.Contains(wire, "prefixLength") {
		t.Fatalf("legacy prefixLength leaked into wire response: %s", wire)
	}
}

func TestNetworkInterfacesReturnsAddressFamilies(t *testing.T) {
	interfaces := NetworkInterfaces()
	if interfaces == nil {
		t.Fatal("network inventory must return an empty slice instead of null")
	}
	for _, networkInterface := range interfaces {
		for _, address := range networkInterface.Addresses {
			if address.Family != "IPv4" && address.Family != "IPv6" {
				t.Fatalf("unexpected address family %q", address.Family)
			}
			if address.PrefixLength < 0 || address.PrefixLength > 128 {
				t.Fatalf("unexpected network prefix %d", address.PrefixLength)
			}
		}
	}
}

func TestParseDefaultRouteInterfacesSupportsIPv4AndIPv6(t *testing.T) {
	ipv4 := strings.NewReader("Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 00000000 0100000A 0003 0 0 100 00000000 0 0 0\neth1 0000A8C0 00000000 0001 0 0 0 00FFFFFF 0 0 0\n")
	if got := parseDefaultRouteInterfaces(ipv4, false); len(got) != 1 || got[0] != "eth0" {
		t.Fatalf("unexpected IPv4 default routes: %#v", got)
	}

	ipv6 := strings.NewReader("00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000064 00000000 00000000 00000003 wan6\n20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001 eth1\n")
	if got := parseDefaultRouteInterfaces(ipv6, true); len(got) != 1 || got[0] != "wan6" {
		t.Fatalf("unexpected IPv6 default routes: %#v", got)
	}
}
