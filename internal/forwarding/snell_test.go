package forwarding

import "testing"

func TestSnellOnlyReservesTCP(t *testing.T) {
	listeners := ExtractCoreListeners("SING_BOX", map[string]any{"inbounds": []any{map[string]any{
		"type": "snell", "tag": "snell", "listen": "0.0.0.0", "listen_port": 54320,
	}}})
	if len(listeners) != 1 || listeners[0].Protocol != ProtocolTCP || listeners[0].Port != 54320 {
		t.Fatalf("Snell transports UDP over TCP, unexpected listeners: %#v", listeners)
	}
}
