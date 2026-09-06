package forwarding

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func ExtractCoreListeners(coreType string, config map[string]any) []Listener {
	items, ok := config["inbounds"].([]any)
	if !ok {
		if typed, ok := config["inbounds"].([]map[string]any); ok {
			items = make([]any, len(typed))
			for i := range typed {
				items[i] = typed[i]
			}
		}
	}
	result := make([]Listener, 0, len(items))
	for index, raw := range items {
		inbound, ok := raw.(map[string]any)
		if !ok || loopbackOnly(inbound["listen"]) {
			continue
		}
		port := integerValue(inbound["listen_port"])
		if port == 0 {
			port = integerValue(inbound["listenPort"])
		}
		if port == 0 {
			port = integerValue(inbound["port"])
		}
		if port < 1 || port > 65535 {
			continue
		}
		tag := stringValue(inbound["tag"])
		if tag == "" {
			tag = fmt.Sprintf("inbound[%d]", index)
		}
		for _, protocol := range inferProtocols(coreType, inbound) {
			result = append(result, Listener{Protocol: protocol, Port: port, Source: tag})
		}
	}
	return result
}

func inferProtocols(coreType string, inbound map[string]any) []Protocol {
	if values := networkValues(inbound["network"]); len(values) > 0 {
		return values
	}
	kind := strings.ToLower(stringValue(inbound["type"]))
	if kind == "" {
		kind = strings.ToLower(stringValue(inbound["protocol"]))
	}
	if strings.EqualFold(coreType, "SING_BOX") {
		switch kind {
		case "anytls", "trojan", "vless", "http", "naive", "shadowtls":
			return []Protocol{ProtocolTCP}
		case "hysteria", "hysteria2", "tuic", "quic":
			return []Protocol{ProtocolUDP}
		case "shadowsocks", "mixed", "socks", "direct", "tun":
			return []Protocol{ProtocolTCP, ProtocolUDP}
		}
	}
	return []Protocol{ProtocolTCP, ProtocolUDP}
}

func networkValues(value any) []Protocol {
	values := []string{}
	switch typed := value.(type) {
	case string:
		values = strings.FieldsFunc(strings.ToLower(typed), func(r rune) bool { return r == ',' || r == ' ' })
	case []any:
		for _, item := range typed {
			if text, ok := item.(string); ok {
				values = append(values, strings.ToLower(text))
			}
		}
	}
	seen := map[Protocol]bool{}
	result := []Protocol{}
	for _, value := range values {
		var protocol Protocol
		switch value {
		case "tcp":
			protocol = ProtocolTCP
		case "udp":
			protocol = ProtocolUDP
		default:
			continue
		}
		if !seen[protocol] {
			seen[protocol] = true
			result = append(result, protocol)
		}
	}
	return result
}

func loopbackOnly(value any) bool {
	text := strings.TrimSpace(stringValue(value))
	if text == "" {
		return false
	}
	host := strings.Trim(text, "[]")
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func integerValue(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case jsonNumber:
		result, _ := strconv.Atoi(string(typed))
		return result
	case string:
		result, _ := strconv.Atoi(typed)
		return result
	default:
		return 0
	}
}

type jsonNumber string
