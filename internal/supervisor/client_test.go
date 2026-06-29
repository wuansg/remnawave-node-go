package supervisor

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestXMLRPCProcessInfoResponse(t *testing.T) {
	raw := `<?xml version="1.0"?>
<methodResponse>
  <params>
    <param>
      <value>
        <struct>
          <member><name>name</name><value><string>sing-box</string></value></member>
          <member><name>state</name><value><int>20</int></value></member>
          <member><name>statename</name><value><string>RUNNING</string></value></member>
          <member><name>description</name><value><string>pid 123, uptime 0:01:02</string></value></member>
        </struct>
      </value>
    </param>
  </params>
</methodResponse>`

	var response methodResponse
	if err := xml.Unmarshal([]byte(raw), &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	value := response.Params[0].Value.Struct
	if got := value["name"].String; got != "sing-box" {
		t.Fatalf("name = %q", got)
	}
	if got := value["state"].Int; got != StateRunning {
		t.Fatalf("state = %d", got)
	}
	if got := value["statename"].String; got != "RUNNING" {
		t.Fatalf("statename = %q", got)
	}
}

func TestXMLRPCFaultResponse(t *testing.T) {
	raw := `<?xml version="1.0"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member><name>faultCode</name><value><int>10</int></value></member>
        <member><name>faultString</name><value><string>BAD_NAME: no such process</string></value></member>
      </struct>
    </value>
  </fault>
</methodResponse>`

	var response methodResponse
	if err := xml.Unmarshal([]byte(raw), &response); err != nil {
		t.Fatalf("unmarshal fault: %v", err)
	}
	if response.Fault == nil {
		t.Fatal("fault is nil")
	}
	fault := response.Fault.Value.Struct
	if got := fault["faultCode"].Int; got != 10 {
		t.Fatalf("faultCode = %d", got)
	}
	if got := fault["faultString"].String; !strings.Contains(got, "BAD_NAME") {
		t.Fatalf("faultString = %q", got)
	}
}

func TestMarshalCallEscapesParams(t *testing.T) {
	body, err := marshalCall("supervisor.getProcessInfo", `xray&"core"`)
	if err != nil {
		t.Fatalf("marshalCall: %v", err)
	}
	raw := string(body)
	if !strings.Contains(raw, "xray&amp;&#34;core&#34;") {
		t.Fatalf("escaped param missing from %s", raw)
	}
}
