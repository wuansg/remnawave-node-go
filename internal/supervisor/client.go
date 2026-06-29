package supervisor

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	StateStopped  = 0
	StateStarting = 10
	StateRunning  = 20
	StateStopping = 40
	StateExited   = 100
	StateFatal    = 200
)

type ProcessInfo struct {
	Name      string `json:"name"`
	State     int    `json:"state"`
	StateName string `json:"statename"`
	Raw       string `json:"raw"`
}

type Client struct {
	socketPath string
	username   string
	password   string
	httpClient *http.Client
}

func New(socketPath, username, password string) *Client {
	client := &Client{
		socketPath: socketPath,
		username:   username,
		password:   password,
	}
	client.httpClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", client.socketPath)
			},
		},
	}
	return client
}

func (c *Client) GetState(ctx context.Context) error {
	if c.socketPath == "" {
		return errors.New("supervisord socket path is empty")
	}
	_, err := c.call(ctx, "supervisor.getState")
	return err
}

func (c *Client) StartProcess(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("process name is empty")
	}
	_, err := c.call(ctx, "supervisor.startProcess", name, true)
	return err
}

func (c *Client) StopProcess(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("process name is empty")
	}
	_, err := c.call(ctx, "supervisor.stopProcess", name, true)
	return err
}

func (c *Client) GetProcessInfo(ctx context.Context, name string) (ProcessInfo, error) {
	if name == "" {
		return ProcessInfo{}, errors.New("process name is empty")
	}
	value, err := c.call(ctx, "supervisor.getProcessInfo", name)
	if err != nil {
		return ProcessInfo{}, err
	}

	info := value.Struct
	stateName := strings.ToUpper(info["statename"].String)
	state := info["state"].Int
	if stateName == "" {
		stateName = mapStateName(state)
	}
	return ProcessInfo{
		Name:      stringOrDefault(info["name"].String, name),
		StateName: stateName,
		State:     state,
		Raw:       info["description"].String,
	}, nil
}

func (c *Client) call(ctx context.Context, method string, params ...any) (xmlRPCValue, error) {
	if c.socketPath == "" {
		return xmlRPCValue{}, errors.New("supervisord socket path is empty")
	}
	body, err := marshalCall(method, params...)
	if err != nil {
		return xmlRPCValue{}, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/RPC2", bytes.NewReader(body))
	if err != nil {
		return xmlRPCValue{}, err
	}
	request.Header.Set("Content-Type", "text/xml")
	if c.username != "" || c.password != "" {
		request.SetBasicAuth(c.username, c.password)
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return xmlRPCValue{}, err
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return xmlRPCValue{}, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return xmlRPCValue{}, fmt.Errorf("supervisord %s failed: HTTP %d (%s)", method, response.StatusCode, strings.TrimSpace(string(responseBody)))
	}

	var rpcResponse methodResponse
	if err := xml.Unmarshal(responseBody, &rpcResponse); err != nil {
		return xmlRPCValue{}, fmt.Errorf("supervisord %s returned invalid XML: %w", method, err)
	}
	if rpcResponse.Fault != nil {
		fault := rpcResponse.Fault.Value.Struct
		return xmlRPCValue{}, fmt.Errorf("supervisord %s fault %d: %s", method, fault["faultCode"].Int, fault["faultString"].String)
	}
	if len(rpcResponse.Params) == 0 {
		return xmlRPCValue{}, nil
	}
	return rpcResponse.Params[0].Value, nil
}

func marshalCall(method string, params ...any) ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteString(`<?xml version="1.0"?>`)
	buffer.WriteString("<methodCall><methodName>")
	if err := xml.EscapeText(&buffer, []byte(method)); err != nil {
		return nil, err
	}
	buffer.WriteString("</methodName><params>")
	for _, param := range params {
		buffer.WriteString("<param><value>")
		switch value := param.(type) {
		case string:
			buffer.WriteString("<string>")
			if err := xml.EscapeText(&buffer, []byte(value)); err != nil {
				return nil, err
			}
			buffer.WriteString("</string>")
		case bool:
			if value {
				buffer.WriteString("<boolean>1</boolean>")
			} else {
				buffer.WriteString("<boolean>0</boolean>")
			}
		default:
			return nil, fmt.Errorf("unsupported XML-RPC param type %T", param)
		}
		buffer.WriteString("</value></param>")
	}
	buffer.WriteString("</params></methodCall>")
	return buffer.Bytes(), nil
}

func mapState(state string) int {
	switch state {
	case "RUNNING":
		return StateRunning
	case "STARTING":
		return StateStarting
	case "STOPPING":
		return StateStopping
	case "EXITED", "STOPPED":
		return StateStopped
	case "FATAL", "BACKOFF":
		return StateFatal
	default:
		return StateStopped
	}
}

func mapStateName(state int) string {
	switch state {
	case StateRunning:
		return "RUNNING"
	case StateStarting:
		return "STARTING"
	case StateStopping:
		return "STOPPING"
	case StateExited:
		return "EXITED"
	case StateFatal:
		return "FATAL"
	default:
		return "STOPPED"
	}
}

func stringOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

type methodResponse struct {
	Params []struct {
		Value xmlRPCValue `xml:"value"`
	} `xml:"params>param"`
	Fault *struct {
		Value xmlRPCValue `xml:"value"`
	} `xml:"fault"`
}

type xmlRPCValue struct {
	String string
	Int    int
	Bool   bool
	Struct map[string]xmlRPCValue
}

func (v *xmlRPCValue) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	var text string
	for {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch element := token.(type) {
		case xml.StartElement:
			switch element.Name.Local {
			case "string":
				if err := decoder.DecodeElement(&v.String, &element); err != nil {
					return err
				}
			case "int", "i4":
				if err := decoder.DecodeElement(&v.Int, &element); err != nil {
					return err
				}
			case "boolean":
				var raw string
				if err := decoder.DecodeElement(&raw, &element); err != nil {
					return err
				}
				v.Bool = raw == "1" || strings.EqualFold(raw, "true")
			case "struct":
				members, err := decodeStruct(decoder, element)
				if err != nil {
					return err
				}
				v.Struct = members
			default:
				if err := decoder.Skip(); err != nil {
					return err
				}
			}
		case xml.CharData:
			text += string(element)
		case xml.EndElement:
			if element.Name.Local == start.Name.Local {
				if v.String == "" && v.Int == 0 && v.Struct == nil {
					v.String = strings.TrimSpace(text)
				}
				return nil
			}
		}
	}
}

func decodeStruct(decoder *xml.Decoder, start xml.StartElement) (map[string]xmlRPCValue, error) {
	members := map[string]xmlRPCValue{}
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		switch element := token.(type) {
		case xml.StartElement:
			if element.Name.Local != "member" {
				if err := decoder.Skip(); err != nil {
					return nil, err
				}
				continue
			}
			name, value, err := decodeMember(decoder, element)
			if err != nil {
				return nil, err
			}
			members[name] = value
		case xml.EndElement:
			if element.Name.Local == start.Name.Local {
				return members, nil
			}
		}
	}
}

func decodeMember(decoder *xml.Decoder, start xml.StartElement) (string, xmlRPCValue, error) {
	var name string
	var value xmlRPCValue
	for {
		token, err := decoder.Token()
		if err != nil {
			return "", xmlRPCValue{}, err
		}
		switch element := token.(type) {
		case xml.StartElement:
			switch element.Name.Local {
			case "name":
				if err := decoder.DecodeElement(&name, &element); err != nil {
					return "", xmlRPCValue{}, err
				}
			case "value":
				if err := decoder.DecodeElement(&value, &element); err != nil {
					return "", xmlRPCValue{}, err
				}
			default:
				if err := decoder.Skip(); err != nil {
					return "", xmlRPCValue{}, err
				}
			}
		case xml.EndElement:
			if element.Name.Local == start.Name.Local {
				return name, value, nil
			}
		}
	}
}
