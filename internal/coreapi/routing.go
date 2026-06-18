package coreapi

import (
	"context"
	"fmt"
	"net"

	router "github.com/xtls/xray-core/app/router"
	routercommand "github.com/xtls/xray-core/app/router/command"
	"github.com/xtls/xray-core/common/serial"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type RoutingClient interface {
	AddSourceIPRule(context.Context, string, string, string, bool) error
	RemoveRule(context.Context, string) error
	Close() error
}

type GRPCRoutingClient struct {
	conn   *grpc.ClientConn
	client routercommand.RoutingServiceClient
}

func NewXrayRoutingClient(target string, transport credentials.TransportCredentials) (*GRPCRoutingClient, error) {
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(transport))
	if err != nil {
		return nil, err
	}
	return &GRPCRoutingClient{conn: conn, client: routercommand.NewRoutingServiceClient(conn)}, nil
}

func (c *GRPCRoutingClient) AddSourceIPRule(ctx context.Context, ruleTag, outbound, address string, appendRule bool) error {
	ip := net.ParseIP(address)
	if ip == nil {
		return fmt.Errorf("invalid IP address %q", address)
	}
	prefix := uint32(128)
	if ipv4 := ip.To4(); ipv4 != nil {
		ip, prefix = ipv4, 32
	} else {
		ip = ip.To16()
	}
	config := &router.Config{Rule: []*router.RoutingRule{{
		TargetTag:   &router.RoutingRule_Tag{Tag: outbound},
		RuleTag:     ruleTag,
		SourceGeoip: []*router.GeoIP{{Cidr: []*router.CIDR{{Ip: []byte(ip), Prefix: prefix}}}},
	}}}
	_, err := c.client.AddRule(ctx, &routercommand.AddRuleRequest{Config: serial.ToTypedMessage(config), ShouldAppend: appendRule})
	return err
}

func (c *GRPCRoutingClient) RemoveRule(ctx context.Context, ruleTag string) error {
	_, err := c.client.RemoveRule(ctx, &routercommand.RemoveRuleRequest{RuleTag: ruleTag})
	return err
}

func (c *GRPCRoutingClient) Close() error { return c.conn.Close() }
