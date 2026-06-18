package coreapi

import (
	"context"
	"fmt"
	"strings"

	proxymancommand "github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	hysteria "github.com/xtls/xray-core/proxy/hysteria/account"
	shadowsocks "github.com/xtls/xray-core/proxy/shadowsocks"
	shadowsocks2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	vless "github.com/xtls/xray-core/proxy/vless"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type User struct {
	Type       string
	Username   string
	Password   string
	UUID       string
	Flow       string
	CipherType int
	IVCheck    bool
}

type InboundUser struct {
	Username string
	Level    uint32
	Protocol string
}

type HandlerClient interface {
	AddUser(context.Context, string, User) error
	RemoveUser(context.Context, string, string) error
	InboundUsers(context.Context, string) ([]InboundUser, error)
	InboundUsersCount(context.Context, string) (int64, error)
	RemoveOutbound(context.Context, string) error
	Close() error
}

type GRPCHandlerClient struct {
	conn   *grpc.ClientConn
	client proxymancommand.HandlerServiceClient
}

func NewXrayHandlerClient(target string, transport credentials.TransportCredentials) (*GRPCHandlerClient, error) {
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(transport))
	if err != nil {
		return nil, err
	}
	return &GRPCHandlerClient{conn: conn, client: proxymancommand.NewHandlerServiceClient(conn)}, nil
}

func (c *GRPCHandlerClient) AddUser(ctx context.Context, tag string, user User) error {
	account, err := userAccount(user)
	if err != nil {
		return err
	}
	_, err = c.client.AlterInbound(ctx, &proxymancommand.AlterInboundRequest{
		Tag: tag,
		Operation: serial.ToTypedMessage(&proxymancommand.AddUserOperation{User: &protocol.User{
			Email: user.Username, Level: 0, Account: account,
		}}),
	})
	return err
}

func userAccount(user User) (*serial.TypedMessage, error) {
	switch user.Type {
	case "trojan":
		return serial.ToTypedMessage(&trojan.Account{Password: user.Password}), nil
	case "vless":
		return serial.ToTypedMessage(&vless.Account{Id: user.UUID, Flow: user.Flow, Encryption: "none"}), nil
	case "shadowsocks":
		return serial.ToTypedMessage(&shadowsocks.Account{Password: user.Password, CipherType: shadowsocks.CipherType(user.CipherType), IvCheck: user.IVCheck}), nil
	case "shadowsocks22":
		return serial.ToTypedMessage(&shadowsocks2022.Account{Key: user.Password}), nil
	case "hysteria":
		return serial.ToTypedMessage(&hysteria.Account{Auth: user.Password}), nil
	default:
		return nil, fmt.Errorf("unsupported Xray user type %q", user.Type)
	}
}

func (c *GRPCHandlerClient) RemoveUser(ctx context.Context, tag, username string) error {
	_, err := c.client.AlterInbound(ctx, &proxymancommand.AlterInboundRequest{
		Tag: tag, Operation: serial.ToTypedMessage(&proxymancommand.RemoveUserOperation{Email: username}),
	})
	return err
}

func (c *GRPCHandlerClient) InboundUsers(ctx context.Context, tag string) ([]InboundUser, error) {
	response, err := c.client.GetInboundUsers(ctx, &proxymancommand.GetInboundUserRequest{Tag: tag})
	if err != nil {
		return nil, err
	}
	users := make([]InboundUser, 0, len(response.GetUsers()))
	for _, user := range response.GetUsers() {
		kind := ""
		if account := user.GetAccount(); account != nil {
			parts := strings.Split(account.GetType(), ".")
			if len(parts) > 2 {
				kind = parts[len(parts)-2]
			}
		}
		users = append(users, InboundUser{Username: user.GetEmail(), Level: user.GetLevel(), Protocol: kind})
	}
	return users, nil
}

func (c *GRPCHandlerClient) InboundUsersCount(ctx context.Context, tag string) (int64, error) {
	response, err := c.client.GetInboundUsersCount(ctx, &proxymancommand.GetInboundUserRequest{Tag: tag})
	if err != nil {
		return 0, err
	}
	return response.GetCount(), nil
}

func (c *GRPCHandlerClient) RemoveOutbound(ctx context.Context, tag string) error {
	_, err := c.client.RemoveOutbound(ctx, &proxymancommand.RemoveOutboundRequest{Tag: tag})
	return err
}

func (c *GRPCHandlerClient) Close() error { return c.conn.Close() }
