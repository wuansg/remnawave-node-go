package coreapi

import (
	"context"
	"fmt"

	statscommand "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	xrayStatsService    = "xray.app.stats.command.StatsService"
	singBoxStatsService = "v2ray.core.app.stats.command.StatsService"
)

type Stat struct {
	Name  string
	Value int64
}

type SystemStats struct {
	NumGoroutine uint32
	NumGC        uint32
	Alloc        uint64
	TotalAlloc   uint64
	Sys          uint64
	Mallocs      uint64
	Frees        uint64
	LiveObjects  uint64
	PauseTotalNs uint64
	Uptime       uint32
}

type StatsClient interface {
	Query(context.Context, string, bool) ([]Stat, error)
	System(context.Context) (SystemStats, error)
	Online(context.Context, string) (bool, error)
	UserIPs(context.Context, string) (map[string]int64, error)
	OnlineUsers(context.Context) ([]string, error)
	Close() error
}

type GRPCStatsClient struct {
	conn    *grpc.ClientConn
	service string
}

func NewXrayStatsClient(target string, transport credentials.TransportCredentials) (*GRPCStatsClient, error) {
	return newStatsClient(target, transport, xrayStatsService)
}

func NewSingBoxStatsClient(target string, transport credentials.TransportCredentials) (*GRPCStatsClient, error) {
	return newStatsClient(target, transport, singBoxStatsService)
}

func newStatsClient(target string, transport credentials.TransportCredentials, service string) (*GRPCStatsClient, error) {
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(transport))
	if err != nil {
		return nil, fmt.Errorf("create stats client for %s: %w", target, err)
	}
	return &GRPCStatsClient{conn: conn, service: service}, nil
}

func (c *GRPCStatsClient) Query(ctx context.Context, pattern string, reset bool) ([]Stat, error) {
	request := &statscommand.QueryStatsRequest{Pattern: pattern, Reset_: reset}
	response := new(statscommand.QueryStatsResponse)
	if err := c.conn.Invoke(ctx, c.method("QueryStats"), request, response); err != nil {
		return nil, fmt.Errorf("query stats %q: %w", pattern, err)
	}
	items := make([]Stat, 0, len(response.GetStat()))
	for _, item := range response.GetStat() {
		items = append(items, Stat{Name: item.GetName(), Value: item.GetValue()})
	}
	return items, nil
}

func (c *GRPCStatsClient) System(ctx context.Context) (SystemStats, error) {
	response := new(statscommand.SysStatsResponse)
	if err := c.conn.Invoke(ctx, c.method("GetSysStats"), &statscommand.SysStatsRequest{}, response); err != nil {
		return SystemStats{}, fmt.Errorf("get system stats: %w", err)
	}
	return SystemStats{
		NumGoroutine: response.GetNumGoroutine(),
		NumGC:        response.GetNumGC(),
		Alloc:        response.GetAlloc(),
		TotalAlloc:   response.GetTotalAlloc(),
		Sys:          response.GetSys(),
		Mallocs:      response.GetMallocs(),
		Frees:        response.GetFrees(),
		LiveObjects:  response.GetLiveObjects(),
		PauseTotalNs: response.GetPauseTotalNs(),
		Uptime:       response.GetUptime(),
	}, nil
}

func (c *GRPCStatsClient) Online(ctx context.Context, userID string) (bool, error) {
	response := new(statscommand.GetStatsResponse)
	err := c.conn.Invoke(ctx, c.method("GetStatsOnline"), &statscommand.GetStatsRequest{Name: "user>>>" + userID + ">>>online"}, response)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (c *GRPCStatsClient) UserIPs(ctx context.Context, userID string) (map[string]int64, error) {
	response := new(statscommand.GetStatsOnlineIpListResponse)
	err := c.conn.Invoke(ctx, c.method("GetStatsOnlineIpList"), &statscommand.GetStatsRequest{Name: "user>>>" + userID + ">>>online", Reset_: true}, response)
	if err != nil {
		return nil, err
	}
	return response.GetIps(), nil
}

func (c *GRPCStatsClient) OnlineUsers(ctx context.Context) ([]string, error) {
	response := new(statscommand.GetAllOnlineUsersResponse)
	if err := c.conn.Invoke(ctx, c.method("GetAllOnlineUsers"), &statscommand.GetAllOnlineUsersRequest{}, response); err != nil {
		return nil, err
	}
	return response.GetUsers(), nil
}

func (c *GRPCStatsClient) Close() error {
	return c.conn.Close()
}

func (c *GRPCStatsClient) method(name string) string {
	return "/" + c.service + "/" + name
}
