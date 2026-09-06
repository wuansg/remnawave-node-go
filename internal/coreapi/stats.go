package coreapi

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const singBoxStatsService = "v2ray.core.app.stats.command.StatsService"

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
	request := &queryStatsRequest{Patterns: []string{pattern}, Reset_: reset}
	response := new(queryStatsResponse)
	if err := c.conn.Invoke(ctx, c.method("QueryStats"), request, response); err != nil {
		return nil, fmt.Errorf("query stats %q: %w", pattern, err)
	}
	items := make([]Stat, 0, len(response.Stat))
	for _, item := range response.Stat {
		items = append(items, Stat{Name: item.Name, Value: item.Value})
	}
	return items, nil
}

// queryStatsRequest matches sing-box's QueryStatsRequest wire format.
// Since sing-box 1.13, field 1 (pattern) is deprecated and the server only
// applies field 3 (patterns).
type queryStatsRequest struct {
	Reset_   bool     `protobuf:"varint,2,opt,name=reset,proto3" json:"reset,omitempty"`
	Patterns []string `protobuf:"bytes,3,rep,name=patterns,proto3" json:"patterns,omitempty"`
}

func (r *queryStatsRequest) Reset() { *r = queryStatsRequest{} }
func (r *queryStatsRequest) String() string {
	return fmt.Sprintf("patterns:%v reset:%t", r.Patterns, r.Reset_)
}
func (*queryStatsRequest) ProtoMessage() {}

type statRecord struct {
	Name  string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Value int64  `protobuf:"varint,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (r *statRecord) Reset()         { *r = statRecord{} }
func (r *statRecord) String() string { return fmt.Sprintf("name:%q value:%d", r.Name, r.Value) }
func (*statRecord) ProtoMessage()    {}

type queryStatsResponse struct {
	Stat []*statRecord `protobuf:"bytes,1,rep,name=stat,proto3" json:"stat,omitempty"`
}

func (r *queryStatsResponse) Reset()         { *r = queryStatsResponse{} }
func (r *queryStatsResponse) String() string { return fmt.Sprintf("stat:%v", r.Stat) }
func (*queryStatsResponse) ProtoMessage()    {}

type sysStatsRequest struct{}

func (r *sysStatsRequest) Reset()         { *r = sysStatsRequest{} }
func (r *sysStatsRequest) String() string { return "" }
func (*sysStatsRequest) ProtoMessage()    {}

type sysStatsResponse struct {
	NumGoroutine uint32 `protobuf:"varint,1,opt,name=NumGoroutine,proto3" json:"NumGoroutine,omitempty"`
	NumGC        uint32 `protobuf:"varint,2,opt,name=NumGC,proto3" json:"NumGC,omitempty"`
	Alloc        uint64 `protobuf:"varint,3,opt,name=Alloc,proto3" json:"Alloc,omitempty"`
	TotalAlloc   uint64 `protobuf:"varint,4,opt,name=TotalAlloc,proto3" json:"TotalAlloc,omitempty"`
	Sys          uint64 `protobuf:"varint,5,opt,name=Sys,proto3" json:"Sys,omitempty"`
	Mallocs      uint64 `protobuf:"varint,6,opt,name=Mallocs,proto3" json:"Mallocs,omitempty"`
	Frees        uint64 `protobuf:"varint,7,opt,name=Frees,proto3" json:"Frees,omitempty"`
	LiveObjects  uint64 `protobuf:"varint,8,opt,name=LiveObjects,proto3" json:"LiveObjects,omitempty"`
	PauseTotalNs uint64 `protobuf:"varint,9,opt,name=PauseTotalNs,proto3" json:"PauseTotalNs,omitempty"`
	Uptime       uint32 `protobuf:"varint,10,opt,name=Uptime,proto3" json:"Uptime,omitempty"`
}

func (r *sysStatsResponse) Reset()         { *r = sysStatsResponse{} }
func (r *sysStatsResponse) String() string { return fmt.Sprintf("uptime:%d", r.Uptime) }
func (*sysStatsResponse) ProtoMessage()    {}

func (c *GRPCStatsClient) System(ctx context.Context) (SystemStats, error) {
	response := new(sysStatsResponse)
	if err := c.conn.Invoke(ctx, c.method("GetSysStats"), &sysStatsRequest{}, response); err != nil {
		return SystemStats{}, fmt.Errorf("get system stats: %w", err)
	}
	return SystemStats{
		NumGoroutine: response.NumGoroutine,
		NumGC:        response.NumGC,
		Alloc:        response.Alloc,
		TotalAlloc:   response.TotalAlloc,
		Sys:          response.Sys,
		Mallocs:      response.Mallocs,
		Frees:        response.Frees,
		LiveObjects:  response.LiveObjects,
		PauseTotalNs: response.PauseTotalNs,
		Uptime:       response.Uptime,
	}, nil
}

func (c *GRPCStatsClient) Online(ctx context.Context, userID string) (bool, error) {
	response := new(getStatsResponse)
	err := c.conn.Invoke(ctx, c.method("GetStatsOnline"), &getStatsRequest{Name: "user>>>" + userID + ">>>online"}, response)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (c *GRPCStatsClient) UserIPs(ctx context.Context, userID string) (map[string]int64, error) {
	response := new(getStatsOnlineIPListResponse)
	err := c.conn.Invoke(ctx, c.method("GetStatsOnlineIpList"), &getStatsRequest{Name: "user>>>" + userID + ">>>online", Reset_: true}, response)
	if err != nil {
		return nil, err
	}
	return response.IPs, nil
}

func (c *GRPCStatsClient) OnlineUsers(ctx context.Context) ([]string, error) {
	response := new(getAllOnlineUsersResponse)
	if err := c.conn.Invoke(ctx, c.method("GetAllOnlineUsers"), &getAllOnlineUsersRequest{}, response); err != nil {
		return nil, err
	}
	return response.Users, nil
}

type getStatsRequest struct {
	Name   string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Reset_ bool   `protobuf:"varint,2,opt,name=reset,proto3" json:"reset,omitempty"`
}

func (r *getStatsRequest) Reset()         { *r = getStatsRequest{} }
func (r *getStatsRequest) String() string { return fmt.Sprintf("name:%q reset:%t", r.Name, r.Reset_) }
func (*getStatsRequest) ProtoMessage()    {}

type getStatsResponse struct {
	Stat *statRecord `protobuf:"bytes,1,opt,name=stat,proto3" json:"stat,omitempty"`
}

func (r *getStatsResponse) Reset()         { *r = getStatsResponse{} }
func (r *getStatsResponse) String() string { return fmt.Sprintf("stat:%v", r.Stat) }
func (*getStatsResponse) ProtoMessage()    {}

type getStatsOnlineIPListResponse struct {
	Name string           `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	IPs  map[string]int64 `protobuf:"bytes,2,rep,name=ips,proto3" json:"ips,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"varint,2,opt,name=value,proto3"`
}

func (r *getStatsOnlineIPListResponse) Reset() { *r = getStatsOnlineIPListResponse{} }
func (r *getStatsOnlineIPListResponse) String() string {
	return fmt.Sprintf("name:%q ips:%v", r.Name, r.IPs)
}
func (*getStatsOnlineIPListResponse) ProtoMessage() {}

type getAllOnlineUsersRequest struct{}

func (r *getAllOnlineUsersRequest) Reset()         { *r = getAllOnlineUsersRequest{} }
func (r *getAllOnlineUsersRequest) String() string { return "" }
func (*getAllOnlineUsersRequest) ProtoMessage()    {}

type getAllOnlineUsersResponse struct {
	Users []string `protobuf:"bytes,1,rep,name=users,proto3" json:"users,omitempty"`
}

func (r *getAllOnlineUsersResponse) Reset()         { *r = getAllOnlineUsersResponse{} }
func (r *getAllOnlineUsersResponse) String() string { return fmt.Sprintf("users:%v", r.Users) }
func (*getAllOnlineUsersResponse) ProtoMessage()    {}

func (c *GRPCStatsClient) Close() error {
	return c.conn.Close()
}

func (c *GRPCStatsClient) method(name string) string {
	return "/" + c.service + "/" + name
}
