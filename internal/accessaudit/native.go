package accessaudit

// Wire-compatible subset of sing-box v1.14.0 daemon/started_service.proto.
// Streaming NEW/CLOSED events capture short connections that polling misses.
import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

const streamMethod = "/daemon.StartedService/SubscribeConnections"

var wire = wireDescriptor()

func wireDescriptor() protoreflect.FileDescriptor {
	field := func(name string, number int32, kind descriptorpb.FieldDescriptorProto_Type, repeated bool, target string) *descriptorpb.FieldDescriptorProto {
		label := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
		if repeated {
			label = descriptorpb.FieldDescriptorProto_LABEL_REPEATED
		}
		f := &descriptorpb.FieldDescriptorProto{Name: proto.String(name), Number: proto.Int32(number), Type: &kind, Label: &label}
		if target != "" {
			f.TypeName = proto.String(target)
		}
		return f
	}
	str, num, msg := descriptorpb.FieldDescriptorProto_TYPE_STRING, descriptorpb.FieldDescriptorProto_TYPE_INT64, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
	c := &descriptorpb.DescriptorProto{Name: proto.String("Connection")}
	for i, name := range map[int32]string{1: "id", 2: "inbound", 5: "network", 7: "destination", 8: "domain", 9: "protocol", 10: "user", 20: "outboundType"} {
		c.Field = append(c.Field, field(name, i, str, false, ""))
	}
	for i, name := range map[int32]string{12: "createdAt", 13: "closedAt", 16: "uplinkTotal", 17: "downlinkTotal"} {
		c.Field = append(c.Field, field(name, i, num, false, ""))
	}
	f, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{Name: proto.String("remnanode_audit.proto"), Package: proto.String("daemon"), Syntax: proto.String("proto3"), MessageType: []*descriptorpb.DescriptorProto{
		{Name: proto.String("SubscribeConnectionsRequest"), Field: []*descriptorpb.FieldDescriptorProto{field("interval", 1, num, false, "")}}, c,
		{Name: proto.String("ConnectionEvent"), Field: []*descriptorpb.FieldDescriptorProto{field("type", 1, descriptorpb.FieldDescriptorProto_TYPE_INT32, false, ""), field("id", 2, str, false, ""), field("connection", 3, msg, false, ".daemon.Connection"), field("uplinkDelta", 4, num, false, ""), field("downlinkDelta", 5, num, false, ""), field("closedAt", 6, num, false, "")}},
		{Name: proto.String("ConnectionEvents"), Field: []*descriptorpb.FieldDescriptorProto{field("events", 1, msg, true, ".daemon.ConnectionEvent"), field("reset", 2, descriptorpb.FieldDescriptorProto_TYPE_BOOL, false, "")}},
	}}, nil)
	if err != nil {
		panic(err)
	}
	return f
}

type Event struct {
	Type                                 int
	ID                                   string
	Connection                           *Connection
	UploadDelta, DownloadDelta, ClosedAt int64
}
type Connection struct {
	ID, User, Domain, Destination, Inbound, Network, Protocol, OutboundType string
	CreatedAt, ClosedAt, Upload, Download                                   int64
}

func readEvents(message protoreflect.Message) []Event {
	get := func(m protoreflect.Message, n protoreflect.FieldNumber) protoreflect.Value {
		return m.Get(m.Descriptor().Fields().ByNumber(n))
	}
	items := get(message, 1).List()
	result := make([]Event, 0, items.Len())
	for i := 0; i < items.Len(); i++ {
		m := items.Get(i).Message()
		e := Event{Type: int(get(m, 1).Int()), ID: get(m, 2).String(), UploadDelta: get(m, 4).Int(), DownloadDelta: get(m, 5).Int(), ClosedAt: get(m, 6).Int()}
		if m.Has(m.Descriptor().Fields().ByNumber(3)) {
			c := get(m, 3).Message()
			e.Connection = &Connection{ID: get(c, 1).String(), Inbound: get(c, 2).String(), Network: get(c, 5).String(), Destination: get(c, 7).String(), Domain: get(c, 8).String(), Protocol: get(c, 9).String(), User: get(c, 10).String(), CreatedAt: get(c, 12).Int(), ClosedAt: get(c, 13).Int(), Upload: get(c, 16).Int(), Download: get(c, 17).Int(), OutboundType: get(c, 20).String()}
		}
		result = append(result, e)
	}
	return result
}
func Subscribe(ctx context.Context, address, secret string, receive func([]Event) error) error {
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(16<<20)))
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+secret)
	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, streamMethod)
	if err != nil {
		return err
	}
	r := dynamicpb.NewMessage(wire.Messages().ByName("SubscribeConnectionsRequest"))
	r.Set(r.Descriptor().Fields().ByNumber(1), protoreflect.ValueOfInt64(int64(10*time.Second)))
	if err = stream.SendMsg(r); err != nil {
		return err
	}
	if err = stream.CloseSend(); err != nil {
		return err
	}
	for {
		response := dynamicpb.NewMessage(wire.Messages().ByName("ConnectionEvents"))
		if err = stream.RecvMsg(response); err != nil {
			return err
		}
		if err = receive(readEvents(response)); err != nil {
			return err
		}
	}
}
