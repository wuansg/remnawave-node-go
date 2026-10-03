package node

import (
	"testing"

	"github.com/remnawave/remnawave-node-go/internal/state"
	"github.com/remnawave/remnawave-node-go/internal/statname"
)

func TestSnellUserLifecycle(t *testing.T) {
	cfg := map[string]any{"inbounds": []any{map[string]any{
		"type": "snell", "tag": "snell", "version": 5,
		"multi_user_psk": true, "users": []any{},
	}}}
	runtime := state.New("test")
	runtime.SetRunningCore(state.CoreTypeSingBox)
	runtime.SetSingBoxConfig(cfg)
	manager := &Manager{state: runtime}
	request := AddUserRequest{Data: []AddUserItem{{Type: "snell", Tag: "snell", Username: "18", Password: "first-user-secret-12345"}}}
	if err := manager.applyAddUserRequest(request); err != nil {
		t.Fatal(err)
	}
	users := asMapSlice(asMapSlice(runtime.SingBoxConfig()["inbounds"])[0]["users"])
	if users[0]["psk"] != "first-user-secret-12345" || users[0]["name"] != statname.UserInbound("18", "snell") {
		t.Fatal("wrong Snell credential or stat name")
	}
	if _, exists := users[0]["password"]; exists {
		t.Fatal("password used instead of psk")
	}
	bulkUser := BulkAddUser{InboundData: []BulkInboundData{{Type: "snell", Tag: "snell"}}}
	bulkUser.UserData.UserID = "18"
	bulkUser.UserData.SnellPSK = "rotated-user-secret-12345"
	if err := manager.applyAddUsersRequest(AddUsersRequest{Users: []BulkAddUser{bulkUser}}); err != nil {
		t.Fatal(err)
	}
	users = asMapSlice(asMapSlice(runtime.SingBoxConfig()["inbounds"])[0]["users"])
	if len(users) != 1 || users[0]["psk"] != bulkUser.UserData.SnellPSK {
		t.Fatal("rotation must replace old PSK")
	}
	if err := manager.removeUserEverywhere("18"); err != nil {
		t.Fatal(err)
	}
	inbound := asMapSlice(runtime.SingBoxConfig()["inbounds"])[0]
	if len(asMapSlice(inbound["users"])) != 0 || inbound["multi_user_psk"] != true {
		t.Fatal("empty config must retain fail-closed mode")
	}
	if err := addSingBoxUser(cfg, AddUserItem{Tag: "snell", Username: "18", Password: ""}); err == nil {
		t.Fatal("empty PSK accepted")
	}
}
