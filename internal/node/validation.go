package node

import (
	"fmt"
	"net"
	"strings"
)

var validUserTypes = map[string]struct{}{
	"trojan": {}, "vless": {}, "shadowsocks": {}, "shadowsocks22": {}, "hysteria": {},
}

func (r StartRequest) Validate() error {
	if r.CoreType == "" {
		r.CoreType = string("XRAY")
	}
	if !strings.EqualFold(r.CoreType, "XRAY") && !strings.EqualFold(r.CoreType, "SING_BOX") {
		return fmt.Errorf("coreType must be XRAY or SING_BOX")
	}
	if strings.EqualFold(r.CoreType, "SING_BOX") && len(r.SingBoxConfig) == 0 {
		return fmt.Errorf("singBoxConfig is required for SING_BOX core")
	}
	if !strings.EqualFold(r.CoreType, "SING_BOX") && len(r.XrayConfig) == 0 {
		return fmt.Errorf("xrayConfig is required for XRAY core")
	}
	return nil
}

func (r AddUserRequest) Validate() error {
	for _, item := range r.Data {
		if err := item.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (u AddUserItem) validate() error {
	if _, ok := validUserTypes[u.Type]; !ok {
		return fmt.Errorf("unsupported user type %q", u.Type)
	}
	if u.Tag == "" || u.Username == "" {
		return fmt.Errorf("user tag and username are required")
	}
	if u.Type == "vless" && (u.UUID == "" || (u.Flow != "" && u.Flow != "xtls-rprx-vision")) {
		return fmt.Errorf("invalid VLESS user")
	}
	return nil
}

func (r RemoveUserRequest) Validate() error {
	if r.Username == "" {
		return fmt.Errorf("username is required")
	}
	return nil
}

func (r AddUsersRequest) Validate() error {
	for _, user := range r.Users {
		if user.UserData.UserID == "" {
			return fmt.Errorf("userId is required")
		}
		for _, inbound := range user.InboundData {
			if _, ok := validUserTypes[inbound.Type]; !ok || inbound.Tag == "" {
				return fmt.Errorf("invalid inbound user data")
			}
		}
	}
	return nil
}

func (r RemoveUsersRequest) Validate() error {
	for _, user := range r.Users {
		if user.UserID == "" {
			return fmt.Errorf("userId is required")
		}
	}
	return nil
}

func (r GetInboundUsersRequest) Validate() error {
	if r.Tag == "" {
		return fmt.Errorf("tag is required")
	}
	return nil
}

func (r DropUsersConnectionsRequest) Validate() error {
	for _, id := range r.UserIDs {
		if id == "" {
			return fmt.Errorf("userIds must not contain empty values")
		}
	}
	return nil
}

func (r DropIPsRequest) Validate() error { return validateIPs(r.IPs) }

func (r GetUserOnlineStatusRequest) Validate() error {
	if r.Username == "" {
		return fmt.Errorf("username is required")
	}
	return nil
}

func (r GetTagStatsRequest) Validate() error {
	if r.Tag == "" {
		return fmt.Errorf("tag is required")
	}
	return nil
}

func (r GetUserIPListRequest) Validate() error {
	if r.UserID == "" {
		return fmt.Errorf("userId is required")
	}
	return nil
}

func (r VisionIPRequest) Validate() error { return validateIPs([]string{r.IP}) }

func (r BlockIPsRequest) Validate() error {
	for _, item := range r.IPs {
		if err := validateIPs([]string{item.IP}); err != nil {
			return err
		}
		if item.Timeout < 0 {
			return fmt.Errorf("timeout must not be negative")
		}
	}
	return nil
}

func (r UnblockIPsRequest) Validate() error { return validateIPs(r.IPs) }

func validateIPs(values []string) error {
	for _, value := range values {
		if net.ParseIP(value) == nil {
			return fmt.Errorf("invalid IP address %q", value)
		}
	}
	return nil
}
