package statname

import (
	"encoding/base64"
	"strings"
)

const userInboundSeparator = ".rwib."

func UserInbound(userID, inboundTag string) string {
	return userID + userInboundSeparator + base64.RawURLEncoding.EncodeToString([]byte(inboundTag))
}

func ParseUserInbound(value string) (userID string, inboundTag string, ok bool) {
	left, right, found := strings.Cut(value, userInboundSeparator)
	if !found || left == "" || right == "" {
		return "", "", false
	}

	decoded, err := base64.RawURLEncoding.DecodeString(right)
	if err != nil || len(decoded) == 0 {
		return "", "", false
	}

	return left, string(decoded), true
}

func UserID(value string) string {
	if userID, _, ok := ParseUserInbound(value); ok {
		return userID
	}
	return value
}
