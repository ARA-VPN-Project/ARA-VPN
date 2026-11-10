package transport

import (
	"crypto/sha256"
	"encoding/hex"
)

// TrojanPassword derives a separate password from the existing device secret.
func TrojanPassword(deviceUUID string) string {
	sum := sha256.Sum256([]byte("ara/trojan/v1/" + deviceUUID))
	return hex.EncodeToString(sum[:])
}
