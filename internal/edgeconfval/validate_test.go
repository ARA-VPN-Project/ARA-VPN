package edgeconfval

import (
	"strings"
	"testing"
)

func TestExternalBackboneHasNoLegacyDialAddress(t *testing.T) {
	config := `{"devices":[{"uuid":"device"}],"exits":[{"id":"de","role":"foreign",
		"backbone":{"protocol":"wireguard","interface":"wg0","socks_addr":"10.82.34.2:1080"}}]}`
	if err := Validate([]byte(config)); err != nil {
		t.Fatal(err)
	}
	mixed := strings.Replace(config, `"backbone":`, `"socks_addr":"10.82.34.2:1080","backbone":`, 1)
	if err := Validate([]byte(mixed)); err == nil {
		t.Fatal("accepted an unbound address that older binaries could dial")
	}
}
