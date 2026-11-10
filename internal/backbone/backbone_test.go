package backbone

import "testing"

func TestBackboneRequiresExplicitPrivateEndpoint(t *testing.T) {
	for _, proto := range []string{"openvpn", "wireguard"} {
		binding := Binding{Protocol: proto, Interface: "ara-backbone0"}
		for _, endpoint := range []string{"10.72.0.2:1080", "[fd00::2]:1080"} {
			binding.SOCKSAddr = endpoint
			if err := binding.Validate(); err != nil {
				t.Fatalf("%s %s: %v", proto, endpoint, err)
			}
		}
		for _, endpoint := range []string{"exit.example:1080", "192.0.2.2:1080", "127.0.0.1:1080", "10.72.0.2:0"} {
			binding.SOCKSAddr = endpoint
			if err := binding.Validate(); err == nil {
				t.Fatalf("%s accepted %s", proto, endpoint)
			}
		}
	}
}
