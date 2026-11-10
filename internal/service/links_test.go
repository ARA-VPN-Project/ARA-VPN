package service

import "testing"

func TestShareLinksUseAnExplicitOrigin(t *testing.T) {
	for _, bad := range []string{"https://ara.invalid", "http://panel.example.com", "https://user@panel.example.com", "https://panel.example.com/sub/", "https://panel.example.com/?x=y", "https://panel.example.com:65536"} {
		if _, err := LinkOrigin(bad); err == nil {
			t.Errorf("accepted unsuitable share origin %q", bad)
		}
	}
	for _, link := range []string{"https://panel.example.com/sub/fixture", "http://[::1]:8080/sub/fixture"} {
		base, token, err := ParseSubscriptionLink(link, "")
		if err != nil || token != "fixture" || SubscriptionTokenURL(base, token) != link {
			t.Fatalf("share link did not round trip: %s, %s, %v", base, token, err)
		}
	}
	for _, bad := range []string{"https://panel.example.com/sub/fixture/extra", "https://panel.example.com/sub/fixture?x=y", "https://panel.example.com/sub/fixture#extra"} {
		if _, _, err := ParseSubscriptionLink(bad, ""); err == nil {
			t.Errorf("accepted noncanonical subscription link %q", bad)
		}
	}
	if _, _, err := ParseSubscriptionLink("https://panel.example.com/sub/fixture", "another"); err == nil {
		t.Fatal("accepted two different subscription tokens")
	}
}
