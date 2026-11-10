package main

// REAL installed verification (F04): runs ONLY as root on the authorized
// lab with ARA_TEST_BUNDLE set (comma-separated v2 .deb paths). Uses the
// real dpkg and real systemctl against the ARA-owned units installed from
// our own packages; foreign packages/services are never touched. Skipped
// in every other environment.
import (
	"os"
	"strings"
	"testing"

	"aravpn/internal/service"
)

func TestRealBundleUpgradeRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-only: real installed upgrade")
	}
	bundle := os.Getenv("ARA_TEST_BUNDLE")
	if bundle == "" || strings.Count(bundle, ",") != 2 {
		t.Skip("ARA_TEST_BUNDLE (component1,component2,component3) not set")
	}
	svc, err := service.New(service.StateDir{Root: os.Getenv("ARA_TEST_STATE")})
	if err != nil {
		t.Fatal(err)
	}
	out, err := updateApplyBundle(svc, strings.Split(bundle, ","), nil)
	if err != nil {
		t.Fatalf("real bundle upgrade: %v", err)
	}
	t.Logf("dpkg: %s", strings.TrimSpace(out))
	// per-component LKG retained
	for _, comp := range []string{"ara-engine", "ara", "ara-edge"} {
		if _, serr := os.Stat(lkgPath(svc, comp)); serr != nil {
			t.Fatalf("LKG for %s not retained: %v", comp, serr)
		}
	}
}
