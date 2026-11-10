//go:build !linux

package netplan

import "errors"

// CommandExecutor refuses off-Linux: privileged mutation is Debian-only
// by design (docs/PLATFORMS_INSTALL.md). Planning and journal semantics
// stay testable everywhere via the Executor interface + fake.
type CommandExecutor struct{}

func (CommandExecutor) Do(op Op) error {
	return errors.New("UNSUPPORTED_CAPABILITY: netplan execution requires Linux (Debian)")
}

// executesOnThisPlatform reports whether Execute may run here.
const executesOnThisPlatform = false
