//go:build linux

package netplan

import (
	"fmt"
	"os/exec"
)

// CommandExecutor runs the typed op table against the real network. It is
// constructed ONLY with a validated plan's ops (Execute validates first)
// and runs with root in the ara-net-helper. Commands are built from
// struct fields — never raw strings.
//
// Outcome classification (review X01, narrowed by round7):
//   - the process could not be STARTED → proven no-effect
//     (netplan.NoEffectError wrapping the original cause);
//   - ANY Wait error of an already-started process → UNKNOWN, including
//     a normal nonzero exit. Atomicity of the netlink mutation does NOT
//     prove delivery of its acknowledgement: iproute2's rtnl_talk can
//     fail while reading the response after the request was sent, and
//     exits nonzero without exposing a structured difference between a
//     negative ACK and a read failure. Without a structured ACK contract
//     we cannot distinguish them, so a nonzero exit stays unknown;
//   - unknown outcomes make the step attempted-unknown: the journal
//     fences the plan (pending operator resolution), never writes
//     recovered over a possible effect and never repeats the command.
//
// Consequence: real CLI rejections become pending until operator
// resolution or a future structured-ACK/helper contract. This is the
// honest limitation of a subprocess adapter — preferred over a false
// recovered record.
type CommandExecutor struct{}

func (CommandExecutor) Do(op Op) error {
	var cmd *exec.Cmd
	switch op.Kind {
	case OpAddRoute:
		args := []string{"route", "replace", op.Prefix, "dev", op.Device}
		if op.Table != "" {
			args = append(args, "table", op.Table)
		}
		if op.Gateway != "" {
			args = append(args, "via", op.Gateway)
		}
		cmd = exec.Command("ip", args...)
	case OpDelRoute:
		args := []string{"route", "del", op.Prefix, "dev", op.Device}
		if op.Table != "" {
			args = append(args, "table", op.Table)
		}
		cmd = exec.Command("ip", args...)
	case OpAddRule:
		cmd = exec.Command("ip", "rule", "add", "fwmark", fmt.Sprint(op.Mark), "table", op.Table, "priority", fmt.Sprint(op.Priority))
	case OpDelRule:
		cmd = exec.Command("ip", "rule", "del", "fwmark", fmt.Sprint(op.Mark), "table", op.Table, "priority", fmt.Sprint(op.Priority))
	case OpAddNftTable:
		cmd = exec.Command("nft", "add", "table", op.Table)
	case OpDelNftTable:
		cmd = exec.Command("nft", "delete", "table", op.Table)
	case OpAddQdisc:
		cmd = exec.Command("tc", "qdisc", "replace", "dev", op.Device, "root", "handle", "1:", "fq_codel")
	case OpDelQdisc:
		cmd = exec.Command("tc", "qdisc", "del", "dev", op.Device, "root")
	default:
		return fmt.Errorf("op kind %q is not in the typed table", op.Kind)
	}
	if err := cmd.Start(); err != nil {
		// the process never ran: proven no-effect, cause preserved
		return NoEffect(fmt.Errorf("start %s: %w", op.Kind, err))
	}
	if err := cmd.Wait(); err != nil {
		// Round7: ANY wait error of a started process is unknown —
		// a normal nonzero exit does not prove the kernel rejected the
		// request (the ACK read may have failed after the mutation).
		// The original *exec.ExitError stays in the cause chain.
		return fmt.Errorf("%s outcome unknown: %w", op.Kind, err)
	}
	return nil
}

// executesOnThisPlatform reports whether Execute may run here.
const executesOnThisPlatform = true
