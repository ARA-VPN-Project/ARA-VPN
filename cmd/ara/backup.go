package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"aravpn/core/schema"
	"aravpn/internal/i18n"
	"aravpn/internal/nodebackup"
)

func cmdBackup(g *globals, tail []string, lang i18n.Lang) int {
	if len(tail) == 0 {
		return schema.ExitUsage
	}
	fs := flag.NewFlagSet("backup "+tail[0], flag.ContinueOnError)
	root := fs.String("root", "/", "node filesystem root")
	file := fs.String("file", "", "private backup archive path")
	offline := fs.Bool("offline", false, "confirm ARA writers have been stopped")
	if err := fs.Parse(tail[1:]); err != nil {
		return emitUsageError(g, err)
	}
	if *file == "" || fs.NArg() != 0 {
		return schema.ExitUsage
	}
	var result nodebackup.Result
	var err error
	if tail[0] == "create" || tail[0] == "restore" {
		if !*offline {
			return fail(g, lang, schema.CodeConflict, "error."+schema.CodeConflict, nil, fmt.Errorf("stop ARA writers and use --offline"))
		}
		resolved, resolveErr := filepath.EvalSymlinks(*root)
		if resolveErr != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, resolveErr)
		}
		resolved, err = filepath.Abs(resolved)
		if err != nil {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
		}
		if resolved == "/" {
			for _, unit := range []string{"ara-agent.service", "ara-control.service", "ara-edge.service", "ara-node-access.service", "ara-node-access.socket"} {
				out, _ := exec.Command("systemctl", "show", "-p", "ActiveState", "--value", unit).Output()
				if state := strings.TrimSpace(string(out)); state != "inactive" && state != "failed" {
					return fail(g, lang, schema.CodeConflict, "error."+schema.CodeConflict, nil, fmt.Errorf("cannot establish offline state of %s", unit))
				}
			}
		}
	}
	switch tail[0] {
	case "create":
		result, err = nodebackup.Create(*root, *file)
	case "verify":
		result, err = nodebackup.Verify(*file)
	case "restore":
		result, err = nodebackup.Restore(*file, *root)
	default:
		return schema.ExitUsage
	}
	if err != nil {
		return fail(g, lang, schema.CodeConflict, "error."+schema.CodeConflict, nil, err)
	}
	if g.json {
		return okJSON(g, result)
	}
	if lang == "ru" {
		fmt.Fprintf(os.Stdout, "Архив ARA · файлов %d · байт %d\n", result.Files, result.Bytes)
	} else {
		fmt.Fprintf(os.Stdout, "ARA archive · %d files · %d bytes\n", result.Files, result.Bytes)
	}
	return schema.ExitOK
}
