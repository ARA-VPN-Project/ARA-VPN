package main

import (
	"flag"
	"fmt"
	"os"

	"aravpn/core/schema"
	"aravpn/internal/i18n"
	"aravpn/internal/service"
)

func cmdAccount(svc *service.Service, g *globals, args []string, lang i18n.Lang) int {
	if rc := requireSvc(svc, g, lang); rc >= 0 {
		return rc
	}
	if len(args) == 0 || (args[0] != "list" && args[0] != "delete") {
		fmt.Fprintln(os.Stderr, "usage: ara account list | ara account delete --id ACCOUNT")
		return schema.ExitUsage
	}
	fs := flag.NewFlagSet("account "+args[0], flag.ContinueOnError)
	var id string
	if args[0] == "delete" {
		fs.StringVar(&id, "id", "", "account ID")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return emitUsageError(g, err)
	}
	if fs.NArg() != 0 || (args[0] == "delete" && id == "") {
		return schema.ExitUsage
	}
	st, err := svc.OpenControlStore()
	if err != nil {
		return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
	}
	defer st.Close()
	if args[0] == "delete" {
		if err := st.ArchiveAccount(id); err != nil {
			return fail(g, lang, schema.CodeConflict, "error."+schema.CodeConflict, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]string{"archived": id})
		}
		fmt.Println(id)
		return schema.ExitOK
	}
	accounts, err := st.ListAccounts()
	if err != nil {
		return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
	}
	if g.json {
		return okJSON(g, map[string]any{"accounts": accounts})
	}
	for _, account := range accounts {
		fmt.Println(account.ID)
	}
	return schema.ExitOK
}
