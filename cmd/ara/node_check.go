package main

import (
	"context"
	"flag"
	"fmt"

	"aravpn/core/schema"
	"aravpn/internal/i18n"
	"aravpn/internal/service"
)

func cmdNodeCheck(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	fs := flag.NewFlagSet("node check", flag.ContinueOnError)
	id := fs.String("id", "", "registered node id")
	if err := fs.Parse(tail); err != nil || *id == "" {
		return schema.ExitUsage
	}
	st, err := svc.OpenControlStore()
	if err != nil {
		return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, err)
	}
	defer st.Close()
	node, err := service.CheckableNode(st, *id)
	if err != nil {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
	}
	result := service.CheckNodeIngress(context.Background(), node)
	if g.json {
		return okJSON(g, result)
	}
	for _, step := range result.Steps {
		fmt.Printf("%s · %s · %d ms\n", step.Name, step.Status, step.DurationMS)
	}
	return schema.ExitOK
}
