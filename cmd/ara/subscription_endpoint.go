package main

import (
	"flag"
	"fmt"
	"os"

	"aravpn/core/schema"
	"aravpn/internal/i18n"
	"aravpn/internal/service"
)

func subscriptionShareEndpoint(svc *service.Service, explicit string) (service.SubscriptionEndpoint, error) {
	e, err := svc.SubscriptionEndpoint()
	if err != nil {
		return e, err
	}
	for _, origin := range []string{explicit, e.Origin, os.Getenv("ARA_PUBLIC_URL")} {
		if origin != "" {
			e.Origin, err = service.LinkOrigin(origin)
			break
		}
	}
	return e, err
}

func cmdSubscriptionEndpoint(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	fs := flag.NewFlagSet("subscription endpoint", flag.ContinueOnError)
	origin := fs.String("origin", "", "public HTTPS origin")
	name := fs.String("name", "", "public subscription service name")
	if err := fs.Parse(tail); err != nil {
		return emitUsageError(g, err)
	}
	var e service.SubscriptionEndpoint
	var err error
	if fs.NFlag() == 0 {
		e, err = subscriptionShareEndpoint(svc, "")
	} else {
		e, err = svc.SetSubscriptionEndpoint(service.SubscriptionEndpoint{Origin: *origin, Name: *name}, os.Getenv("ARA_ADMIN_PATH"))
	}
	if err != nil {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, err)
	}
	if g.json {
		return okJSON(g, e)
	}
	if e.Base() != "" {
		fmt.Println(e.Base() + "/<key>")
	} else if lang == "ru" {
		fmt.Println("Домен подписочного сервиса не задан")
	} else {
		fmt.Println("Subscription service origin is unset")
	}
	return schema.ExitOK
}

func subscriptionShareLink(svc *service.Service, origin, token string) (string, error) {
	e, err := subscriptionShareEndpoint(svc, origin)
	if err != nil {
		return "", err
	}
	if e.Base() == "" {
		return "", fmt.Errorf("VALIDATION_FAILED: set the subscription endpoint or supply --base")
	}
	link := service.SubscriptionTokenURL(e.Base(), token)
	if _, _, err := service.ParseSubscriptionLink(link, ""); err != nil {
		return "", err
	}
	return link, nil
}
