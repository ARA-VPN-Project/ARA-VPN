package main

// update commands (docs/UPDATES.md): check → verify → stage against a
// signed metadata file and the operator trust root; installation goes
// through the OS package manager (ARA deliberately keeps one updater).

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aravpn/core/schema"
	"aravpn/core/update"
	"aravpn/internal/i18n"
	"aravpn/internal/service"
)

// verifyAndStageParts (G01): splits the artifact list FIRST, then verifies
// EVERY part against the signed metadata with its own per-component
// selector, and stages each verified copy under the update state. The
// installer receives exactly these verified staged paths — operator input
// paths and tampered parts never reach dpkg (a mismatch fails before the
// first package mutation).
func verifyAndStageParts(svc *service.Service, meta string, roots []string, sel update.Selector, parts []string, stageFn func(*update.Target, string, string) (string, error), checkFn func(string, []string, update.Selector, string) (*update.Target, *update.Metadata, error)) ([]string, error) {
	staged := make([]string, 0, len(parts))
	for _, part := range parts {
		selP := sel
		comp := componentOfArtifact(part)
		if comp == "" {
			return nil, fmt.Errorf("VALIDATION_FAILED: artifact %s has no recognizable ARA component name", filepath.Base(part))
		}
		selP.Component = comp
		t2, _, err := checkFn(meta, roots, selP, part)
		if err != nil {
			return nil, fmt.Errorf("part %s: %w", filepath.Base(part), err)
		}
		sp, err := stageFn(t2, part, t2.Version)
		if err != nil {
			return nil, fmt.Errorf("part %s: %w", filepath.Base(part), err)
		}
		staged = append(staged, sp)
	}
	return staged, nil
}

func cmdUpdate(svc *service.Service, g *globals, tail []string, lang i18n.Lang) int {
	if svc == nil {
		return fail(g, lang, schema.CodeUnavailable, "error."+schema.CodeUnavailable, nil, serviceOpenErr)
	}
	if len(tail) > 0 && tail[0] == "recover" {
		// C02: finish an INTERRUPTED install (dpkg --configure -a →
		// restart → health gate), journaled and locked.
		out, err := updateRecoverWorkflow(svc, nil)
		if err != nil {
			return fail(g, lang, schema.CodeConflict, "error."+schema.CodeConflict, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"recovered": out})
		}
		fmt.Println(i18n.T(lang, "update.staged", map[string]any{"path": out}))
		return schema.ExitOK
	}
	if len(tail) == 0 || (tail[0] != "check" && tail[0] != "apply") {
		fmt.Fprintln(os.Stderr, "usage: ara update check --url HTTPS_ZIP | update apply --url HTTPS_ZIP --install | update apply --metadata|repo … --artifact f.deb [--install] | update recover")
		return schema.ExitUsage
	}
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	meta := fs.String("metadata", "", "signed metadata JSON (legacy single-doc)")
	repo := fs.String("repo", "", "TUF role repository directory (root/timestamp/snapshot/targets)")
	releaseURL := fs.String("url", "", "HTTPS URL of a signed ARA release ZIP")
	root := fs.String("trusted-root", "", "operator trust anchors file (hex ed25519 per line)")
	artifact := fs.String("artifact", "", "artifact to verify (apply requires it)")
	component := fs.String("component", "ara-client", "target component")
	channel := fs.String("channel", "stable", "release channel")
	install := fs.Bool("install", false, "apply: COMPLETE the workflow (dpkg install → restart → health → rollback); root required")
	if err := fs.Parse(tail[1:]); err != nil {
		return emitUsageError(g, err)
	}
	if *releaseURL == "" && *repo == "" && *meta == "" {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--url, --repo (TUF) or --metadata required"}, nil)
	}
	if *repo != "" && *meta != "" {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--repo and --metadata are mutually exclusive"}, nil)
	}
	if *releaseURL != "" {
		if *repo != "" || *meta != "" || *artifact != "" || (tail[0] == "apply") != *install {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, nil, fmt.Errorf("use update check --url or update apply --url --install"))
		}
		if *root == "" {
			*root = "/etc/ara/update-root.keys"
		}
	}
	roots, err := service.LoadTrustedRoots(*root)
	if err != nil {
		return fail(g, lang, schema.CodeVerification, "error."+schema.CodeVerification, nil, err)
	}
	sel := update.Selector{Component: *component, Channel: *channel, CoreAPI: schema.APIVersionInt(), SchemaVer: schema.SchemaVersionNum()}
	if *releaseURL != "" {
		version, err := updateFromRelease(svc, *releaseURL, roots, sel, *install)
		if err != nil {
			return fail(g, lang, schema.CodeConflict, "error."+schema.CodeConflict, nil, err)
		}
		if g.json {
			return okJSON(g, map[string]any{"version": version, "installed": *install})
		}
		key := "update.check"
		if *install {
			key = "update.installed"
		}
		fmt.Println(i18n.T(lang, key, map[string]any{"version": version}))
		return schema.ExitOK
	}
	if *repo != "" {
		// TUF path
		if tail[0] == "check" {
			t, _, err := svc.UpdateCheckTUF(*repo, roots, sel, "")
			if err != nil {
				return fail(g, lang, schema.CodeVerification, "error."+schema.CodeVerification, nil, err)
			}
			if g.json {
				return okJSON(g, map[string]any{"version": t.Version, "sha256": t.SHA256, "url": t.URL})
			}
			fmt.Println(i18n.T(lang, "update.check", map[string]any{"version": t.Version}))
			fmt.Printf("sha256: %s\nurl: %s\n", t.SHA256, t.URL)
			return schema.ExitOK
		}
		if *artifact == "" {
			return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--artifact required for apply"}, nil)
		}
		// G01: split FIRST; each part is verified against the signed TUF
		// metadata with its own per-component selector and staged; the
		// installer receives exactly the verified staged copies.
		parts := strings.Split(*artifact, ",")
		stagedParts := make([]string, 0, len(parts))
		for _, part := range parts {
			selP := sel
			comp := componentOfArtifact(part)
			if comp == "" {
				return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation,
					nil, fmt.Errorf("artifact %s has no recognizable ARA component name", filepath.Base(part)))
			}
			selP.Component = comp
			sp, serr := svc.UpdateStageTUF(*repo, roots, selP, part)
			if serr != nil {
				return fail(g, lang, schema.CodeVerification, "error."+schema.CodeVerification, nil, serr)
			}
			stagedParts = append(stagedParts, sp)
		}
		staged := strings.Join(stagedParts, ",")
		if *install {
			// F04/G01: the DEPENDENT SET (engine+ara+edge) installs as one
			// transaction FROM THE VERIFIED STAGED COPIES
			out, ierr := updateApplyBundle(svc, stagedParts, nil)
			if ierr != nil {
				return fail(g, lang, schema.CodeConflict, "error."+schema.CodeConflict, nil, ierr)
			}
			if g.json {
				return okJSON(g, map[string]any{"installed": staged, "dpkg": out})
			}
			fmt.Println(i18n.T(lang, "update.staged", map[string]any{"path": staged}))
			return schema.ExitOK
		}
		if g.json {
			return okJSON(g, map[string]any{"staged": staged, "next": "re-run with --install to complete the workflow (dpkg → restart → health), or install with the OS package manager"})
		}
		fmt.Println(i18n.T(lang, "update.staged", map[string]any{"path": staged}))
		return schema.ExitOK
	}
	if *meta == "" {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--metadata required for the legacy path"}, nil)
	}
	t, m, err := svc.UpdateCheck(*meta, roots, sel, "")
	if err != nil {
		return fail(g, lang, schema.CodeVerification, "error."+schema.CodeVerification, nil, err)
	}
	if tail[0] == "check" {
		if g.json {
			return okJSON(g, map[string]any{"version": t.Version, "sha256": t.SHA256, "url": t.URL, "metadata_version": m.Version, "expires_at": m.ExpiresAt})
		}
		fmt.Println(i18n.T(lang, "update.check", map[string]any{"version": t.Version}))
		fmt.Printf("sha256: %s\nurl: %s\n", t.SHA256, t.URL)
		return schema.ExitOK
	}
	// apply (G01): split the artifact list FIRST, verify EVERY part against
	// the signed metadata with its own per-component selector, stage each
	// verified copy, and install THE STAGED COPIES as one bundle
	// transaction. Tamper of any part fails before the first dpkg mutation.
	if *artifact == "" {
		return fail(g, lang, schema.CodeValidation, "error."+schema.CodeValidation, map[string]any{"detail": "--artifact required for apply"}, nil)
	}
	parts := strings.Split(*artifact, ",")
	stagedParts, verr := verifyAndStageParts(svc, *meta, roots, sel, parts, svc.UpdateStage, svc.UpdateCheck)
	if verr != nil {
		return fail(g, lang, schema.CodeVerification, "error."+schema.CodeVerification, nil, verr)
	}
	staged := strings.Join(stagedParts, ",")
	if *install {
		out, ierr := updateApplyBundle(svc, stagedParts, nil)
		if ierr != nil {
			return fail(g, lang, schema.CodeConflict, "error."+schema.CodeConflict, nil, ierr)
		}
		if g.json {
			return okJSON(g, map[string]any{"installed": staged, "dpkg": out})
		}
		fmt.Println(i18n.T(lang, "update.staged", map[string]any{"path": staged}))
		return schema.ExitOK
	}
	if g.json {
		return okJSON(g, map[string]any{"staged": staged, "next": "re-run with --install to complete the workflow (dpkg → restart → health), or install with the OS package manager"})
	}
	fmt.Println(i18n.T(lang, "update.staged", map[string]any{"path": staged}))
	return schema.ExitOK
}
