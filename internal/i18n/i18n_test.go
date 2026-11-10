package i18n

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogsLoadAndHaveIdenticalKeySets(t *testing.T) {
	if err := LoadError(); err != nil {
		t.Fatal(err)
	}
	en, ru := Keys(EN), Keys(RU)
	if len(en) == 0 || len(ru) == 0 {
		t.Fatal("empty catalog")
	}
	set := map[string]bool{}
	for _, k := range en {
		set[k] = true
	}
	for _, k := range ru {
		if !set[k] {
			t.Errorf("key %q exists in ru but not en", k)
		}
		delete(set, k)
	}
	for k := range set {
		t.Errorf("key %q exists in en but not ru", k)
	}
}

// placeholderSet extracts {name} and plural parameter names, honoring
// nested braces inside plural branches.
func placeholderSet(tmpl string) map[string]bool {
	out := map[string]bool{}
	for i := 0; i < len(tmpl); i++ {
		if tmpl[i] != '{' {
			continue
		}
		end, ok := placeholderEnd(tmpl, i)
		if !ok {
			break
		}
		inner := tmpl[i+1 : end]
		name := strings.TrimSpace(inner)
		if idx := strings.Index(inner, ","); idx >= 0 {
			name = strings.TrimSpace(inner[:idx])
		}
		out[name] = true
		i = end
	}
	return out
}

func TestPlaceholderParity(t *testing.T) {
	if err := LoadError(); err != nil {
		t.Fatal(err)
	}
	for _, key := range Keys(EN) {
		enT := T(EN, key, nil)
		ruT := T(RU, key, nil)
		enP := placeholderSet(enT)
		ruP := placeholderSet(ruT)
		if len(enP) != len(ruP) {
			t.Errorf("key %q placeholder count differs: en %v ru %v", key, enP, ruP)
			continue
		}
		for p := range enP {
			if !ruP[p] {
				t.Errorf("key %q: placeholder %q missing in ru", key, p)
			}
		}
	}
}

func TestEmbeddedMatchCanonicalDesignLocales(t *testing.T) {
	// internal/i18n/locales is a build-time copy of design/locales because
	// go:embed cannot reach outside the package. This test fails when the
	// copies drift.
	for _, name := range []string{"en.json", "ru.json"} {
		emb, err := os.ReadFile(filepath.Join("locales", name))
		if err != nil {
			t.Fatalf("embedded %s: %v", name, err)
		}
		canon, err := os.ReadFile(filepath.Join("..", "..", "design", "locales", name))
		if err != nil {
			t.Fatalf("canonical design/locales/%s: %v", name, err)
		}
		if string(emb) != string(canon) {
			t.Errorf("%s differs between design/locales and internal/i18n/locales; sync the copy", name)
		}
	}
}

func TestResolveSystemLocale(t *testing.T) {
	cases := map[string]Lang{
		"ru_RU.UTF-8": RU,
		"ru":          RU,
		"en_US":       EN,
		"en":          EN,
		"de_DE":       EN,
		"":            EN,
	}
	for in, want := range cases {
		if got := Resolve(in); got != want {
			t.Errorf("Resolve(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestPluralRussianAndEnglish(t *testing.T) {
	ru := map[int]string{1: "1 правило", 2: "2 правила", 5: "5 правил", 11: "11 правил", 21: "21 правило", 22: "22 правила", 25: "25 правил"}
	for n, want := range ru {
		got := T(RU, "common.rule", map[string]any{"count": n})
		if got != want {
			t.Errorf("ru plural %d: %q, want %q", n, got, want)
		}
	}
	if got := T(EN, "common.rule", map[string]any{"count": 1}); got != "1 rule" {
		t.Errorf("en plural 1: %q", got)
	}
	if got := T(EN, "common.rule", map[string]any{"count": 3}); got != "3 rules" {
		t.Errorf("en plural 3: %q", got)
	}
	// exact match overrides category
	if got := render(EN, "{n, plural, =42 {the answer} other {# items}}", map[string]any{"n": 42}); got != "the answer" {
		t.Errorf("exact plural: %q", got)
	}
}

func TestMissingKeyReturnsKeyNotGarbage(t *testing.T) {
	if got := T(EN, "no.such.key", nil); got != "no.such.key" {
		t.Fatalf("missing key: %q", got)
	}
	// missing param stays visible rather than rendering empty lies
	if got := T(EN, "route.rule_id", map[string]any{}); !strings.Contains(got, "{rule}") {
		t.Fatalf("missing param hidden: %q", got)
	}
}

func TestNoRawParamsLeak(t *testing.T) {
	out := T(RU, "error.QUOTA_EXCEEDED", map[string]any{"reset_at": "2026-11-01T00:00:00Z"})
	if strings.Contains(out, "{") {
		t.Fatalf("unresolved placeholder in ru output: %q", out)
	}
	out = T(EN, "error.QUOTA_EXCEEDED", map[string]any{"reset_at": "2026-11-01T00:00:00Z"})
	if strings.Contains(out, "{") {
		t.Fatalf("unresolved placeholder in en output: %q", out)
	}
}
