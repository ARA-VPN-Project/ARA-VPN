// Package i18n resolves stable message keys into localized human text for
// RU and EN (docs/UI_I18N.md). Machine contracts — error codes, JSON keys,
// CLI syntax — are never localized; only message_key + typed params are.
//
// A minimal ICU-plural subset is supported: {count, plural, =1 {one item}
// other {# items}} with English one/other and Russian one/few/many/other
// categories. '#' inside a plural branch substitutes the count.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//go:embed locales/en.json locales/ru.json
var localeFS embed.FS

// Lang is a supported UI language.
type Lang string

const (
	EN Lang = "en"
	RU Lang = "ru"
)

// Resolve maps a system locale tag to a supported language: ru-* → ru,
// en-* → en, anything else → en (first-run default per docs/UI_I18N.md).
// Both RFC 5646 ("ru-RU") and POSIX ("ru_RU.UTF-8") forms are accepted.
func Resolve(systemLocale string) Lang {
	l := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(systemLocale)), "_", "-")
	if l == "" {
		return EN
	}
	if l == "ru" || strings.HasPrefix(l, "ru-") {
		return RU
	}
	if l == "en" || strings.HasPrefix(l, "en-") {
		return EN
	}
	return EN
}

type catalog map[string]string

var (
	catalogs = map[Lang]catalog{}
	loadErr  error
)

func init() {
	for _, l := range []Lang{EN, RU} {
		b, err := localeFS.ReadFile("locales/" + string(l) + ".json")
		if err != nil {
			loadErr = fmt.Errorf("locale %s missing: %w", l, err)
			return
		}
		var c catalog
		if err := json.Unmarshal(b, &c); err != nil {
			loadErr = fmt.Errorf("locale %s invalid: %w", l, err)
			return
		}
		catalogs[l] = c
	}
}

// LoadError reports embedded-catalog problems (build-time invariant).
func LoadError() error { return loadErr }

// Keys returns the sorted key set of a language (used by parity tests and
// the CLI `ara i18n-check` maintenance command).
func Keys(l Lang) []string {
	c := catalogs[l]
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// T translates key with parameters for the language. Unknown keys return
// the key itself (a missing-key bug must be loud, never an empty string).
func T(l Lang, key string, params map[string]any) string {
	c := catalogs[l]
	if c == nil {
		return key
	}
	tmpl, ok := c[key]
	if !ok {
		if alt := catalogs[EN]; l != EN {
			tmpl, ok = alt[key]
		}
		if !ok {
			return key
		}
	}
	return render(l, tmpl, params)
}

// render substitutes {name} placeholders and ICU plural selectors.
func render(l Lang, tmpl string, params map[string]any) string {
	var b strings.Builder
	i := 0
	for i < len(tmpl) {
		c := tmpl[i]
		if c != '{' {
			b.WriteByte(c)
			i++
			continue
		}
		end, ok := placeholderEnd(tmpl, i)
		if !ok {
			b.WriteString(tmpl[i:])
			break
		}
		inner := tmpl[i+1 : end]
		if strings.Contains(inner, ", plural,") {
			b.WriteString(selectPlural(l, inner, params))
		} else if v, ok := params[strings.TrimSpace(inner)]; ok {
			b.WriteString(fmt.Sprint(v))
		} else {
			b.WriteString("{" + inner + "}") // missing param stays visible
		}
		i = end + 1
	}
	return b.String()
}

// placeholderEnd returns the index of the '}' matching the '{' at start,
// honoring nested braces so plural branches are not cut short.
func placeholderEnd(tmpl string, start int) (int, bool) {
	depth := 0
	for i := start; i < len(tmpl); i++ {
		switch tmpl[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

// selectPlural handles "{count, plural, =1 {…} one {…} other {…}}".
func selectPlural(l Lang, inner string, params map[string]any) string {
	parts := strings.SplitN(inner, ",", 3)
	name := strings.TrimSpace(parts[0])
	body := parts[2]
	count := toFloat(params[name])
	branches := parseBranches(body)
	var pick string
	// exact match takes precedence, then language category
	if s, ok := branches["="+fmt.Sprint(int64(count))]; ok {
		pick = s
	} else {
		cat := category(l, count)
		pick, ok = branches[cat]
		if !ok {
			pick = branches["other"]
		}
	}
	return strings.ReplaceAll(pick, "#", trimNum(count))
}

func parseBranches(body string) map[string]string {
	out := map[string]string{}
	depth := 0
	var key strings.Builder
	var val strings.Builder
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c == '{':
			depth++
			if depth == 1 {
				// key already holds the selector accumulated before the
				// brace; start a fresh value buffer
				val.Reset()
				continue
			}
			val.WriteByte(c)
		case c == '}':
			depth--
			if depth == 0 {
				out[strings.TrimSpace(key.String())] = val.String()
				key.Reset()
				val.Reset()
				continue
			}
			val.WriteByte(c)
		default:
			if depth == 0 {
				key.WriteByte(c)
			} else {
				val.WriteByte(c)
			}
		}
	}
	return out
}

func toFloat(v any) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case int32:
		return float64(n)
	case int64:
		return float64(n)
	case float64:
		return n
	case float32:
		return float64(n)
	}
	return 0
}

func trimNum(f float64) string {
	if f == float64(int64(f)) {
		return fmt.Sprint(int64(f))
	}
	return fmt.Sprintf("%.1f", f)
}

// category implements CLDR plural categories for ru and en.
func category(l Lang, n float64) string {
	switch l {
	case RU:
		i := int64(n)
		frac := n != float64(i)
		if frac {
			return "other"
		}
		mod10, mod100 := i%10, i%100
		switch {
		case mod10 == 1 && mod100 != 11:
			return "one"
		case mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14):
			return "few"
		default:
			return "many"
		}
	default: // EN
		if n == 1 {
			return "one"
		}
		return "other"
	}
}
