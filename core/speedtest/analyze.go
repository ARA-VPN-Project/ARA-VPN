package speedtest

// Analyzer: turns measured segments into an EXPLAINABLE hypothesis with
// evidence and confidence. Hard rules (docs/SPEEDTEST.md):
//   - chain goodput is never computed by subtracting segment speeds;
//   - good segments do not guarantee the same chain speed (reported as a
//     caveat, not dropped);
//   - one test never "proves" a cause: hypotheses carry confidence, the
//     evidence that produced them, and what to run next.

import (
	"fmt"
	"math"
	"sort"
)

// Hypothesis is one explainable candidate explanation.
type Hypothesis struct {
	Cause      string   `json:"cause"`       // stable machine id (bottleneck.client-edge etc.)
	DetailRU   string   `json:"detail_ru"`   // RU/EN text resolved by surfaces
	DetailEN   string   `json:"detail_en"`
	Confidence string   `json:"confidence"`  // low | medium | high
	Evidence   []string `json:"evidence"`    // the numbers behind the claim
	Next       string   `json:"next,omitempty"` // suggested follow-up measurement
}

// Analysis is the report section after a chain of segment results.
type Analysis struct {
	Hypotheses []Hypothesis `json:"hypotheses"`
	Caveats    []string     `json:"caveats"`
}

// Observation is one measured direction feeding the analyzer.
type Observation struct {
	Segment      Segment
	Dest         string
	Direction    Direction
	GoodputMbps  float64
	OK           bool
	Error        string
	RTTP50IdleMs float64
	RTTP95IdleMs float64
	RTTP95LoadedMs float64
	FailedProbeRatio float64
	RateLimited  bool
	RateLimitNote string
}

// Analyze builds hypotheses from the chain client-edge → edge-exit → e2e.
// All inputs are optional; the analysis covers what exists.
func Analyze(obs []Observation) Analysis {
	a := Analysis{}
	addCaveat := func(s string) { a.Caveats = append(a.Caveats, s) }

	ceDownOK := false
	var ceDown Observation
	for _, o := range obs {
		if o.Segment == SegClientEdge && o.Direction == DirDown && o.OK {
			ceDown, ceDownOK = o, true
		}
	}

	// 1. A configured limit bounding the result is the FIRST explanation:
	// a rate/quota cap means "path is at least this fast", not "this slow".
	for _, o := range obs {
		if o.RateLimited && o.OK {
			a.Hypotheses = append(a.Hypotheses, Hypothesis{
				Cause: "bounded.by_limit",
				DetailRU: "Скорость ограничена действующим лимитом/квотой (" + o.RateLimitNote + "); реальная ёмкость пути не ниже и может быть выше.",
				DetailEN: "Speed is bounded by the active limit/quota (" + o.RateLimitNote + "); the path capacity is at least this and may be higher.",
				Confidence: "high",
				Evidence:   []string{fmt.Sprintf("%s %s %.1f Mbit/s ≈ limit", o.Segment, o.Direction, o.GoodputMbps)},
				Next:       "run the admin capacity test (server-side capability) for the unbounded value",
			})
		}
	}

	// 2. Explicit failures dominate their segment.
	for _, o := range obs {
		if o.OK {
			continue
		}
		cause := "unreachable." + string(o.Segment)
		detailRU := fmt.Sprintf("Участок %s (%s) недоступен: %s", o.Segment, o.Direction, o.Error)
		detailEN := fmt.Sprintf("Segment %s (%s) is unreachable: %s", o.Segment, o.Direction, o.Error)
		if o.FailedProbeRatio >= 1 {
			detailRU += "; все пробы неуспешны"
			detailEN += "; all probes failed"
		}
		a.Hypotheses = append(a.Hypotheses, Hypothesis{
			Cause: cause, DetailRU: detailRU, DetailEN: detailEN,
			Confidence: "high",
			Evidence:   []string{o.Error, fmt.Sprintf("failed_probe_ratio=%.2f", o.FailedProbeRatio)},
		})
	}

	// 3. Segment comparison for the bottleneck hypothesis: only when both
	// the first hop and the chain succeeded. NO subtraction: the chain
	// value is compared, not derived.
	var e2eDown *Observation
	for i := range obs {
		o := obs[i]
		if o.Segment == SegEndToEnd && o.Direction == DirDown && o.OK {
			e2eDown = &obs[i]
		}
	}
	if ceDownOK && e2eDown != nil {
		switch {
		case e2eDown.GoodputMbps <= ceDown.GoodputMbps*0.6:
			// chain much slower than the first hop: the bottleneck is past
			// the first hop with medium confidence (transit or exit side)
			a.Hypotheses = append(a.Hypotheses, Hypothesis{
				Cause:   "bottleneck.past_first_hop",
				DetailRU: fmt.Sprintf("Сквозная скорость (%.1f Мбит/с) заметно ниже участка клиент↔Edge (%.1f Мбит/с) — вероятное узкое место дальше первого участка (транзит Edge→Exit или сам Exit).", e2eDown.GoodputMbps, ceDown.GoodputMbps),
				DetailEN: fmt.Sprintf("End-to-end (%.1f Mbit/s) is far below client↔Edge (%.1f Mbit/s) — the bottleneck is likely beyond the first hop (Edge→Exit transit or the exit itself).", e2eDown.GoodputMbps, ceDown.GoodputMbps),
				Confidence: "medium",
				Evidence: []string{
					fmt.Sprintf("client-edge down %.1f", ceDown.GoodputMbps),
					fmt.Sprintf("e2e down %.1f", e2eDown.GoodputMbps),
				},
				Next: "measure edge-exit per exit to localize",
			})
		case ceDown.GoodputMbps <= e2eDown.GoodputMbps*0.6:
			a.Hypotheses = append(a.Hypotheses, Hypothesis{
				Cause:   "bottleneck.client_edge",
				DetailRU: fmt.Sprintf("Участок клиент↔Edge (%.1f Мбит/с) заметно ниже сквозной (%.1f Мбит/с) — вероятное узкое место на первом участке (доступ, Wi-Fi, провайдер).", ceDown.GoodputMbps, e2eDown.GoodputMbps),
				DetailEN: fmt.Sprintf("Client↔Edge (%.1f Mbit/s) is far below end-to-end (%.1f Mbit/s) — the first hop (access link, Wi-Fi, ISP) is the likely bottleneck.", ceDown.GoodputMbps, e2eDown.GoodputMbps),
				Confidence: "medium",
				Evidence: []string{
					fmt.Sprintf("client-edge down %.1f", ceDown.GoodputMbps),
					fmt.Sprintf("e2e down %.1f", e2eDown.GoodputMbps),
				},
			})
		default:
			addCaveat("Участки сопоставимы, но это не гарантирует такую же скорость цепочки в других условиях / Caveat: comparable segments do not guarantee the same chain speed")
		}
	}

	// 4. Asymmetry hint (upload vs download on the same segment).
	bySeg := map[Segment][2]*Observation{}
	for i := range obs {
		o := obs[i]
		if !o.OK {
			continue
		}
		p := bySeg[o.Segment]
		if o.Direction == DirDown && p[0] == nil {
			p[0] = &obs[i]
		}
		if o.Direction == DirUp && p[1] == nil {
			p[1] = &obs[i]
		}
		bySeg[o.Segment] = p
	}
	for seg, p := range bySeg {
		if p[0] == nil || p[1] == nil {
			continue
		}
		d, u := p[0].GoodputMbps, p[1].GoodputMbps
		if math.Max(d, u) > 0 && math.Min(d, u)/math.Max(d, u) < 0.4 {
			a.Hypotheses = append(a.Hypotheses, Hypothesis{
				Cause:   "asymmetry." + string(seg),
				DetailRU: fmt.Sprintf("Заметная асимметрия на %s: down %.1f / up %.1f Мбит/с — проверьте лимиты направлений и канал доступа.", seg, d, u),
				DetailEN: fmt.Sprintf("Pronounced asymmetry on %s: down %.1f / up %.1f Mbit/s — check per-direction limits and the access link.", seg, d, u),
				Confidence: "medium",
				Evidence:   []string{fmt.Sprintf("down=%.1f up=%.1f", d, u)},
			})
		}
	}

	// 5. Latency growth under load (bufferbloat hint).
	for _, o := range obs {
		if !o.OK || o.RTTP95LoadedMs == 0 || o.RTTP50IdleMs == 0 {
			continue
		}
		if o.RTTP95LoadedMs > 3*o.RTTP50IdleMs+30 {
			a.Hypotheses = append(a.Hypotheses, Hypothesis{
				Cause:   "latency.under_load." + string(o.Segment),
				DetailRU: fmt.Sprintf("Задержка растёт под нагрузкой на %s: p50 idle %.0f мс → p95 loaded %.0f мс (переполнение буферов).", o.Segment, o.RTTP50IdleMs, o.RTTP95LoadedMs),
				DetailEN: fmt.Sprintf("Latency grows under load on %s: p50 idle %.0f ms → p95 loaded %.0f ms (bufferbloat).", o.Segment, o.RTTP50IdleMs, o.RTTP95LoadedMs),
				Confidence: "low",
				Evidence:   []string{fmt.Sprintf("idle_p50=%.0f loaded_p95=%.0f", o.RTTP50IdleMs, o.RTTP95LoadedMs)},
			})
		}
	}

	sort.Slice(a.Hypotheses, func(i, j int) bool {
		return confRank(a.Hypotheses[i].Confidence) < confRank(a.Hypotheses[j].Confidence)
	})
	if len(a.Hypotheses) == 0 && len(obs) > 0 {
		addCaveat("Явных узких мест по одному прогону не видно; один тест не доказывает причину / No obvious bottleneck from one run; one test never proves a cause")
	}
	if len(obs) == 0 {
		addCaveat("Нет наблюдений для анализа / no observations")
	}
	return a
}

func confRank(c string) int {
	switch c {
	case "high":
		return 0
	case "medium":
		return 1
	default:
		return 2
	}
}
