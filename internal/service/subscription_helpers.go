package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func jsonMarshalIndent(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func httpClientWithTimeout(d time.Duration) *http.Client {
	return &http.Client{Timeout: d}
}

var _ = fmt.Sprintf
