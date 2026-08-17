package metadata

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func FuzzMetadataLookup(f *testing.F) {
	for _, seed := range []string{"", "0", "53", "65535", "65536", "-1", "80junk", "%00"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, sourcePort string) {
		if len(sourcePort) > 1024 {
			t.Skip()
		}
		s := &Server{}
		r := httptest.NewRequest(http.MethodGet, "/v1/flow?source_port="+url.QueryEscape(sourcePort), nil)
		w := httptest.NewRecorder()
		s.handle(w, r)
		if w.Code < 100 || w.Code > 599 {
			t.Fatalf("invalid HTTP status %d", w.Code)
		}
	})
}
