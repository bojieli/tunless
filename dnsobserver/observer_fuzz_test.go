package dnsobserver

import (
	"net/netip"
	"testing"
	"time"
)

func FuzzObserveDNS(f *testing.F) {
	f.Add(
		[]byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1},
		[]byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1},
	)
	f.Fuzz(func(t *testing.T, query, reply []byte) {
		if len(query) > 65535 || len(reply) > 65535 {
			t.Skip()
		}
		o := &Observer{records: make(map[netip.Addr]map[string]time.Time)}
		o.observe(query, reply)
	})
}
