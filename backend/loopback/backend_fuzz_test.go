package loopback

import (
	"bytes"
	"context"
	"testing"
)

func FuzzSOCKSAddresses(f *testing.F) {
	for _, seed := range [][]byte{
		{0, 0, 0, 1, 127, 0, 0, 1, 0, 53},
		{0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187},
		{0, 0, 0, 3, 0},
		{3, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0, 80},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			t.Skip()
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if address, used, err := parseDatagram(ctx, data); err == nil {
			if !address.IsValid() || used < 4 || used > len(data) {
				t.Fatalf("invalid successful datagram parse: address=%v used=%d input=%d", address, used, len(data))
			}
		}
		_, _, _ = readAddress(ctx, bytes.NewReader(data))
	})
}
