package socks5

import (
	"bytes"
	"context"
	"testing"
)

func FuzzParseAddr(f *testing.F) {
	for _, seed := range [][]byte{
		{1, 127, 0, 0, 1, 0, 53},
		{4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187},
		{3, 0},
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
		address, used, err := parseAddr(ctx, data)
		if err == nil {
			if !address.IsValid() || used < 1 || used > len(data) {
				t.Fatalf("invalid successful parse: address=%v used=%d input=%d", address, used, len(data))
			}
		}
		_, _ = readAddr(ctx, bytes.NewReader(data))
	})
}
