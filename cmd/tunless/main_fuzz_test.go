package main

import "testing"

func FuzzConfigurationParsers(f *testing.F) {
	for _, seed := range []string{
		"127.0.0.1:7890",
		"socks5://user:pass@localhost:1080",
		"[::1]:1080",
		"0::/docker/0123456789abcdef\n",
		"192.0.2.0/24",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 4096 {
			t.Skip()
		}
		_, _ = parseUpstream(value)
		_, _ = prefixes([]string{value})
		_, _ = cgroupPathFromProc([]byte(value))
		_ = validateContainerID(value)
	})
}
