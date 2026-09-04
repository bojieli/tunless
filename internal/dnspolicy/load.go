package dnspolicy

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
)

// maxListBytes bounds a list file. The lists operators supply here are large by
// design — a national address allocation is tens of thousands of prefixes, and
// the matching name lists run to six figures — so the limit is generous. It
// exists so that a path pointed at the wrong file fails at startup with a clear
// message instead of being read into memory.
const maxListBytes = 64 << 20

// maxListEntries bounds how many entries one file may contribute.
const maxListEntries = 1 << 20

// LoadSuffixFile reads one name suffix per line.
//
// Blank lines and comments are skipped, and an inline comment ends a line, so a
// generated list can carry provenance next to the entry it belongs to. Nothing
// else about the format is negotiable: this reads a list, not a configuration
// language, and the moment it parses somebody else's file format it owns that
// format's next revision.
func LoadSuffixFile(path string) ([]string, error) {
	var suffixes []string
	err := readList(path, func(line string) error {
		if len(suffixes) >= maxListEntries {
			return fmt.Errorf("more than %d entries", maxListEntries)
		}
		suffixes = append(suffixes, line)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return suffixes, nil
}

// LoadPrefixFile reads one CIDR prefix per line, in either address family.
//
// A bare address is accepted as a host route, because a hand-written exception
// list is easier to read without a /32 on every line and every line that omits
// one plainly means the single address.
func LoadPrefixFile(path string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	err := readList(path, func(line string) error {
		if len(prefixes) >= maxListEntries {
			return fmt.Errorf("more than %d entries", maxListEntries)
		}
		prefix, err := ParsePrefix(line)
		if err != nil {
			return err
		}
		prefixes = append(prefixes, prefix)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return prefixes, nil
}

// ParsePrefix accepts a CIDR prefix or a bare address.
func ParsePrefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR prefix %q", value)
		}
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid address or CIDR prefix %q", value)
	}
	addr = addr.Unmap().WithZone("")
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// readList applies visit to each meaningful line of a list file, reporting the
// line number with any error the visitor returns. A file this large is one
// nobody reads by hand, so an error that does not say where is an error that
// costs an afternoon.
func readList(path string, visit func(string) error) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() > maxListBytes {
		return fmt.Errorf("%s is larger than the %d MiB list limit", path, maxListBytes>>20)
	}
	scanner := bufio.NewScanner(io.LimitReader(file, maxListBytes))
	// A generated list has no long lines, but one produced by a tool that
	// forgot its newlines has exactly one, and the default 64 KiB token would
	// report that as a truncated entry rather than as the malformed file it is.
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for line := 1; scanner.Scan(); line++ {
		entry := strings.TrimSpace(scanner.Text())
		if cut := strings.IndexAny(entry, "#;"); cut >= 0 {
			entry = strings.TrimSpace(entry[:cut])
		}
		if entry == "" {
			continue
		}
		if err := visit(entry); err != nil {
			return fmt.Errorf("%s:%d: %w", path, line, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
