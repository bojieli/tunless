package dnspolicy

import (
	"net/netip"
	"slices"
	"sort"

	"golang.org/x/net/dns/dnsmessage"
)

// PrefixSet is the set of addresses that make an answer from the direct
// resolver credible.
//
// It is stored as merged, sorted ranges rather than as the prefix list it was
// built from, and searched by bisection. The lists operators actually supply
// here run to five figures — a national address allocation is around nine
// thousand v4 prefixes before v6 — and this is consulted once per address in
// every adjudicated answer. A linear scan would put tens of thousands of
// comparisons inside the lookup path, which is the one place in this project
// that must not become the reason a page is slow.
//
// Merging is not only an optimisation. Supplied lists routinely contain
// adjacent and overlapping prefixes, and collapsing them means the bisection
// cannot land between two entries that jointly cover the address.
//
// A PrefixSet is read-only once built and safe for concurrent use.
type PrefixSet struct {
	v4 []addrRange
	v6 []addrRange
}

type addrRange struct{ lo, hi netip.Addr }

// NewPrefixSet builds a set from prefixes in any order, with any overlap.
func NewPrefixSet(prefixes []netip.Prefix) *PrefixSet {
	set := &PrefixSet{}
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			continue
		}
		lo, hi := prefixBounds(prefix)
		if !lo.IsValid() || !hi.IsValid() {
			continue
		}
		if lo.Is4() {
			set.v4 = append(set.v4, addrRange{lo, hi})
		} else {
			set.v6 = append(set.v6, addrRange{lo, hi})
		}
	}
	set.v4 = mergeRanges(set.v4)
	set.v6 = mergeRanges(set.v6)
	return set
}

// Empty reports whether the set covers nothing. An empty set disables
// adjudication rather than rejecting every answer, because a set that rejects
// everything is indistinguishable at runtime from a set that is working and
// finding nothing, and the second is a state an operator has to be able to
// recognise.
func (s *PrefixSet) Empty() bool {
	return s == nil || (len(s.v4) == 0 && len(s.v6) == 0)
}

// Len reports how many disjoint ranges remain after merging. It is what the
// status endpoint and the startup log report, so an operator can see that a
// file with fifty thousand lines in it produced a set with something in it.
func (s *PrefixSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.v4) + len(s.v6)
}

// Contains reports whether addr falls in the set. An IPv4-mapped IPv6 address
// is judged as the IPv4 address it carries, because that is the address a
// connection to it would use.
func (s *PrefixSet) Contains(addr netip.Addr) bool {
	if s == nil || !addr.IsValid() {
		return false
	}
	addr = addr.Unmap().WithZone("")
	ranges := s.v6
	if addr.Is4() {
		ranges = s.v4
	}
	if len(ranges) == 0 {
		return false
	}
	// The first range whose low end is above addr cannot contain it, so the one
	// before it is the only candidate.
	index := sort.Search(len(ranges), func(i int) bool {
		return ranges[i].lo.Compare(addr) > 0
	})
	if index == 0 {
		return false
	}
	candidate := ranges[index-1]
	return candidate.hi.Compare(addr) >= 0
}

// prefixBounds returns the first and last address a prefix covers.
func prefixBounds(prefix netip.Prefix) (netip.Addr, netip.Addr) {
	masked := prefix.Masked()
	lo := masked.Addr()
	octets := lo.AsSlice()
	for bit := masked.Bits(); bit < len(octets)*8; bit++ {
		octets[bit/8] |= byte(1) << (7 - bit%8)
	}
	hi, ok := netip.AddrFromSlice(octets)
	if !ok {
		return netip.Addr{}, netip.Addr{}
	}
	return lo, hi
}

// mergeRanges sorts and collapses overlapping or adjacent ranges.
func mergeRanges(ranges []addrRange) []addrRange {
	if len(ranges) < 2 {
		return ranges
	}
	slices.SortFunc(ranges, func(a, b addrRange) int {
		if cmp := a.lo.Compare(b.lo); cmp != 0 {
			return cmp
		}
		return a.hi.Compare(b.hi)
	})
	merged := ranges[:1]
	for _, next := range ranges[1:] {
		last := &merged[len(merged)-1]
		// Adjacent counts as overlapping: 10.0.0.0/24 and 10.0.1.0/24 leave no
		// address between them, and keeping them apart would only add a range
		// for the bisection to cross.
		if next.lo.Compare(last.hi) <= 0 || next.lo == last.hi.Next() {
			if next.hi.Compare(last.hi) > 0 {
				last.hi = next.hi
			}
			continue
		}
		merged = append(merged, next)
	}
	return merged
}

// maxAdjudicatedAnswers bounds how many records one reply is read for. A real
// answer carries a handful of addresses; the limit keeps a crafted reply with a
// vast answer section from turning one adjudication into a long parse.
const maxAdjudicatedAnswers = 64

// answerAddresses returns the A and AAAA addresses a reply carries.
//
// Only the answer section is read. Additional and authority records are not
// what the application will connect to, and believing an address because of a
// section the querier did not ask about is how a resolver gets poisoned by a
// record it never requested.
func answerAddresses(reply []byte) []netip.Addr {
	var parser dnsmessage.Parser
	if _, err := parser.Start(reply); err != nil {
		return nil
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return nil
	}
	var found []netip.Addr
	for range maxAdjudicatedAnswers {
		header, err := parser.AnswerHeader()
		if err != nil {
			break
		}
		switch header.Type {
		case dnsmessage.TypeA:
			record, err := parser.AResource()
			if err != nil {
				return found
			}
			found = append(found, netip.AddrFrom4(record.A))
		case dnsmessage.TypeAAAA:
			record, err := parser.AAAAResource()
			if err != nil {
				return found
			}
			found = append(found, netip.AddrFrom16(record.AAAA).Unmap())
		default:
			if err := parser.SkipAnswer(); err != nil {
				return found
			}
		}
	}
	return found
}

// ReplyAddresses returns the A and AAAA addresses a reply carries. It is the
// same reading Adjudicate does, exported so that diagnostics show exactly what
// the decision saw rather than a second opinion about it.
func ReplyAddresses(reply []byte) []netip.Addr { return answerAddresses(reply) }
