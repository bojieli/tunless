package dnspolicy

import (
	"fmt"
	"strings"

	"github.com/bojieli/tunless/internal/dnsname"
)

// SuffixSet maps name suffixes to routes, and answers with the longest one that
// matches.
//
// Longest match rather than list order, because that is what every resolver an
// operator already runs does — dnsmasq, mosdns and systemd-resolved all resolve
// an overlap by specificity — and because the overlap has an obvious intended
// meaning that order would get wrong. Someone who sends `example.com` down the
// direct path and `secret.example.com` through the tunnel has said something
// precise, and a set that resolved that by which file loaded first would
// silently do the opposite of it.
//
// The trie is over labels rather than characters, so `notexample.com` cannot
// match `example.com` by sharing a suffix that does not start at a label
// boundary.
//
// A SuffixSet is read-only once built and safe for concurrent use.
type SuffixSet struct {
	root  *suffixNode
	count int
}

type suffixNode struct {
	children map[string]*suffixNode
	route    Route
	// suffix is the presentation form that reached this node, kept so a match
	// can report which line of which list decided.
	suffix string
}

func NewSuffixSet() *SuffixSet {
	return &SuffixSet{root: &suffixNode{}}
}

// Len reports how many suffixes carry a route.
func (s *SuffixSet) Len() int {
	if s == nil {
		return 0
	}
	return s.count
}

// Add records one suffix.
//
// A suffix already present keeps RouteTrusted if either entry asked for it.
// That is the tie-break for an exact duplicate across the two lists, and it
// breaks toward the tunnel on purpose: the direct list is the one an operator
// downloads with thousands of entries in it, the trusted list is the one they
// write by hand to carve exceptions out of it, and a collision between a list
// you audited and a list you did not should resolve in favour of the audited
// one. It also fails safe — a name that ends up on the tunnel by accident is
// slow, and one that ends up on the direct path by accident is exposed.
func (s *SuffixSet) Add(suffix string, route Route) error {
	if s.root == nil {
		s.root = &suffixNode{}
	}
	canonical := dnsname.Canonical(strings.TrimSpace(suffix))
	if canonical == "" {
		return fmt.Errorf("empty name suffix")
	}
	if strings.ContainsAny(canonical, " \t") {
		return fmt.Errorf("name suffix %q contains whitespace", suffix)
	}
	labels := strings.Split(canonical, ".")
	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("name suffix %q has an empty label", suffix)
		}
		if len(label) > 63 {
			return fmt.Errorf("name suffix %q has a label longer than 63 octets", suffix)
		}
	}
	node := s.root
	for i := len(labels) - 1; i >= 0; i-- {
		if node.children == nil {
			node.children = make(map[string]*suffixNode)
		}
		child, ok := node.children[labels[i]]
		if !ok {
			child = &suffixNode{}
			node.children[labels[i]] = child
		}
		node = child
	}
	if node.route == RouteUnset {
		s.count++
		node.route = route
		node.suffix = canonical
		return nil
	}
	if node.route != route {
		node.route = RouteTrusted
	}
	return nil
}

// Match returns the route of the longest suffix covering name.
func (s *SuffixSet) Match(name string) (Route, string, bool) {
	if s == nil || s.root == nil || s.count == 0 {
		return RouteUnset, "", false
	}
	canonical := dnsname.Canonical(name)
	if canonical == "" {
		return RouteUnset, "", false
	}
	labels := strings.Split(canonical, ".")
	node := s.root
	best := RouteUnset
	bestSuffix := ""
	for i := len(labels) - 1; i >= 0; i-- {
		if node.children == nil {
			break
		}
		child, ok := node.children[labels[i]]
		if !ok {
			break
		}
		node = child
		if node.route != RouteUnset {
			best, bestSuffix = node.route, node.suffix
		}
	}
	return best, bestSuffix, best != RouteUnset
}
