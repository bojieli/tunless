package workload

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Choosing where to attach on a Kubernetes node is a loop-avoidance problem
// before it is anything else.
//
// Capturing other pods' traffic means attaching above them, and on a node that
// is `kubepods.slice` or `kubepods`. But a DaemonSet is itself a pod, so it
// lives under that same root: attaching there captures the capture agent's own
// connection to its upstream, and every packet it forwards is captured again
// on the way out. There is no exception list that fixes this, because an
// exception list is exactly what this project exists not to need -- and an
// exception keyed on the agent's own address is the first thing a
// misconfiguration silently removes.
//
// What fixes it is cgroup separation, which is the same answer the desktop
// deployment uses when it captures `user.slice` from `system.slice`. On a node
// there are two ways to get it: run the agent outside the pod hierarchy
// entirely -- a systemd unit, or a static pod placed in `system.slice` -- and
// attach at the root; or run it as an ordinary pod and attach to the QoS
// subtrees it is not in.
//
// This file works out which of those is available and refuses the arrangements
// that would loop, rather than attaching and discovering it under load.

// ErrWouldLoop reports that attaching at the chosen scope would capture the
// calling process.
var ErrWouldLoop = errors.New("capture scope contains this process")

// Scope is a cgroup subtree a capture may attach to.
type Scope struct {
	// Path is absolute, as the attach syscall wants it.
	Path string
	// Why records what this subtree is, so an operator reading a log knows
	// whether the set covers what they expected.
	Why string
}

// kubernetesRoots are the pod hierarchy roots for the two cgroup drivers,
// most specific first. Both are checked because both are deployed and a node
// has exactly one.
var kubernetesRoots = []struct{ dir, why string }{
	{"kubepods.slice", "kubernetes pods, systemd cgroup driver"},
	{"kubepods", "kubernetes pods, cgroupfs cgroup driver"},
}

// KubernetesRoot returns the pod hierarchy root under fsRoot, if this is a
// Kubernetes node.
func KubernetesRoot(fsRoot string) (Scope, bool) {
	for _, candidate := range kubernetesRoots {
		p := filepath.Join(fsRoot, candidate.dir)
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return Scope{Path: p, Why: candidate.why}, true
		}
	}
	return Scope{}, false
}

// containsSelf reports whether attaching at scope would capture a process
// whose cgroup path is selfCgroup.
//
// The comparison is on path segments rather than string prefixes: a scope of
// `/kubepods` must not be judged to contain `/kubepods-other`, and a plain
// prefix test says it does.
func containsSelf(fsRoot, scope, selfCgroup string) bool {
	// Cgroup paths out of /proc always use forward slashes, but fsRoot is
	// joined with the host's separator, so on Windows the scope arrives with
	// backslashes and nothing matches.
	//
	// The normalization replaces backslashes directly rather than calling
	// filepath.ToSlash, which is a no-op on any host whose separator is
	// already "/". That would make this correct on Windows and untestable
	// anywhere else, which is the wrong trade for a comparison this load
	// bearing.
	fsRoot = slashed(fsRoot)
	scope = slashed(scope)
	rel := strings.TrimPrefix(scope, strings.TrimSuffix(fsRoot, "/"))
	rel = "/" + strings.Trim(rel, "/")
	self := "/" + strings.Trim(slashed(selfCgroup), "/")
	if rel == "/" {
		return true // the whole hierarchy contains everything
	}
	if self == rel {
		return true
	}
	return strings.HasPrefix(self, rel+"/")
}

// CaptureScopes returns the subtrees a capture may attach to on this node
// without capturing itself.
//
// When the agent is outside the pod hierarchy -- a systemd unit, or a static
// pod in system.slice -- the answer is the pod root itself, which is the whole
// point of running it there. When the agent is inside, the root is refused and
// the QoS subtrees it is not in are offered instead, which covers every pod
// except the ones sharing its own QoS class.
//
// That last gap is real and is reported rather than hidden: a burstable agent
// cannot capture other burstable pods this way, and an operator who needs
// those has to move the agent out of the hierarchy.
func CaptureScopes(fsRoot, selfCgroup string) ([]Scope, error) {
	root, ok := KubernetesRoot(fsRoot)
	if !ok {
		return nil, fmt.Errorf("no kubernetes pod hierarchy under %s", fsRoot)
	}
	if !containsSelf(fsRoot, root.Path, selfCgroup) {
		return []Scope{root}, nil
	}

	entries, err := os.ReadDir(root.Path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", root.Path, err)
	}
	var out []Scope
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		child := filepath.Join(root.Path, e.Name())
		if containsSelf(fsRoot, child, selfCgroup) {
			continue
		}
		out = append(out, Scope{Path: child, Why: "pod QoS class " + e.Name()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: %s, and it has no sibling subtree to attach to instead",
			ErrWouldLoop, root.Path)
	}
	return out, nil
}

// SelfCgroup reads the calling process's own cgroup path.
func SelfCgroup() string {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	return cgroupV2Path(string(b))
}

// slashed normalizes a path to forward slashes on every host, so the same
// input produces the same answer whatever built it.
func slashed(p string) string { return strings.ReplaceAll(p, `\`, "/") }
