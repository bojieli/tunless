// Package workload turns the cgroup a flow came from into an identity a
// consumer can act on.
//
// Capturing at the socket layer already knows more than a proxy protocol can
// express: the kernel hands over the calling process, and on a host running
// containers that process sits in a cgroup whose path names the pod or
// container it belongs to. That name is the difference between a downstream
// transport guessing what a flow is from how many bytes it has moved, and
// being told.
//
// The distinction matters because byte counts are a poor proxy for intent. A
// request and a transfer of the same size are indistinguishable by volume and
// obvious by workload, and a policy that has to infer one from the other
// arrives at its answer after the flow it was deciding about has finished.
//
// What can honestly be recovered from a cgroup path is bounded, and this
// package does not exceed it. Kubernetes encodes the pod's UID and the
// container's ID, not the namespace and name a human would recognise: those
// live in the API server. Reporting the UID and saying it is a UID is the
// accurate answer; inventing a name for it would be a guess that reads like a
// fact.
package workload

import (
	"os"
	"path/filepath"
	"strings"
)

// Kind is the sort of supervisor that owns the cgroup.
type Kind string

const (
	KindKubernetes Kind = "kubernetes"
	KindContainer  Kind = "container"
	KindSystemd    Kind = "systemd"
	KindUnknown    Kind = "unknown"
)

// Identity is what a cgroup path reveals. Fields not determinable from the
// path are empty rather than guessed.
type Identity struct {
	Kind Kind `json:"kind"`
	// PodUID is the Kubernetes pod UID, which is what the cgroup path carries.
	// The pod's namespace and name require the API server and are not invented
	// here.
	PodUID string `json:"pod_uid,omitempty"`
	// ContainerID is the runtime's container identifier, truncated by the
	// runtime itself in some cgroup layouts.
	ContainerID string `json:"container_id,omitempty"`
	// Unit is the systemd unit for a host process.
	Unit string `json:"unit,omitempty"`
	// Cgroup is the path the rest was derived from, kept so a consumer that
	// disagrees with this parse can redo it.
	Cgroup string `json:"cgroup,omitempty"`
}

// Empty reports whether nothing was determined, which is the honest state for
// a host with no container runtime and no systemd.
func (i Identity) Empty() bool {
	return i.Kind == "" || (i.Kind == KindUnknown && i.PodUID == "" && i.ContainerID == "" && i.Unit == "")
}

// String is a stable single-token rendering for logs and for grouping.
func (i Identity) String() string {
	switch {
	case i.PodUID != "" && i.ContainerID != "":
		return "k8s:" + i.PodUID + "/" + short(i.ContainerID)
	case i.PodUID != "":
		return "k8s:" + i.PodUID
	case i.ContainerID != "":
		return "container:" + short(i.ContainerID)
	case i.Unit != "":
		return "unit:" + i.Unit
	}
	return "unknown"
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// FromCgroupPath parses the cgroup path of a process.
//
// Both cgroup drivers are handled because both are deployed. The systemd
// driver encodes the pod as `kubepods-burstable-pod<UID>.slice` with dashes
// substituted for the UID's own, and the cgroupfs driver encodes it as
// `pod<UID>` with the UID intact. Treating one as the other yields a UID that
// looks plausible and matches nothing.
func FromCgroupPath(path string) Identity {
	id := Identity{Kind: KindUnknown, Cgroup: path}
	if path == "" {
		return id
	}
	segments := strings.Split(strings.Trim(path, "/"), "/")
	for _, seg := range segments {
		switch {
		case strings.HasPrefix(seg, "kubepods-") && strings.Contains(seg, "-pod"):
			// systemd driver: kubepods-burstable-pod<uid-with-dashes>.slice
			rest := seg[strings.Index(seg, "-pod")+len("-pod"):]
			rest = strings.TrimSuffix(rest, ".slice")
			id.Kind = KindKubernetes
			id.PodUID = strings.ReplaceAll(rest, "_", "-")
		case strings.HasPrefix(seg, "pod") && looksLikeUID(seg[3:]):
			// cgroupfs driver: pod<uid>
			id.Kind = KindKubernetes
			id.PodUID = seg[3:]
		case strings.HasSuffix(seg, ".scope"):
			if cid := containerIDFromScope(seg); cid != "" {
				id.ContainerID = cid
				if id.Kind != KindKubernetes {
					id.Kind = KindContainer
				}
			}
		case strings.HasSuffix(seg, ".service"):
			if id.Kind == KindUnknown {
				id.Kind = KindSystemd
				id.Unit = seg
			}
		case looksLikeContainerID(seg):
			id.ContainerID = seg
			if id.Kind != KindKubernetes {
				id.Kind = KindContainer
			}
		}
	}
	return id
}

// containerIDFromScope pulls the identifier out of the runtime-prefixed scope
// names the common runtimes emit.
func containerIDFromScope(seg string) string {
	body := strings.TrimSuffix(seg, ".scope")
	for _, prefix := range []string{
		"cri-containerd-", "crio-", "docker-", "containerd-", "libpod-",
	} {
		if rest, ok := strings.CutPrefix(body, prefix); ok {
			return rest
		}
	}
	if looksLikeContainerID(body) {
		return body
	}
	return ""
}

func looksLikeContainerID(s string) bool {
	if len(s) < 12 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// looksLikeUID accepts both the dashed form and the underscore-substituted
// form the systemd driver produces, without accepting arbitrary text that
// merely began with "pod".
func looksLikeUID(s string) bool {
	if len(s) < 8 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9',
			r >= 'a' && r <= 'f',
			r >= 'A' && r <= 'F',
			r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// FromPID reads the cgroup of a running process.
//
// The cgroup v2 line is the one with an empty controller field, which is how
// it is distinguished from the v1 lines a hybrid host also lists. A process
// that has exited between capture and lookup yields an empty identity rather
// than an error: the flow is still worth carrying, just with less known about
// it.
func FromPID(pid int32) Identity {
	b, err := os.ReadFile(filepath.Join("/proc", itoa(pid), "cgroup"))
	if err != nil {
		return Identity{Kind: KindUnknown}
	}
	return FromCgroupPath(cgroupV2Path(string(b)))
}

// cgroupV2Path extracts the unified hierarchy path from /proc/PID/cgroup.
func cgroupV2Path(contents string) string {
	var v1 string
	for _, line := range strings.Split(contents, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[1] == "" {
			return parts[2] // unified hierarchy
		}
		// Keep a v1 line as a fallback for hosts that have not migrated.
		if v1 == "" {
			v1 = parts[2]
		}
	}
	return v1
}

func itoa(v int32) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [12]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
