package workload

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// node builds a synthetic cgroup hierarchy, so the selection logic is tested
// against the layouts Kubernetes actually produces rather than against a
// cluster that has to exist for the test to run.
func node(t *testing.T, dirs ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestKubernetesRootFoundForBothDrivers(t *testing.T) {
	systemd := node(t, "kubepods.slice/kubepods-burstable.slice", "system.slice")
	if got, ok := KubernetesRoot(systemd); !ok || filepath.Base(got.Path) != "kubepods.slice" {
		t.Errorf("systemd driver root = %+v ok=%v", got, ok)
	}
	cgroupfs := node(t, "kubepods/burstable", "system.slice")
	if got, ok := KubernetesRoot(cgroupfs); !ok || filepath.Base(got.Path) != "kubepods" {
		t.Errorf("cgroupfs driver root = %+v ok=%v", got, ok)
	}
	plain := node(t, "system.slice", "user.slice")
	if _, ok := KubernetesRoot(plain); ok {
		t.Error("a node with no pod hierarchy reported one")
	}
}

// An agent outside the pod hierarchy gets the root, which is the reason to run
// it there.
func TestAgentOutsideTheHierarchyCapturesEverything(t *testing.T) {
	root := node(t, "kubepods.slice/kubepods-burstable.slice", "system.slice/tunless.service")
	got, err := CaptureScopes(root, "/system.slice/tunless.service")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || filepath.Base(got[0].Path) != "kubepods.slice" {
		t.Errorf("scopes = %+v, want the pod root", got)
	}
}

// An agent inside the hierarchy must not be offered the root: attaching there
// would capture its own connection to its upstream, and every packet it
// forwarded would be captured again on the way out.
func TestAgentInsideTheHierarchyIsNotOfferedTheRoot(t *testing.T) {
	root := node(t,
		"kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podAAA.slice",
		"kubepods.slice/kubepods-besteffort.slice",
		"kubepods.slice/kubepods-guaranteed.slice",
	)
	self := "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podAAA.slice/cri-containerd-abc.scope"
	got, err := CaptureScopes(root, self)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range got {
		if filepath.Base(s.Path) == "kubepods.slice" {
			t.Fatal("the pod root was offered to an agent inside it")
		}
		if filepath.Base(s.Path) == "kubepods-burstable.slice" {
			t.Error("the agent's own QoS subtree was offered")
		}
	}
	if len(got) != 2 {
		t.Errorf("scopes = %+v, want the two QoS classes the agent is not in", got)
	}
}

// The gap is real and must be reported rather than papered over: an agent that
// is the only thing on the node, or whose siblings are all in its own QoS
// class, has nowhere safe to attach.
func TestNoSafeSubtreeIsAnErrorNotAnEmptyList(t *testing.T) {
	root := node(t, "kubepods.slice/kubepods-burstable.slice")
	_, err := CaptureScopes(root, "/kubepods.slice/kubepods-burstable.slice/pod.scope")
	if !errors.Is(err, ErrWouldLoop) {
		t.Fatalf("err = %v, want ErrWouldLoop", err)
	}
}

// Containment is by path segment. A plain string prefix would judge
// /kubepods to contain /kubepods-other, which is a different subtree, and the
// agent would then be refused a scope it could safely have used.
func TestContainmentIsBySegmentNotByStringPrefix(t *testing.T) {
	root := "/sys/fs/cgroup"
	if containsSelf(root, "/sys/fs/cgroup/kubepods", "/kubepods-other/pod.scope") {
		t.Error("/kubepods was judged to contain /kubepods-other")
	}
	if !containsSelf(root, "/sys/fs/cgroup/kubepods", "/kubepods/burstable/pod.scope") {
		t.Error("/kubepods was not judged to contain its own child")
	}
	if !containsSelf(root, "/sys/fs/cgroup/kubepods", "/kubepods") {
		t.Error("a scope did not contain itself")
	}
	if !containsSelf(root, "/sys/fs/cgroup", "/anything") {
		t.Error("the whole hierarchy did not contain an arbitrary path")
	}
}

// A node with no pod hierarchy is not a Kubernetes node, and saying so is more
// useful than returning an empty list that reads like "nothing to capture".
func TestNonKubernetesNodeSaysSo(t *testing.T) {
	root := node(t, "system.slice", "user.slice")
	if _, err := CaptureScopes(root, "/system.slice/tunless.service"); err == nil {
		t.Error("a non-kubernetes node returned scopes without error")
	}
}
