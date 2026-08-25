package workload

import "testing"

// The two cgroup drivers encode a pod differently and both are deployed.
// Parsing one as the other yields a UID that looks plausible and matches
// nothing, which is worse than reporting nothing.
func TestKubernetesPodUIDFromBothCgroupDrivers(t *testing.T) {
	for _, c := range []struct {
		name, path, wantPod, wantContainer string
	}{
		{
			name:          "systemd driver",
			path:          "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1a2b3c4d_5e6f_7081_92a3_b4c5d6e7f809.slice/cri-containerd-9f8e7d6c5b4a3928170615243342516071829304.scope",
			wantPod:       "1a2b3c4d-5e6f-7081-92a3-b4c5d6e7f809",
			wantContainer: "9f8e7d6c5b4a3928170615243342516071829304",
		},
		{
			name:          "cgroupfs driver",
			path:          "/kubepods/burstable/pod1a2b3c4d-5e6f-7081-92a3-b4c5d6e7f809/9f8e7d6c5b4a3928170615243342516071829304",
			wantPod:       "1a2b3c4d-5e6f-7081-92a3-b4c5d6e7f809",
			wantContainer: "9f8e7d6c5b4a3928170615243342516071829304",
		},
		{
			name:          "crio runtime",
			path:          "/kubepods.slice/kubepods-podabcdef01_2345_6789_abcd_ef0123456789.slice/crio-1122334455667788990011223344556677889900.scope",
			wantPod:       "abcdef01-2345-6789-abcd-ef0123456789",
			wantContainer: "1122334455667788990011223344556677889900",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := FromCgroupPath(c.path)
			if got.Kind != KindKubernetes {
				t.Errorf("kind = %q, want kubernetes", got.Kind)
			}
			if got.PodUID != c.wantPod {
				t.Errorf("pod uid = %q, want %q", got.PodUID, c.wantPod)
			}
			if got.ContainerID != c.wantContainer {
				t.Errorf("container = %q, want %q", got.ContainerID, c.wantContainer)
			}
		})
	}
}

func TestPlainContainerAndSystemdUnits(t *testing.T) {
	docker := FromCgroupPath("/docker/aabbccddeeff00112233445566778899aabbccddeeff001122334455667788")
	if docker.Kind != KindContainer || docker.ContainerID == "" {
		t.Errorf("docker cgroup parsed as %+v", docker)
	}
	scope := FromCgroupPath("/system.slice/docker-aabbccddeeff0011223344556677889900.scope")
	if scope.Kind != KindContainer || scope.ContainerID != "aabbccddeeff0011223344556677889900" {
		t.Errorf("docker scope parsed as %+v", scope)
	}
	unit := FromCgroupPath("/system.slice/nginx.service")
	if unit.Kind != KindSystemd || unit.Unit != "nginx.service" {
		t.Errorf("systemd unit parsed as %+v", unit)
	}
}

// A path that merely begins with "pod" is not a pod. Accepting it would
// attribute host processes to a Kubernetes workload that does not exist.
func TestDoesNotInventPodsFromArbitraryNames(t *testing.T) {
	for _, path := range []string{
		"/system.slice/podman.service",
		"/user.slice/user-1000.slice/session-3.scope",
		"/system.slice/podcast-downloader.service",
		"",
	} {
		got := FromCgroupPath(path)
		if got.PodUID != "" {
			t.Errorf("%q produced pod uid %q", path, got.PodUID)
		}
		if got.Kind == KindKubernetes {
			t.Errorf("%q classified as kubernetes", path)
		}
	}
}

// The unified hierarchy line is the one with an empty controller field. A
// hybrid host lists v1 lines too, and taking the first line would report a
// controller-specific path that need not name the workload at all.
func TestUnifiedHierarchyIsPreferredOverV1Lines(t *testing.T) {
	hybrid := "12:pids:/system.slice/other.service\n" +
		"4:memory:/system.slice/another.service\n" +
		"0::/kubepods.slice/kubepods-pod00112233_4455_6677_8899_aabbccddeeff.slice\n"
	if got := cgroupV2Path(hybrid); got != "/kubepods.slice/kubepods-pod00112233_4455_6677_8899_aabbccddeeff.slice" {
		t.Errorf("v2 path = %q", got)
	}
	// A v1-only host still gets an answer rather than nothing.
	v1only := "12:pids:/system.slice/nginx.service\n"
	if got := cgroupV2Path(v1only); got != "/system.slice/nginx.service" {
		t.Errorf("v1 fallback = %q", got)
	}
}

func TestStringIsStableAndNamesWhatItKnows(t *testing.T) {
	k8s := FromCgroupPath("/kubepods.slice/kubepods-pod00112233_4455_6677_8899_aabbccddeeff.slice/cri-containerd-abcdef0123456789abcdef0123456789abcdef01.scope")
	if got, want := k8s.String(), "k8s:00112233-4455-6677-8899-aabbccddeeff/abcdef012345"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if FromCgroupPath("").String() != "unknown" {
		t.Error("an empty path did not render as unknown")
	}
	if !FromCgroupPath("").Empty() {
		t.Error("an empty path was not reported as empty")
	}
	if k8s.Empty() {
		t.Error("a resolved kubernetes identity reported itself empty")
	}
}

// The cgroup path is retained so a consumer that disagrees with this parse can
// redo it. Dropping it would make every parsing decision here final.
func TestRawCgroupPathIsRetained(t *testing.T) {
	p := "/kubepods.slice/kubepods-pod00112233_4455_6677_8899_aabbccddeeff.slice"
	if got := FromCgroupPath(p); got.Cgroup != p {
		t.Errorf("Cgroup = %q, want %q", got.Cgroup, p)
	}
}
