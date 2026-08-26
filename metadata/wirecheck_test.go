package metadata

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/bojieli/tunless"
	"github.com/bojieli/tunless/workload"
)

// The JSON is the contract, not the Go type.
//
// The consumer lives in another repository and decodes these bytes by hand, so
// renaming a field or moving one under a different object breaks it silently:
// the lookup keeps returning 200 and the consumer keeps reading zeroes. This
// pins the shape from the producing side. docs/FLOW_ATTRIBUTION.md describes
// the same thing for a reader.
func TestWireShapeForConsumers(t *testing.T) {
	e := entry{
		Process: tunless.ProcessInfo{
			PID: 991, Path: "/app/voice-gateway", CgroupID: 77,
			Workload: workload.FromCgroupPath(
				"/kubepods.slice/kubepods-pod1a2b3c4d_5e6f_7081_92a3_b4c5d6e7f809.slice/cri-containerd-9f8e7d6c5b4a39281706152433425160.scope"),
		},
		Expires: time.Now().Add(time.Minute),
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("wire: %s", b)
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	proc, ok := back["process"].(map[string]any)
	if !ok {
		t.Fatal("no process object")
	}
	for _, k := range []string{"PID", "Path", "CgroupID", "Workload"} {
		if _, ok := proc[k]; !ok {
			t.Errorf("process lacks %q", k)
		}
	}
	w, ok := proc["Workload"].(map[string]any)
	if !ok {
		t.Fatal("no Workload object")
	}
	for _, k := range []string{"kind", "pod_uid", "container_id", "cgroup"} {
		if _, ok := w[k]; !ok {
			t.Errorf("workload lacks %q: %v", k, w)
		}
	}
}
