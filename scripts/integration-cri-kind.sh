#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

for command in kind docker go; do
	command -v "$command" >/dev/null 2>&1 || {
		echo "required CRI integration command is missing: $command" >&2
		exit 2
	}
done
singbox=${SINGBOX_BINARY:-sing-box}
command -v "$singbox" >/dev/null 2>&1 || [[ -x "$singbox" ]] || {
	echo "sing-box is required for the CRI integration test" >&2
	exit 2
}

cluster=${TUNLESS_KIND_CLUSTER:-tunless-cri-$$}
node=${cluster}-control-plane
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/tunless-cri-kind.XXXXXX")
stage=$work_dir/tunless-integration
mkdir -p "$stage"
created=false
cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	if [[ $created == true ]]; then
		docker exec "$node" pkill -f '/tunless-integration/sing-box' >/dev/null 2>&1 || true
		kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
	fi
	case "$work_dir" in
		"${TMPDIR:-/tmp}"/tunless-cri-kind.*) rm -rf -- "$work_dir" ;;
	esac
	exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if kind get clusters | grep -Fxq "$cluster"; then
	echo "refusing to reuse or delete existing kind cluster: $cluster" >&2
	exit 2
fi

GOOS=linux CGO_ENABLED=0 go build -trimpath \
	-ldflags '-s -w -X main.version=cri-integration' \
	-o "$stage/tunless" ./cmd/tunless
install -m 0755 "$singbox" scripts/tunless-cri.sh "$stage/"
install -m 0644 testdata/singbox-direct.json testdata/kind-pod.yaml "$stage/"
kind create cluster --name "$cluster" --wait 120s
created=true

docker cp "$stage" "$node:/"

runtime=(docker exec "$node" crictl)
kube=(docker exec "$node" kubectl --kubeconfig /etc/kubernetes/admin.conf)
"${kube[@]}" apply -f /tunless-integration/kind-pod.yaml >/dev/null
for _ in {1..120}; do
	if [[ $("${kube[@]}" get pod tunless-integration -o jsonpath='{.status.phase}' 2>/dev/null) == Running ]]; then break; fi
	sleep 0.5
done
container_ref=$("${kube[@]}" get pod tunless-integration -o jsonpath='{.status.containerStatuses[0].containerID}')
container_id=${container_ref#containerd://}
[[ "$container_id" =~ ^[0-9a-f]{64}$ ]] || {
	echo "Kubernetes did not expose a running containerd container: $container_ref" >&2
	exit 1
}

docker exec -d "$node" /tunless-integration/sing-box run \
	-c /tunless-integration/singbox-direct.json
for _ in {1..100}; do
	if docker exec "$node" ss -lnt | grep -q ':17898 '; then break; fi
	sleep 0.1
done
docker exec "$node" ss -lnt | grep -q ':17898 ' || {
	echo "sing-box did not start inside the kind node" >&2
	exit 1
}

docker exec -d \
	-e TUNLESS_UPSTREAM=127.0.0.1:17898 \
	-e TUNLESS_BINARY=/tunless-integration/tunless \
	"$node" sh -c \
	'exec /tunless-integration/tunless-cri.sh "$1" --log-level debug --status-listen 127.0.0.1:6060 >/tunless-integration/helper.log 2>&1' \
	sh "$container_id"
for _ in {1..100}; do
	if docker exec "$node" curl --fail --silent http://127.0.0.1:6060/healthz >/dev/null 2>&1; then break; fi
	sleep 0.1
done
docker exec "$node" curl --fail --silent http://127.0.0.1:6060/healthz >/dev/null || {
	docker exec "$node" tail -100 /tunless-integration/helper.log >&2 || true
	exit 1
}

probe='import http.client,ipaddress,socket,ssl,struct
host="icanhazip.com"; ip=socket.getaddrinfo(host,443,socket.AF_INET,socket.SOCK_STREAM)[0][4][0]
raw=socket.create_connection((ip,443),timeout=20); tls=ssl.create_default_context().wrap_socket(raw,server_hostname=host)
tls.sendall(b"GET / HTTP/1.1\r\nHost: icanhazip.com\r\nConnection: close\r\n\r\n")
resp=http.client.HTTPResponse(tls); resp.begin(); assert resp.status==200
wan=resp.read().decode().strip(); assert ipaddress.ip_address(wan).version==4
q=struct.pack("!HHHHHH",0x7541,0x0100,1,0,0,0)+b"\x07example\x03com\x00"+struct.pack("!HH",1,1)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(10); s.sendto(q,("9.9.9.9",53)); r,_=s.recvfrom(4096)
assert r[:2]==b"\x75\x41"; print(wan)'
exit_address=$("${runtime[@]}" exec --sync "$container_id" python -c "$probe")
[[ "$exit_address" =~ ^[0-9]+(\.[0-9]+){3}$ ]] || {
	echo "unexpected CRI WAN result: $exit_address" >&2
	exit 1
}

status=$(docker exec "$node" curl --fail --silent http://127.0.0.1:6060/v1/status)
python3 -c 'import json,sys
s=json.loads(sys.argv[1]); f=s["flows"]; c=s["capture"]
assert f["accepted_flows"] >= 2, f
assert c["links"] == 7 and len(c["maps"]) >= 7, c' "$status"

"${kube[@]}" delete pod tunless-integration --wait=true >/dev/null
for _ in {1..50}; do
	if ! docker exec "$node" pgrep -f '/tunless-integration/tunless-cri.sh' >/dev/null; then break; fi
	sleep 0.1
done
if docker exec "$node" pgrep -f '/tunless-integration/tunless-cri.sh' >/dev/null; then
	echo "CRI helper did not detach after container stop" >&2
	exit 1
fi

printf 'runtime=containerd-via-kind wan_exit=%s tcp_udp=pass lifecycle_detach=pass\n' "$exit_address"
