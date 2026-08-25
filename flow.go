package tunless

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/bojieli/tunless/workload"
)

type Proto uint8

const (
	TCP Proto = iota + 1
	UDP
)

func (p Proto) String() string {
	switch p {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	default:
		return "unknown"
	}
}

type ProcessInfo struct {
	PID       int32
	Path      string
	SigningID string
	CgroupID  uint64
	// Workload is what the process's cgroup says it belongs to: a Kubernetes
	// pod, a container, a systemd unit, or nothing.
	//
	// The socket layer knows this and a proxy protocol cannot express it. A
	// consumer that receives it can decide what a flow is from what produced
	// it; one that does not has to infer intent from byte counts, and arrives
	// at the answer after the flow it was deciding about has finished. It is
	// optional in exactly that sense: consumers that ignore it behave as they
	// did before it existed.
	Workload workload.Identity
}

type Packet struct {
	Payload []byte
	Dst     netip.AddrPort
}

func (p Packet) Validate() error {
	if !p.Dst.IsValid() || p.Dst.Port() == 0 {
		return errors.New("packet destination is invalid")
	}
	if p.Dst.Addr().Zone() != "" {
		return errors.New("packet destination cannot contain an IPv6 zone")
	}
	// The UDP length field is 16 bits and includes its eight-byte header. The
	// SOCKS encapsulation imposes a slightly smaller path-specific limit, which
	// the emitter checks before allocating a frame.
	if len(p.Payload) > 65527 {
		return errors.New("packet payload exceeds the UDP protocol limit")
	}
	return nil
}

// PacketPort is the datagram equivalent of net.Conn. ReadPacket returns a
// packet sent by the captured application; WritePacket sends one back.
type PacketPort interface {
	ReadPacket(context.Context) (Packet, error)
	WritePacket(context.Context, Packet) error
	Close() error
}

type Flow struct {
	Proto    Proto
	OrigDst  netip.AddrPort
	Hostname string
	Process  ProcessInfo
	Conn     net.Conn
	Packets  PacketPort
	// RedirectRecords is the opaque WFP connection-redirection record carried
	// by a Windows TCP flow. The SOCKS emitter applies it to the outbound socket
	// before connect so multiple WFP redirectors can cooperate without loops.
	RedirectRecords []byte
	// DatapathOwned marks metadata-only flows whose platform extension moves
	// bytes itself (notably NETransparentProxyProvider on macOS).
	DatapathOwned bool
}

const maxRedirectRecords = 1 << 20

func (f Flow) Validate() error {
	if !f.OrigDst.IsValid() {
		return errors.New("original destination is required")
	}
	if f.OrigDst.Port() == 0 {
		return errors.New("original destination port is required")
	}
	if f.OrigDst.Addr().Zone() != "" {
		return errors.New("original destination cannot contain an IPv6 zone")
	}
	if f.Process.PID < 0 {
		return errors.New("process PID cannot be negative")
	}
	if len(f.RedirectRecords) > maxRedirectRecords {
		return errors.New("redirect records exceed the one MiB limit")
	}
	switch f.Proto {
	case TCP:
		if f.Conn == nil && !f.DatapathOwned {
			return errors.New("TCP flow requires Conn")
		}
	case UDP:
		if f.Packets == nil && !f.DatapathOwned {
			return errors.New("UDP flow requires Packets")
		}
	default:
		return errors.New("unsupported protocol")
	}
	return nil
}

type Backend interface {
	Start(context.Context) (<-chan Flow, error)
	Close() error
}
