package tunless

import (
	"context"
	"errors"
	"net"
	"net/netip"
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
}

type Packet struct {
	Payload []byte
	Dst     netip.AddrPort
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

func (f Flow) Validate() error {
	if !f.OrigDst.IsValid() {
		return errors.New("original destination is required")
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
