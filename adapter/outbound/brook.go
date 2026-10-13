package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/brook"
)

type Brook struct {
	*Base
	option *BrookOption
}

type BrookOption struct {
	BasicOption
	Name       string `proxy:"name"`
	Server     string `proxy:"server"`
	Port       int    `proxy:"port"`
	Password   string `proxy:"password"`
	UDP        bool   `proxy:"udp,omitempty"`
	UDPOverTCP bool   `proxy:"udp-over-tcp,omitempty"`
}

func (b *Brook) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	conn, err := b.dialer.DialContext(ctx, "tcp", b.addr)
	if err != nil {
		return nil, fmt.Errorf("brook %s connect error: %w", b.addr, err)
	}
	defer func() { safeConnClose(conn, err) }()

	done := N.SetupContextForConn(ctx, conn)
	defer done(&err)
	conn, err = brook.NewStreamConn(conn, []byte(b.option.Password), serializesSocksAddr(metadata), "tcp")
	if err != nil {
		return nil, fmt.Errorf("brook %s handshake error: %w", b.addr, err)
	}
	return NewConn(conn, b), nil
}

func (b *Brook) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = b.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	if b.option.UDPOverTCP {
		conn, dialErr := b.dialer.DialContext(ctx, "tcp", b.addr)
		if dialErr != nil {
			return nil, fmt.Errorf("brook %s connect error: %w", b.addr, dialErr)
		}
		defer func() { safeConnClose(conn, err) }()
		done := N.SetupContextForConn(ctx, conn)
		defer done(&err)
		stream, streamErr := brook.NewStreamConn(conn, []byte(b.option.Password), serializesSocksAddr(metadata), "udp")
		if streamErr != nil {
			return nil, fmt.Errorf("brook %s UDP-over-TCP handshake error: %w", b.addr, streamErr)
		}
		return NewPacketConn(brook.NewBoundPacketConn(stream, metadata.UDPAddr()), b), nil
	}

	serverAddr, err := resolveUDPAddr(ctx, "udp", b.addr, b.prefer)
	if err != nil {
		return nil, err
	}
	packetConn, err := b.dialer.ListenPacket(ctx, "udp", "", serverAddr.AddrPort())
	if err != nil {
		return nil, fmt.Errorf("brook %s UDP connect error: %w", b.addr, err)
	}
	return NewPacketConn(brook.NewPacketConn(packetConn, serverAddr, []byte(b.option.Password)), b), nil
}

func (b *Brook) ProxyInfo() C.ProxyInfo {
	info := b.Base.ProxyInfo()
	info.DialerProxy = b.option.DialerProxy
	return info
}

// SupportUOT reports whether this Brook instance is configured to carry UDP
// through its TCP stream. Mihomo exposes this capability through the common
// ProxyAdapter contract and the proxy API response.
func (b *Brook) SupportUOT() bool {
	return b.option.UDPOverTCP
}

func NewBrook(option BrookOption) (*Brook, error) {
	if option.Server == "" || option.Port <= 0 || option.Port > 0xffff {
		return nil, fmt.Errorf("brook %s requires a valid server and port", option.Name)
	}
	if option.Password == "" {
		return nil, errors.New("brook password is required")
	}
	if option.UDPOverTCP {
		option.UDP = true
	}
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &Brook{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Brook,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}
