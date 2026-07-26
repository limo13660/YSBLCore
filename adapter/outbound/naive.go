//go:build with_naive

package outbound

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
	"github.com/miekg/dns"
	"github.com/sagernet/cronet-go"
	SM "github.com/sagernet/sing/common/metadata"
	SN "github.com/sagernet/sing/common/network"
)

type Naive struct {
	*Base
	option    *NaiveOption
	client    *cronet.NaiveClient
	startOnce sync.Once
	startErr  error
}

func (n *Naive) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if err := n.start(); err != nil {
		return nil, err
	}
	destination := SM.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort)
	conn, err := n.client.DialEarly(ctx, destination)
	if err != nil {
		return nil, err
	}
	return NewConn(conn, n), nil
}

func (n *Naive) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if !n.option.UDPOverTCP && !n.option.UDP {
		return nil, C.ErrNotSupport
	}
	if err := n.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	if err := n.start(); err != nil {
		return nil, err
	}
	version := uint8(n.option.UDPOverTCPVersion)
	requestDestination := uot.RequestDestination(version)
	conn, err := n.client.DialEarly(ctx, SM.ParseSocksaddrHostPort(requestDestination.AddrString(), requestDestination.Port))
	if err != nil {
		return nil, err
	}
	destination := M.SocksaddrFromNet(metadata.UDPAddr())
	return NewPacketConn(N.NewThreadSafePacketConn(uot.NewLazyConn(conn, uot.Request{Destination: destination})), n), nil
}

func (n *Naive) SupportUOT() bool {
	return n.option.UDPOverTCP || n.option.UDP
}

func (n *Naive) ProxyInfo() C.ProxyInfo {
	info := n.Base.ProxyInfo()
	info.DialerProxy = n.option.DialerProxy
	return info
}

func (n *Naive) Close() error {
	return n.client.Close()
}

func (n *Naive) start() error {
	n.startOnce.Do(func() {
		n.startErr = n.client.Start()
	})
	return n.startErr
}

func NewNaive(option NaiveOption) (*Naive, error) {
	if option.Server == "" || option.Port <= 0 || option.Port > 0xffff {
		return nil, fmt.Errorf("naive %s requires a valid server and port", option.Name)
	}
	if option.QUIC && option.InsecureConcurrency > 1 {
		return nil, errors.New("naive insecure-concurrency greater than 1 is incompatible with QUIC")
	}
	switch option.UDPOverTCPVersion {
	case 0:
		option.UDPOverTCPVersion = uot.Version
	case uot.Version, uot.LegacyVersion:
	default:
		return nil, fmt.Errorf("naive %s unknown UDP-over-TCP version: %d", option.Name, option.UDPOverTCPVersion)
	}
	if option.UDP {
		option.UDPOverTCP = true
	}

	congestionControl, err := parseNaiveCongestionControl(option.QUICCongestionController)
	if err != nil {
		return nil, err
	}
	trustedRoots, err := loadNaiveCertificate(option.Certificate)
	if err != nil {
		return nil, err
	}
	var echConfigList []byte
	if option.ECHOpts.Config != "" {
		echConfigList, err = base64.StdEncoding.DecodeString(option.ECHOpts.Config)
		if err != nil {
			return nil, fmt.Errorf("naive: decode ECH config: %w", err)
		}
	}

	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &Naive{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Naive,
			ProviderName: option.ProviderName,
			UDP:          option.UDPOverTCP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	client, err := cronet.NewNaiveClient(cronet.NaiveClientOptions{
		Context:                  context.Background(),
		ServerAddress:            SM.ParseSocksaddrHostPort(option.Server, uint16(option.Port)),
		ServerName:               option.SNI,
		Username:                 option.Username,
		Password:                 option.Password,
		InsecureConcurrency:      option.InsecureConcurrency,
		ReceiveWindow:            option.ReceiveWindow,
		ExtraHeaders:             option.ExtraHeaders,
		TrustedRootCertificates:  trustedRoots,
		DNSResolver:              naiveDNSResolver,
		Dialer:                   &naiveDialer{dialer: outbound.dialer, prefer: outbound.prefer},
		ECHEnabled:               option.ECHOpts.Enable,
		ECHConfigList:            echConfigList,
		ECHQueryServerName:       option.ECHOpts.QueryServerName,
		QUIC:                     option.QUIC,
		QUICCongestionControl:    congestionControl,
		QUICSessionReceiveWindow: option.QUICSessionReceiveWindow,
	})
	if err != nil {
		return nil, err
	}
	outbound.client = client
	return outbound, nil
}

func parseNaiveCongestionControl(value string) (cronet.QUICCongestionControl, error) {
	switch strings.ToLower(value) {
	case "":
		return cronet.QUICCongestionControlDefault, nil
	case "bbr":
		return cronet.QUICCongestionControlBBR, nil
	case "bbr2", "bbrv2":
		return cronet.QUICCongestionControlBBRv2, nil
	case "cubic":
		return cronet.QUICCongestionControlCubic, nil
	case "reno", "new_reno":
		return cronet.QUICCongestionControlReno, nil
	default:
		return "", fmt.Errorf("naive: unknown QUIC congestion controller %q", value)
	}
}

func loadNaiveCertificate(value string) (string, error) {
	if value == "" || strings.Contains(value, "-----BEGIN CERTIFICATE-----") {
		return value, nil
	}
	path := C.Path.Resolve(value)
	if !C.Path.IsSafePath(path) {
		return "", C.Path.ErrNotSafePath(path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("naive: read certificate: %w", err)
	}
	return string(content), nil
}

func naiveDNSResolver(ctx context.Context, request *dns.Msg) *dns.Msg {
	dnsResolver := resolver.ProxyServerHostResolver
	if dnsResolver == nil {
		dnsResolver = resolver.DefaultResolver
	}
	if dnsResolver == nil {
		dnsResolver = resolver.SystemResolver
	}
	if dnsResolver != nil {
		response, err := dnsResolver.ExchangeContext(ctx, request)
		if err == nil {
			return response
		}
	}
	response := new(dns.Msg)
	response.SetRcode(request, dns.RcodeServerFailure)
	return response
}

type naiveDialer struct {
	dialer C.Dialer
	prefer C.DNSPrefer
}

var _ SN.Dialer = (*naiveDialer)(nil)

func (d *naiveDialer) DialContext(ctx context.Context, network string, destination SM.Socksaddr) (net.Conn, error) {
	if SN.NetworkName(network) != SN.NetworkUDP {
		return d.dialer.DialContext(ctx, network, destination.String())
	}
	remoteAddr, err := resolveUDPAddr(ctx, "udp", destination.String(), d.prefer)
	if err != nil {
		return nil, err
	}
	packetConn, err := d.dialer.ListenPacket(ctx, "udp", "", remoteAddr.AddrPort())
	if err != nil {
		return nil, err
	}
	return &boundNaivePacketConn{PacketConn: packetConn, remoteAddr: remoteAddr}, nil
}

func (d *naiveDialer) ListenPacket(ctx context.Context, destination SM.Socksaddr) (net.PacketConn, error) {
	remoteAddr, err := resolveUDPAddr(ctx, "udp", destination.String(), d.prefer)
	if err != nil {
		return nil, err
	}
	return d.dialer.ListenPacket(ctx, "udp", "", remoteAddr.AddrPort())
}

type boundNaivePacketConn struct {
	net.PacketConn
	remoteAddr net.Addr
}

func (c *boundNaivePacketConn) Read(p []byte) (int, error) {
	n, _, err := c.PacketConn.ReadFrom(p)
	return n, err
}

func (c *boundNaivePacketConn) Write(p []byte) (int, error) {
	return c.PacketConn.WriteTo(p, c.remoteAddr)
}

func (c *boundNaivePacketConn) RemoteAddr() net.Addr { return c.remoteAddr }

var _ net.Conn = (*boundNaivePacketConn)(nil)
