package outbound

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/juicity"
	tuicCommon "github.com/metacubex/mihomo/transport/tuic/common"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

type Juicity struct {
	*Base
	option     *JuicityOption
	client     *juicity.Client
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	echConfig  *ech.Config
}

type JuicityOption struct {
	BasicOption
	Name                  string     `proxy:"name"`
	Server                string     `proxy:"server"`
	Port                  int        `proxy:"port"`
	IP                    string     `proxy:"ip,omitempty"`
	UUID                  string     `proxy:"uuid"`
	Password              string     `proxy:"password"`
	SNI                   string     `proxy:"sni,omitempty"`
	ALPN                  []string   `proxy:"alpn,omitempty"`
	UDP                   bool       `proxy:"udp,omitempty"`
	SkipCertVerify        bool       `proxy:"skip-cert-verify,omitempty"`
	AllowInsecure         bool       `proxy:"allow-insecure,omitempty"`
	NameCertVerify        string     `proxy:"name-cert-verify,omitempty"`
	Fingerprint           string     `proxy:"fingerprint,omitempty"`
	PinnedCertChainSHA256 string     `proxy:"pinned-certchain-sha256,omitempty"`
	Certificate           string     `proxy:"certificate,omitempty"`
	PrivateKey            string     `proxy:"private-key,omitempty"`
	CongestionController  string     `proxy:"congestion-controller,omitempty"`
	CongestionControl     string     `proxy:"congestion-control,omitempty"`
	CWND                  int        `proxy:"cwnd,omitempty"`
	BBRProfile            string     `proxy:"bbr-profile,omitempty"`
	ReceiveWindowConn     int        `proxy:"recv-window-conn,omitempty"`
	ReceiveWindow         int        `proxy:"recv-window,omitempty"`
	DisableMTUDiscovery   bool       `proxy:"disable-mtu-discovery,omitempty"`
	HeartbeatInterval     int        `proxy:"heartbeat-interval,omitempty"`
	ECHOpts               ECHOptions `proxy:"ech-opts,omitempty"`
}

func (j *Juicity) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	conn, err := j.client.DialContext(ctx, serializesSocksAddr(metadata))
	if err != nil {
		return nil, err
	}
	return NewConn(conn, j), nil
}

func (j *Juicity) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := j.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	packetConn, err := j.client.ListenPacket(ctx, serializesSocksAddr(metadata), metadata.UDPAddr())
	if err != nil {
		return nil, err
	}
	return NewPacketConn(packetConn, j), nil
}

func (j *Juicity) ProxyInfo() C.ProxyInfo {
	info := j.Base.ProxyInfo()
	info.DialerProxy = j.option.DialerProxy
	return info
}

func (j *Juicity) Close() error {
	return j.client.Close()
}

func (j *Juicity) dial(ctx context.Context) (*quic.Conn, error) {
	tlsConfig := j.tlsConfig.Clone()
	if err := j.echConfig.ClientHandle(ctx, tlsConfig); err != nil {
		return nil, err
	}
	_, quicConn, err := tuicCommon.DialQuic(ctx, j.addr, j.DialOptions(), j.dialer, tlsConfig, j.quicConfig, tuicCommon.DialQuicOption{})
	if err != nil {
		return nil, err
	}
	tuicCommon.SetCongestionController(quicConn, j.option.CongestionController, j.option.CWND, j.option.BBRProfile)
	return quicConn, nil
}

func NewJuicity(option JuicityOption) (*Juicity, error) {
	if option.Server == "" || option.Port <= 0 || option.Port > 0xffff {
		return nil, fmt.Errorf("juicity %s requires a valid server and port", option.Name)
	}
	id, err := uuid.FromString(option.UUID)
	if err != nil {
		return nil, fmt.Errorf("juicity %s invalid UUID: %w", option.Name, err)
	}
	if option.Password == "" {
		return nil, errors.New("juicity password is required")
	}

	serverName := option.SNI
	if serverName == "" {
		serverName = option.Server
	}
	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: option.SkipCertVerify || option.AllowInsecure,
			MinVersion:         tls.VersionTLS13,
		},
		Fingerprint:    option.Fingerprint,
		NameCertVerify: option.NameCertVerify,
		Certificate:    option.Certificate,
		PrivateKey:     option.PrivateKey,
	})
	if err != nil {
		return nil, err
	}
	if option.ALPN != nil {
		tlsConfig.NextProtos = option.ALPN
	} else {
		tlsConfig.NextProtos = []string{"h3"}
	}
	if option.PinnedCertChainSHA256 != "" {
		pinnedHash, decodeErr := decodeJuicityCertHash(option.PinnedCertChainSHA256)
		if decodeErr != nil {
			return nil, decodeErr
		}
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if !bytes.Equal(juicityCertChainHash(rawCerts), pinnedHash) {
				return errors.New("juicity: pinned certificate chain hash does not match")
			}
			return nil
		}
	}

	if option.CongestionController == "" {
		option.CongestionController = option.CongestionControl
		if option.CongestionController == "" {
			option.CongestionController = "bbr"
		}
	}
	if option.CWND == 0 {
		option.CWND = 10
	}
	if option.HeartbeatInterval <= 0 {
		option.HeartbeatInterval = 5000
	}
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     uint64(option.ReceiveWindowConn),
		MaxStreamReceiveWindow:         uint64(option.ReceiveWindowConn),
		InitialConnectionReceiveWindow: uint64(option.ReceiveWindow),
		MaxConnectionReceiveWindow:     uint64(option.ReceiveWindow),
		KeepAlivePeriod:                time.Duration(option.HeartbeatInterval) * time.Millisecond,
		DisablePathMTUDiscovery:        option.DisableMTUDiscovery,
		EnableDatagrams:                true,
		HandshakeIdleTimeout:           8 * time.Second,
	}
	if option.ReceiveWindowConn == 0 {
		quicConfig.InitialStreamReceiveWindow = 2 * 1024 * 1024
		quicConfig.MaxStreamReceiveWindow = 32 * 1024 * 1024
	}
	if option.ReceiveWindow == 0 {
		quicConfig.InitialConnectionReceiveWindow = 32 * 1024 * 1024
		quicConfig.MaxConnectionReceiveWindow = 64 * 1024 * 1024
	}
	echConfig, err := option.ECHOpts.Parse()
	if err != nil {
		return nil, err
	}

	addrHost := option.Server
	if option.IP != "" {
		addrHost = option.IP
	}
	addr := net.JoinHostPort(addrHost, strconv.Itoa(option.Port))
	outbound := &Juicity{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Juicity,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:     &option,
		tlsConfig:  tlsConfig,
		quicConfig: quicConfig,
		echConfig:  echConfig,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	var uuidBytes [16]byte
	copy(uuidBytes[:], id.Bytes())
	outbound.client = juicity.NewClient(uuidBytes, option.Password, outbound.dial)
	return outbound, nil
}

func decodeJuicityCertHash(value string) ([]byte, error) {
	if decoded, err := hex.DecodeString(value); err == nil && len(decoded) == sha256.Size {
		return decoded, nil
	}
	encodings := []*base64.Encoding{base64.URLEncoding, base64.RawURLEncoding, base64.StdEncoding, base64.RawStdEncoding}
	for _, encoding := range encodings {
		if decoded, err := encoding.DecodeString(value); err == nil {
			if len(decoded) != sha256.Size {
				return nil, fmt.Errorf("juicity: pinned certificate chain hash must be %d bytes", sha256.Size)
			}
			return decoded, nil
		}
	}
	return nil, errors.New("juicity: invalid pinned certificate chain hash")
}

func juicityCertChainHash(rawCerts [][]byte) []byte {
	var chainHash []byte
	for _, certificate := range rawCerts {
		certificateHash := sha256.Sum256(certificate)
		if chainHash == nil {
			chainHash = append([]byte(nil), certificateHash[:]...)
		} else {
			nextHash := sha256.Sum256(append(chainHash, certificateHash[:]...))
			chainHash = append(chainHash[:0], nextHash[:]...)
		}
	}
	return chainHash
}
