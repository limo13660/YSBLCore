package juicity

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/tuic/types"

	"github.com/metacubex/quic-go"
)

const (
	protocolVersion  = 0
	authenticateType = 0
	networkTCP       = 1
	networkUDP       = 3
	protocolError    = quic.ApplicationErrorCode(0xfffffff0)
	// Juicity requires clients to open a new QUIC connection before the
	// stream limit is exhausted. quic-go does not expose the peer's dynamic
	// max-open-stream count, so use the protocol's recommended safe limit.
	maxStreamsPerConn = 30
)

type DialFunc func(ctx context.Context) (*quic.Conn, error)

type Client struct {
	uuid     [16]byte
	password string
	dialFn   DialFunc

	mu   sync.Mutex
	conn *quic.Conn
	// connections includes retired connections that may still carry active
	// streams. They are closed together with the client.
	connections map[*quic.Conn]struct{}
	streamCount int
	closed      bool
}

func NewClient(uuid [16]byte, password string, dialFn DialFunc) *Client {
	return &Client{uuid: uuid, password: password, dialFn: dialFn}
}

func (c *Client) DialContext(ctx context.Context, destination []byte) (net.Conn, error) {
	return c.openStream(ctx, networkTCP, destination)
}

func (c *Client) ListenPacket(ctx context.Context, destination []byte, remoteAddr net.Addr) (net.PacketConn, error) {
	conn, err := c.openStream(ctx, networkUDP, destination)
	if err != nil {
		return nil, err
	}
	return NewStreamPacketConn(conn, remoteAddr), nil
}

func (c *Client) openStream(ctx context.Context, network byte, destination []byte) (net.Conn, error) {
	if len(destination) == 0 {
		return nil, errors.New("juicity: invalid destination")
	}
	quicConn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		c.invalidate(quicConn, err)
		return nil, err
	}
	conn := types.NewQuicStreamConn(stream, quicConn.LocalAddr(), quicConn.RemoteAddr(), nil)
	header := make([]byte, 1+len(destination))
	header[0] = network
	copy(header[1:], destination)
	if _, err = conn.Write(header); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("juicity: write request header: %w", err)
	}
	return conn, nil
}

func (c *Client) getConn(ctx context.Context) (*quic.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	if c.conn != nil {
		if c.conn.Context().Err() != nil {
			delete(c.connections, c.conn)
			c.conn = nil
			c.streamCount = 0
		} else if c.streamCount < maxStreamsPerConn {
			c.streamCount++
			return c.conn, nil
		} else {
			// Keep the old connection alive for streams already opened on it.
			// New requests use a fresh connection instead.
			c.conn = nil
			c.streamCount = 0
		}
	}
	quicConn, err := c.dialFn(ctx)
	if err != nil {
		return nil, err
	}
	if err = c.authenticate(quicConn); err != nil {
		_ = quicConn.CloseWithError(protocolError, err.Error())
		return nil, err
	}
	c.conn = quicConn
	c.streamCount = 1
	if c.connections == nil {
		c.connections = make(map[*quic.Conn]struct{})
	}
	c.connections[quicConn] = struct{}{}
	return quicConn, nil
}

func (c *Client) authenticate(conn *quic.Conn) error {
	state := conn.ConnectionState()
	token, err := state.TLS.ExportKeyingMaterial(string(c.uuid[:]), []byte(c.password), 32)
	if err != nil {
		return fmt.Errorf("juicity: generate authentication token: %w", err)
	}
	stream, err := conn.OpenUniStream()
	if err != nil {
		return fmt.Errorf("juicity: open authentication stream: %w", err)
	}
	header := make([]byte, 2+len(c.uuid)+len(token))
	header[0] = protocolVersion
	header[1] = authenticateType
	copy(header[2:], c.uuid[:])
	copy(header[2+len(c.uuid):], token)
	if _, err = stream.Write(header); err != nil {
		stream.CancelWrite(0)
		return fmt.Errorf("juicity: write authentication: %w", err)
	}
	if err = stream.Close(); err != nil {
		return fmt.Errorf("juicity: close authentication stream: %w", err)
	}
	return nil
}

func (c *Client) invalidate(conn *quic.Conn, cause error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	description := ""
	if cause != nil {
		description = cause.Error()
	}
	if c.conn != conn {
		delete(c.connections, conn)
		_ = conn.CloseWithError(protocolError, description)
		return
	}
	c.conn = nil
	c.streamCount = 0
	delete(c.connections, conn)
	_ = conn.CloseWithError(protocolError, description)
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	var closeErr error
	for conn := range c.connections {
		if err := conn.CloseWithError(0, ""); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	c.connections = nil
	c.conn = nil
	c.streamCount = 0
	return closeErr
}

type streamPacketConn struct {
	conn       net.Conn
	remoteAddr net.Addr
	readMu     sync.Mutex
	writeMu    sync.Mutex
}

func NewStreamPacketConn(conn net.Conn, remoteAddr net.Addr) net.PacketConn {
	return &streamPacketConn{conn: conn, remoteAddr: remoteAddr}
}

func (c *streamPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	addr, err := socks5.ReadAddr0(c.conn)
	if err != nil {
		return 0, nil, fmt.Errorf("juicity: read UDP source: %w", err)
	}
	var lengthBytes [2]byte
	if _, err = io.ReadFull(c.conn, lengthBytes[:]); err != nil {
		return 0, nil, fmt.Errorf("juicity: read UDP length: %w", err)
	}
	length := int(lengthBytes[0])<<8 | int(lengthBytes[1])
	if length <= len(p) {
		n, readErr := io.ReadFull(c.conn, p[:length])
		return n, packetAddr(addr), readErr
	}
	n, readErr := io.ReadFull(c.conn, p)
	if readErr != nil {
		return n, packetAddr(addr), readErr
	}
	_, readErr = io.CopyN(io.Discard, c.conn, int64(length-len(p)))
	return n, packetAddr(addr), readErr
}

func (c *streamPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > 0xffff {
		return 0, fmt.Errorf("juicity: UDP payload is too large: %d", len(p))
	}
	destination := socks5.ParseAddrToSocksAddr(addr)
	if destination == nil {
		return 0, errors.New("juicity: invalid UDP destination")
	}
	frame := make([]byte, len(destination)+2+len(p))
	copy(frame, destination)
	frame[len(destination)] = byte(len(p) >> 8)
	frame[len(destination)+1] = byte(len(p))
	copy(frame[len(destination)+2:], p)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if _, err := c.conn.Write(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *streamPacketConn) Close() error                       { return c.conn.Close() }
func (c *streamPacketConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *streamPacketConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *streamPacketConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *streamPacketConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

type packetAddr socks5.Addr

func (a packetAddr) Network() string { return "udp" }
func (a packetAddr) String() string  { return socks5.Addr(a).String() }
