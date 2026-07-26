// Package brook implements the classic Brook client protocol.
//
// The wire format is compatible with github.com/txthinking/brook. Brook is
// licensed under GPL-3.0, the same license family as this project.
package brook

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/transport/socks5"

	"golang.org/x/crypto/hkdf"
)

const (
	nonceSize          = 12
	maxTCPFrameSize    = 2048
	maxUDPFrameSize    = 65507
	frameOverhead      = 2 + 2*aes.BlockSize
	packetOverhead     = nonceSize + aes.BlockSize
	packetTimestampLen = 4
)

var hkdfInfo = []byte("brook")

type StreamConn struct {
	net.Conn

	clientNonce []byte
	serverNonce []byte
	clientAEAD  cipher.AEAD
	serverAEAD  cipher.AEAD
	maxPayload  int

	readMu   sync.Mutex
	writeMu  sync.Mutex
	readData []byte
}

func NewStreamConn(conn net.Conn, password, destination []byte, network string) (*StreamConn, error) {
	maxFrameSize := maxTCPFrameSize
	if network == "udp" {
		maxFrameSize = maxUDPFrameSize
	} else if network != "tcp" {
		return nil, fmt.Errorf("brook: unsupported network %q", network)
	}
	if len(destination) == 0 || len(destination)+packetTimestampLen > maxFrameSize-frameOverhead {
		return nil, errors.New("brook: invalid destination")
	}

	clientNonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, clientNonce); err != nil {
		return nil, err
	}
	clientAEAD, err := newAEAD(password, clientNonce)
	if err != nil {
		return nil, err
	}
	if _, err = conn.Write(clientNonce); err != nil {
		return nil, err
	}

	c := &StreamConn{
		Conn:        conn,
		clientNonce: clientNonce,
		clientAEAD:  clientAEAD,
		maxPayload:  maxFrameSize - frameOverhead,
	}

	initial := make([]byte, packetTimestampLen+len(destination))
	timestamp := time.Now().Unix()
	if network == "tcp" && timestamp%2 != 0 {
		timestamp++
	}
	if network == "udp" && timestamp%2 != 1 {
		timestamp++
	}
	binary.BigEndian.PutUint32(initial, uint32(timestamp))
	copy(initial[packetTimestampLen:], destination)
	if err = c.writeFrame(initial); err != nil {
		return nil, err
	}

	serverNonce := make([]byte, nonceSize)
	if _, err = io.ReadFull(conn, serverNonce); err != nil {
		return nil, err
	}
	serverAEAD, err := newAEAD(password, serverNonce)
	if err != nil {
		return nil, err
	}
	c.serverNonce = serverNonce
	c.serverAEAD = serverAEAD
	return c, nil
}

func (c *StreamConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(c.readData) == 0 {
		frame, err := c.readFrame()
		if err != nil {
			return 0, err
		}
		c.readData = frame
	}
	n := copy(p, c.readData)
	c.readData = c.readData[n:]
	return n, nil
}

func (c *StreamConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > c.maxPayload {
			n = c.maxPayload
		}
		if err := c.writeFrame(p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (c *StreamConn) ReadPacket(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	frame, err := c.readFrame()
	if err != nil {
		return 0, err
	}
	return copy(p, frame), nil
}

func (c *StreamConn) WritePacket(p []byte) (int, error) {
	if len(p) > c.maxPayload {
		return 0, fmt.Errorf("brook: UDP payload is too large: %d > %d", len(p), c.maxPayload)
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.writeFrame(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *StreamConn) writeFrame(payload []byte) error {
	frame := make([]byte, frameOverhead+len(payload))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
	c.clientAEAD.Seal(frame[:0], c.clientNonce, frame[:2], nil)
	nextNonce(c.clientNonce)
	copy(frame[2+aes.BlockSize:], payload)
	c.clientAEAD.Seal(frame[:2+aes.BlockSize], c.clientNonce, frame[2+aes.BlockSize:2+aes.BlockSize+len(payload)], nil)
	nextNonce(c.clientNonce)
	_, err := c.Conn.Write(frame)
	return err
}

func (c *StreamConn) readFrame() ([]byte, error) {
	header := make([]byte, 2+aes.BlockSize)
	if _, err := io.ReadFull(c.Conn, header); err != nil {
		return nil, err
	}
	if _, err := c.serverAEAD.Open(header[:0], c.serverNonce, header, nil); err != nil {
		return nil, fmt.Errorf("brook: decrypt frame length: %w", err)
	}
	length := int(binary.BigEndian.Uint16(header[:2]))
	if length > c.maxPayload {
		return nil, fmt.Errorf("brook: invalid frame length %d", length)
	}
	nextNonce(c.serverNonce)
	ciphertext := make([]byte, length+aes.BlockSize)
	if _, err := io.ReadFull(c.Conn, ciphertext); err != nil {
		return nil, err
	}
	plaintext, err := c.serverAEAD.Open(ciphertext[:0], c.serverNonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("brook: decrypt frame payload: %w", err)
	}
	nextNonce(c.serverNonce)
	return plaintext, nil
}

type PacketConn struct {
	net.PacketConn
	serverAddr net.Addr
	password   []byte
	writeMu    sync.Mutex
}

func NewPacketConn(conn net.PacketConn, serverAddr net.Addr, password []byte) *PacketConn {
	return &PacketConn{PacketConn: conn, serverAddr: serverAddr, password: append([]byte(nil), password...)}
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	destination := socks5.ParseAddrToSocksAddr(addr)
	if destination == nil {
		return 0, errors.New("brook: invalid UDP destination")
	}
	plainLen := packetTimestampLen + len(destination) + len(p)
	if nonceSize+plainLen+aes.BlockSize > maxUDPFrameSize {
		return 0, fmt.Errorf("brook: UDP payload is too large: %d", len(p))
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	packet := make([]byte, nonceSize+plainLen+aes.BlockSize)
	nonce := packet[:nonceSize]
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return 0, err
	}
	aead, err := newAEAD(c.password, nonce)
	if err != nil {
		return 0, err
	}
	plain := packet[nonceSize : nonceSize+plainLen]
	binary.BigEndian.PutUint32(plain, uint32(time.Now().Unix()))
	copy(plain[packetTimestampLen:], destination)
	copy(plain[packetTimestampLen+len(destination):], p)
	aead.Seal(packet[:nonceSize], nonce, plain, nil)
	if _, err = c.PacketConn.WriteTo(packet, c.serverAddr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	packet := make([]byte, maxUDPFrameSize)
	n, _, err := c.PacketConn.ReadFrom(packet)
	if err != nil {
		return 0, nil, err
	}
	if n < packetOverhead {
		return 0, nil, errors.New("brook: UDP packet is too short")
	}
	nonce := packet[:nonceSize]
	aead, err := newAEAD(c.password, nonce)
	if err != nil {
		return 0, nil, err
	}
	plaintext, err := aead.Open(packet[:nonceSize], nonce, packet[nonceSize:n], nil)
	if err != nil {
		return 0, nil, fmt.Errorf("brook: decrypt UDP packet: %w", err)
	}
	plaintext = plaintext[nonceSize:]
	addr := socks5.SplitAddr(plaintext)
	if addr == nil {
		return 0, nil, errors.New("brook: invalid UDP source address")
	}
	payload := plaintext[len(addr):]
	return copy(p, payload), brookAddr(addr.String()), nil
}

type BoundPacketConn struct {
	conn       *StreamConn
	remoteAddr net.Addr
}

func NewBoundPacketConn(conn *StreamConn, remoteAddr net.Addr) *BoundPacketConn {
	return &BoundPacketConn{conn: conn, remoteAddr: remoteAddr}
}

func (c *BoundPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.conn.ReadPacket(p)
	return n, c.remoteAddr, err
}

func (c *BoundPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.conn.WritePacket(p)
}

func (c *BoundPacketConn) Close() error                       { return c.conn.Close() }
func (c *BoundPacketConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *BoundPacketConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *BoundPacketConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *BoundPacketConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

func newAEAD(password, nonce []byte) (cipher.AEAD, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, password, nonce, hkdfInfo), key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func nextNonce(nonce []byte) {
	value := binary.LittleEndian.Uint64(nonce[:8]) + 1
	binary.LittleEndian.PutUint64(nonce[:8], value)
}

type brookAddr string

func (a brookAddr) Network() string { return "udp" }
func (a brookAddr) String() string  { return string(a) }
