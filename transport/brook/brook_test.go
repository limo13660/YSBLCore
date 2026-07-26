package brook

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/stretchr/testify/require"
)

func TestStreamConn(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	deadline := time.Now().Add(5 * time.Second)
	require.NoError(t, clientConn.SetDeadline(deadline))
	require.NoError(t, serverConn.SetDeadline(deadline))

	password := []byte("secret")
	destination := socks5.ParseAddr("example.com:443")
	serverErr := make(chan error, 1)
	go func() {
		clientNonce := make([]byte, nonceSize)
		if _, err := io.ReadFull(serverConn, clientNonce); err != nil {
			serverErr <- err
			return
		}
		clientAEAD, err := newAEAD(password, clientNonce)
		if err != nil {
			serverErr <- err
			return
		}
		initial, err := readTestFrame(serverConn, clientAEAD, clientNonce)
		if err != nil {
			serverErr <- err
			return
		}
		if binary.BigEndian.Uint32(initial[:4])%2 != 0 || string(initial[4:]) != string(destination) {
			serverErr <- io.ErrUnexpectedEOF
			return
		}

		serverNonce := make([]byte, nonceSize)
		if _, err = io.ReadFull(rand.Reader, serverNonce); err != nil {
			serverErr <- err
			return
		}
		if _, err = serverConn.Write(serverNonce); err != nil {
			serverErr <- err
			return
		}
		serverAEAD, err := newAEAD(password, serverNonce)
		if err != nil {
			serverErr <- err
			return
		}
		payload, err := readTestFrame(serverConn, clientAEAD, clientNonce)
		if err != nil {
			serverErr <- err
			return
		}
		if string(payload) != "request" {
			serverErr <- io.ErrUnexpectedEOF
			return
		}
		serverErr <- writeTestFrame(serverConn, serverAEAD, serverNonce, []byte("response"))
	}()

	conn, err := NewStreamConn(clientConn, password, destination, "tcp")
	require.NoError(t, err)
	_, err = conn.Write([]byte("request"))
	require.NoError(t, err)
	response := make([]byte, len("response"))
	_, err = io.ReadFull(conn, response)
	require.NoError(t, err)
	require.Equal(t, "response", string(response))
	require.NoError(t, <-serverErr)
}

func TestPacketConn(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	deadline := time.Now().Add(5 * time.Second)
	require.NoError(t, server.SetDeadline(deadline))
	require.NoError(t, client.SetDeadline(deadline))

	password := []byte("secret")
	conn := NewPacketConn(client, server.LocalAddr(), password)
	destination := &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53}
	_, err = conn.WriteTo([]byte("request"), destination)
	require.NoError(t, err)

	packet := make([]byte, maxUDPFrameSize)
	n, clientAddr, err := server.ReadFrom(packet)
	require.NoError(t, err)
	nonce := packet[:nonceSize]
	aead, err := newAEAD(password, nonce)
	require.NoError(t, err)
	plaintext, err := aead.Open(packet[:nonceSize], nonce, packet[nonceSize:n], nil)
	require.NoError(t, err)
	plaintext = plaintext[nonceSize:]
	require.NotZero(t, binary.BigEndian.Uint32(plaintext[:4]))
	addr := socks5.SplitAddr(plaintext[4:])
	require.Equal(t, destination.String(), addr.String())
	require.Equal(t, "request", string(plaintext[4+len(addr):]))

	serverNonce := make([]byte, nonceSize)
	_, err = io.ReadFull(rand.Reader, serverNonce)
	require.NoError(t, err)
	serverAEAD, err := newAEAD(password, serverNonce)
	require.NoError(t, err)
	source := socks5.ParseAddr("8.8.8.8:53")
	responsePlaintext := append(append([]byte(nil), source...), []byte("response")...)
	response := append([]byte(nil), serverNonce...)
	response = serverAEAD.Seal(response, serverNonce, responsePlaintext, nil)
	_, err = server.WriteTo(response, clientAddr)
	require.NoError(t, err)

	buffer := make([]byte, 64)
	n, responseAddr, err := conn.ReadFrom(buffer)
	require.NoError(t, err)
	require.Equal(t, "8.8.8.8:53", responseAddr.String())
	require.Equal(t, "response", string(buffer[:n]))
}

func readTestFrame(conn net.Conn, aead cipher.AEAD, nonce []byte) ([]byte, error) {
	header := make([]byte, 2+aes.BlockSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if _, err := aead.Open(header[:0], nonce, header, nil); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[:2]))
	nextNonce(nonce)
	payload := make([]byte, length+aes.BlockSize)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(payload[:0], nonce, payload, nil)
	nextNonce(nonce)
	return plaintext, err
}

func writeTestFrame(conn net.Conn, aead cipher.AEAD, nonce []byte, payload []byte) error {
	length := []byte{byte(len(payload) >> 8), byte(len(payload))}
	header := aead.Seal(nil, nonce, length, nil)
	nextNonce(nonce)
	ciphertext := aead.Seal(nil, nonce, payload, nil)
	nextNonce(nonce)
	_, err := conn.Write(append(header, ciphertext...))
	return err
}
