package juicity

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/stretchr/testify/require"
)

func TestStreamPacketConn(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	deadline := time.Now().Add(5 * time.Second)
	require.NoError(t, client.SetDeadline(deadline))
	require.NoError(t, server.SetDeadline(deadline))

	packetConn := NewStreamPacketConn(client, &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53})
	serverErr := make(chan error, 1)
	go func() {
		destination, err := socks5.ReadAddr0(server)
		if err != nil {
			serverErr <- err
			return
		}
		if destination.String() != "1.1.1.1:53" {
			serverErr <- io.ErrUnexpectedEOF
			return
		}
		var length uint16
		if err = binary.Read(server, binary.BigEndian, &length); err != nil {
			serverErr <- err
			return
		}
		payload := make([]byte, length)
		if _, err = io.ReadFull(server, payload); err != nil {
			serverErr <- err
			return
		}
		if string(payload) != "request" {
			serverErr <- io.ErrUnexpectedEOF
			return
		}
		responseAddr := socks5.ParseAddr("8.8.8.8:53")
		frame := append([]byte(nil), responseAddr...)
		frame = binary.BigEndian.AppendUint16(frame, uint16(len("response")))
		frame = append(frame, "response"...)
		_, err = server.Write(frame)
		serverErr <- err
	}()

	_, err := packetConn.WriteTo([]byte("request"), &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53})
	require.NoError(t, err)
	response := make([]byte, 64)
	n, source, err := packetConn.ReadFrom(response)
	require.NoError(t, err)
	require.Equal(t, "8.8.8.8:53", source.String())
	require.Equal(t, "response", string(response[:n]))
	require.NoError(t, <-serverErr)
}

func TestStreamPacketConnDiscardsTruncatedPayload(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	go func() {
		addr := socks5.ParseAddr("8.8.8.8:53")
		for _, payload := range []string{"too-long", "ok"} {
			frame := append([]byte(nil), addr...)
			frame = binary.BigEndian.AppendUint16(frame, uint16(len(payload)))
			frame = append(frame, payload...)
			_, _ = server.Write(frame)
		}
	}()

	packetConn := NewStreamPacketConn(client, nil)
	short := make([]byte, 3)
	n, _, err := packetConn.ReadFrom(short)
	require.NoError(t, err)
	require.Equal(t, "too", string(short[:n]))
	next := make([]byte, 8)
	n, _, err = packetConn.ReadFrom(next)
	require.NoError(t, err)
	require.Equal(t, "ok", string(next[:n]))
}
