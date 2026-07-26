package adapter

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

func TestParseBrook(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":         "brook-test",
		"type":         "brook",
		"server":       "127.0.0.1",
		"port":         9000,
		"password":     "secret",
		"udp-over-tcp": true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = proxy.Close() })
	require.Equal(t, C.Brook, proxy.Type())
	require.True(t, proxy.SupportUDP())
}

func TestParseJuicity(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":               "juicity-test",
		"type":               "juicity",
		"server":             "127.0.0.1",
		"port":               9001,
		"uuid":               "00000000-0000-0000-0000-000000000001",
		"password":           "secret",
		"udp":                true,
		"allow-insecure":     true,
		"congestion-control": "cubic",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = proxy.Close() })
	require.Equal(t, C.Juicity, proxy.Type())
	require.True(t, proxy.SupportUDP())
}
