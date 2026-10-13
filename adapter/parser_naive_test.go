//go:build with_naive

package adapter

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

func TestParseNaive(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":                 "naive-test",
		"type":                 "naive",
		"server":               "127.0.0.1",
		"port":                 443,
		"username":             "user",
		"password":             "secret",
		"udp-over-tcp":         true,
		"udp-over-tcp-version": 2,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = proxy.Close() })
	require.Equal(t, C.Naive, proxy.Type())
	require.True(t, proxy.SupportUDP())
	require.True(t, proxy.SupportUOT())
}
