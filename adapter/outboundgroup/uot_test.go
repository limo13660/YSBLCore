package outboundgroup

import (
	"encoding/json"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/provider"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/stretchr/testify/require"
)

func newUOTGroupProvider(t *testing.T, proxies []C.Proxy) P.ProxyProvider {
	t.Helper()
	hc := provider.NewHealthCheck(proxies, testUrl, 1000, 0, true, nil)
	pd, err := provider.NewCompatibleProvider("uot-test", proxies, hc)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pd.Close()) })
	return pd
}

func newUOTProxy(t *testing.T) C.Proxy {
	t.Helper()
	p, err := outbound.NewBrook(outbound.BrookOption{
		BasicOption: outbound.BasicOption{},
		Name:        "brook-uot",
		Server:      "127.0.0.1",
		Port:        9000,
		Password:    "secret",
		UDPOverTCP:  true,
	})
	require.NoError(t, err)
	proxy := adapter.NewProxy(p)
	t.Cleanup(func() { require.NoError(t, proxy.Close()) })
	return proxy
}

func marshalGroupUOT(t *testing.T, group ProxyGroup) bool {
	t.Helper()
	encoded, err := json.Marshal(group)
	require.NoError(t, err)
	var state map[string]any
	require.NoError(t, json.Unmarshal(encoded, &state))
	uot, ok := state["uot"].(bool)
	require.True(t, ok, "group response must expose a boolean uot field: %s", encoded)
	return uot
}

func TestProxyGroupsExposeUOTCapability(t *testing.T) {
	uotProxy := newUOTProxy(t)
	fallback := adapter.NewProxy(outbound.NewDirect())
	providers := []P.ProxyProvider{newUOTGroupProvider(t, []C.Proxy{uotProxy})}
	option := GroupCommonOption{Name: "group", URL: testUrl}

	selector, err := NewSelector(option, SelectorOption{}, fallback, providers)
	require.NoError(t, err)
	urlTest, err := NewURLTest(option, URLTestOption{}, fallback, providers)
	require.NoError(t, err)
	fallbackGroup, err := NewFallback(option, FallbackOption{}, fallback, providers)
	require.NoError(t, err)
	loadBalance, err := NewLoadBalance(option, LoadBalanceOption{Strategy: "round-robin"}, fallback, providers)
	require.NoError(t, err)

	for _, group := range []ProxyGroup{selector, urlTest, fallbackGroup, loadBalance} {
		require.True(t, group.SupportUOT())
		require.True(t, marshalGroupUOT(t, group))
	}
}

func TestLoadBalanceUOTRequiresEveryCandidate(t *testing.T) {
	uotProxy := newUOTProxy(t)
	nonUOTProxy := adapter.NewProxy(outbound.NewDirect())
	providers := []P.ProxyProvider{newUOTGroupProvider(t, []C.Proxy{uotProxy, nonUOTProxy})}
	fallback := adapter.NewProxy(outbound.NewDirect())
	group, err := NewLoadBalance(GroupCommonOption{Name: "mixed", URL: testUrl}, LoadBalanceOption{Strategy: "round-robin"}, fallback, providers)
	require.NoError(t, err)
	require.False(t, group.SupportUOT())
	require.False(t, marshalGroupUOT(t, group))
}
