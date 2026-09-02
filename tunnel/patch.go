package tunnel

import (
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

// AllProxies returns a snapshot containing configured proxies and provider
// entries. Embedders can use it without reaching into tunnel internals.
func AllProxies() map[string]C.Proxy {
	configMux.RLock()
	defer configMux.RUnlock()
	result := make(map[string]C.Proxy, len(proxies))
	for name, proxy := range proxies {
		result[name] = proxy
	}
	for _, provider := range providers {
		for _, proxy := range provider.Proxies() {
			result[proxy.Name()] = proxy
		}
	}
	return result
}

// UpdateAllProxies is kept for source compatibility with embedders. Provider
// entries are merged by AllProxies on every read so online updates are visible
// immediately without maintaining a stale second map.
func UpdateAllProxies(newProxies map[string]C.Proxy, newProviders map[string]P.ProxyProvider) {
	configMux.Lock()
	proxies = newProxies
	providers = newProviders
	configMux.Unlock()
}
