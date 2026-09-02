package executor

// ProviderLoadedHook is called after a provider has finished initialization.
// It is optional so standalone Mihomo usage remains unchanged.
type ProviderLoadedHook func(providerName string)

var DefaultProviderLoadedHook ProviderLoadedHook
