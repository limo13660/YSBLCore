package adapter

// UrlTestCheck receives the result of a proxy health check. Embedders can
// register it to stream latency changes without polling every proxy.
type UrlTestCheck func(url string, name string, delay uint16)

var UrlTestHook UrlTestCheck
