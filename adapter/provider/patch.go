package provider

// GetSubscriptionInfo exposes the parsed subscription metadata to embedders.
func (pp *proxySetProvider) GetSubscriptionInfo() *SubscriptionInfo {
	return pp.subscriptionInfo
}
