package config

import "sync"

var (
	proxyNameList   []string
	proxyNameListMu sync.RWMutex
)

// GetProxyNameList returns a snapshot of names parsed from the latest config.
func GetProxyNameList() []string {
	proxyNameListMu.RLock()
	defer proxyNameListMu.RUnlock()
	return append([]string(nil), proxyNameList...)
}

func SetProxyNameList(list []string) {
	proxyNameListMu.Lock()
	defer proxyNameListMu.Unlock()
	proxyNameList = append([]string(nil), list...)
}
