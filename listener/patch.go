package listener

// StopListener closes every listener owned by the core. It is the explicit
// lifecycle boundary used by embedding clients when the VPN is stopped.
func StopListener() {
	lifecycleMux.Lock()
	defer lifecycleMux.Unlock()

	socksMux.Lock()
	if socksListener != nil {
		_ = socksListener.Close()
		socksListener = nil
	}
	if socksUDPListener != nil {
		_ = socksUDPListener.Close()
		socksUDPListener = nil
	}
	socksMux.Unlock()

	httpMux.Lock()
	if httpListener != nil {
		_ = httpListener.Close()
		httpListener = nil
	}
	httpMux.Unlock()

	redirMux.Lock()
	if redirListener != nil {
		_ = redirListener.Close()
		redirListener = nil
	}
	if redirUDPListener != nil {
		_ = redirUDPListener.Close()
		redirUDPListener = nil
	}
	redirMux.Unlock()

	tproxyMux.Lock()
	if tproxyListener != nil {
		_ = tproxyListener.Close()
		tproxyListener = nil
	}
	if tproxyUDPListener != nil {
		_ = tproxyUDPListener.Close()
		tproxyUDPListener = nil
	}
	tproxyMux.Unlock()

	mixedMux.Lock()
	if mixedListener != nil {
		_ = mixedListener.Close()
		mixedListener = nil
	}
	if mixedUDPLister != nil {
		_ = mixedUDPLister.Close()
		mixedUDPLister = nil
	}
	mixedMux.Unlock()

	tunnelMux.Lock()
	for name, listener := range tunnelTCPListeners {
		_ = listener.Close()
		delete(tunnelTCPListeners, name)
	}
	for name, listener := range tunnelUDPListeners {
		_ = listener.Close()
		delete(tunnelUDPListeners, name)
	}
	tunnelMux.Unlock()

	inboundMux.Lock()
	for name, listener := range inboundListeners {
		_ = listener.Close()
		delete(inboundListeners, name)
	}
	inboundMux.Unlock()

	tunMux.Lock()
	closeTunListener()
	tunMux.Unlock()

	ssMux.Lock()
	if shadowSocksListener != nil {
		_ = shadowSocksListener.Close()
		shadowSocksListener = nil
	}
	ssMux.Unlock()

	vmessMux.Lock()
	if vmessListener != nil {
		_ = vmessListener.Close()
		vmessListener = nil
	}
	vmessMux.Unlock()

	tuicMux.Lock()
	if tuicListener != nil {
		_ = tuicListener.Close()
		tuicListener = nil
	}
	tuicMux.Unlock()
}
