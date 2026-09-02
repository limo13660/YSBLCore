//go:build android

package http

import "net"

// Listener exposes the underlying listener to the Android embedding layer.
func (l *Listener) Listener() net.Listener {
	return l.listener
}
