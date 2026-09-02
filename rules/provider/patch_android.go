//go:build android

package provider

import "time"

var suspended bool

type UpdatableProvider interface {
	UpdatedAt() time.Time
}

// Suspend allows the Android embedding layer to pause provider updates while
// the VPN service is being replaced.
func Suspend(value bool) {
	suspended = value
}
