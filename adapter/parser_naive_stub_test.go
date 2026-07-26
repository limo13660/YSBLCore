//go:build !with_naive

package adapter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseNaiveWithoutBuildTag(t *testing.T) {
	_, err := ParseProxy(map[string]any{
		"name":     "naive-test",
		"type":     "naive",
		"server":   "127.0.0.1",
		"port":     443,
		"username": "user",
		"password": "secret",
	})
	require.ErrorContains(t, err, "-tags with_naive")
}
