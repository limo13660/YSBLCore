package constant

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewAdapterTypeStrings(t *testing.T) {
	require.Equal(t, "Naive", Naive.String())
	require.Equal(t, "Brook", Brook.String())
	require.Equal(t, "Juicity", Juicity.String())
}
