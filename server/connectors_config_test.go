package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/connector/principal"
)

func TestConnectorsConfigIncludesPrincipal(t *testing.T) {
	config, ok := ConnectorsConfig["principal"]
	require.True(t, ok)
	require.IsType(t, new(principal.Config), config())
}
