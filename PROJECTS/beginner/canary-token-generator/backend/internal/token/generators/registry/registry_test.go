// ©AngelaMos | 2026
// registry_test.go

package registry_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/registry"
)

const testBaseURL = "https://canary.example.com"

func TestBuild_RegistersWebbug(t *testing.T) {
	reg := registry.Build(registry.Config{BaseURL: testBaseURL})
	g, ok := reg[token.TypeWebbug]
	require.True(t, ok, "expected webbug generator registered")
	require.NotNil(t, g)
	require.Equal(t, token.TypeWebbug, g.Type())
}

func TestBuild_RegistersSlowRedirect(t *testing.T) {
	reg := registry.Build(registry.Config{BaseURL: testBaseURL})
	g, ok := reg[token.TypeSlowRedirect]
	require.True(t, ok, "expected slowredirect generator registered")
	require.NotNil(t, g)
	require.Equal(t, token.TypeSlowRedirect, g.Type())
}

func TestBuild_UnknownTypeReturnsZeroValue(t *testing.T) {
	reg := registry.Build(registry.Config{BaseURL: testBaseURL})
	g, ok := reg["nonexistent-type"]
	require.False(t, ok, "unknown type must not be present")
	require.Nil(t, g, "map zero value for missing key must be nil interface")
}

func TestBuild_PendingTypesNotYetRegistered(t *testing.T) {
	reg := registry.Build(registry.Config{BaseURL: testBaseURL})
	pending := []token.Type{
		token.TypeDocx,
		token.TypePDF,
		token.TypeKubeconfig,
		token.TypeEnvfile,
		token.TypeMySQL,
	}
	for _, tt := range pending {
		_, ok := reg[tt]
		require.False(
			t,
			ok,
			"type %q is not yet registered (subsequent phases will add it); registry must not claim it",
			tt,
		)
	}
}

func TestBuild_OnlyExpectedTypesPresentInPhase3(t *testing.T) {
	reg := registry.Build(registry.Config{BaseURL: testBaseURL})
	require.Len(
		t,
		reg,
		2,
		"Phase 3 registers exactly two generators (webbug, slowredirect); other phases append",
	)
}
