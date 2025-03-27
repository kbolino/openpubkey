package discover

import (
	"context"
	"testing"
	"time"

	"github.com/openpubkey/openpubkey/discover/mocks"
	"github.com/stretchr/testify/require"
)

func TestJwksCache(t *testing.T) {
	ctx := context.Background()
	startTime := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
	mockClock := mocks.NewMockClock(startTime)
	mockFunc := mocks.NewMockJwksFetchWithExpiresFunc()
	cache := NewJwksCacheWithClock(mockFunc.Call, mockClock.Now)

	// get same value twice from an initially empty cache
	mockFunc.Return([]byte("foo_jwks"), mockClock.Now().Add(5*time.Second), nil)
	for i := range 2 {
		jwks, err := cache.GetJwksByIssuer(ctx, "foo_issuer")
		require.NoError(t, err, "attempt %d", i)
		require.Equal(t, []byte("foo_jwks"), jwks, "attempt %d", i)
	}
	calls := mockFunc.Calls()
	require.Len(t, calls, 1)
	require.Equal(t, "foo_issuer", calls[0].ArgIssuer)

	// test expiration
	mockClock.Add(10 * time.Second)
	mockFunc.Reset()
	mockFunc.Return([]byte("foo_jwks2"), mockClock.Now().Add(5*time.Second), nil)
	jwks, err := cache.GetJwksByIssuer(ctx, "foo_issuer")
	require.NoError(t, err)
	require.Equal(t, []byte("foo_jwks2"), jwks)
	calls = mockFunc.Calls()
	require.Len(t, calls, 1)
	require.Equal(t, "foo_issuer", calls[0].ArgIssuer)

	// TODO: test multiple issuers, test errors, test concurrency
}
