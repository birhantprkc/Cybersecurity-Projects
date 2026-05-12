// ©AngelaMos | 2026
// fingerprint_handler_test.go

//go:build integration

package slowredirect_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/testutil"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/slowredirect"
)

const (
	fingerprintRoute = "/c/{id}/fingerprint"
	clientIP         = "203.0.113.45"
)

func newSlowredirectRepos(
	t *testing.T,
) (*token.Repository, *event.Repository) {
	t.Helper()
	db := sqlx.NewDb(testutil.NewTestDB(t), "pgx")
	return token.NewRepository(db), event.NewRepository(db)
}

func seedSlowredirectToken(
	t *testing.T,
	repo *token.Repository,
	id, destination string,
) *token.Token {
	t.Helper()
	metaJSON, _ := json.Marshal(map[string]string{
		"destination_url": destination,
	})
	tok := &token.Token{
		ID:           id,
		ManageID:     uuid.New().String(),
		Type:         token.TypeSlowRedirect,
		Memo:         "integration-fp",
		AlertChannel: token.ChannelWebhook,
		WebhookURL:   testutil.Ptr("https://example.com/hook"),
		CreatedIP:    clientIP,
		CreatedFP:    "abcdef0123456789",
		Metadata:     json.RawMessage(metaJSON),
		Enabled:      true,
	}
	require.NoError(t, repo.Insert(context.Background(), tok))
	return tok
}

func mountFingerprintRouter(h http.Handler) http.Handler {
	r := chi.NewRouter()
	r.Post(fingerprintRoute, h.ServeHTTP)
	return r
}

func TestFingerprintHandler_AttachesToRecentEvent(t *testing.T) {
	t.Parallel()
	tokRepo, evtRepo := newSlowredirectRepos(t)
	ctx := context.Background()

	tok := seedSlowredirectToken(t, tokRepo, "fpattach0001", "https://news.example.com")
	evt := &event.Event{
		TokenID:  tok.ID,
		SourceIP: clientIP,
		Extra:    json.RawMessage(`{"initial":"value"}`),
	}
	require.NoError(t, evtRepo.Insert(ctx, evt))

	handler := slowredirect.NewFingerprintHandler(evtRepo)
	router := mountFingerprintRouter(handler)

	fpBody := []byte(`{"screen":{"w":1920,"h":1080},"timezone":"America/Los_Angeles"}`)
	req := httptest.NewRequest(
		http.MethodPost,
		"/c/"+tok.ID+"/fingerprint",
		bytes.NewReader(fpBody),
	)
	req.Header.Set("CF-Connecting-IP", clientIP)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)

	got, err := evtRepo.GetByID(ctx, evt.ID)
	require.NoError(t, err)

	var merged map[string]any
	require.NoError(t, json.Unmarshal(got.Extra, &merged))
	require.Equal(t, "value", merged["initial"])
	require.Equal(t, "America/Los_Angeles", merged["timezone"])
	screen, ok := merged["screen"].(map[string]any)
	require.True(t, ok, "screen sub-object must round-trip as nested map")
	require.EqualValues(t, 1920, screen["w"])
	require.EqualValues(t, 1080, screen["h"])
}

func TestFingerprintHandler_NoMatchingEvent_Returns204(t *testing.T) {
	t.Parallel()
	tokRepo, evtRepo := newSlowredirectRepos(t)

	tok := seedSlowredirectToken(t, tokRepo, "fpnomatch001", "https://news.example.com")

	handler := slowredirect.NewFingerprintHandler(evtRepo)
	router := mountFingerprintRouter(handler)

	fpBody := []byte(`{"screen":{"w":800,"h":600}}`)
	req := httptest.NewRequest(
		http.MethodPost,
		"/c/"+tok.ID+"/fingerprint",
		bytes.NewReader(fpBody),
	)
	req.Header.Set("CF-Connecting-IP", clientIP)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(
		t,
		http.StatusNoContent,
		rr.Code,
		"no matching event must still return 204 — fingerprint is enrichment, not the trigger",
	)
}

func TestFingerprintHandler_InvalidJSON_Returns204AndDoesNotTouchEvent(t *testing.T) {
	t.Parallel()
	tokRepo, evtRepo := newSlowredirectRepos(t)
	ctx := context.Background()

	tok := seedSlowredirectToken(t, tokRepo, "fpinvjson001", "https://news.example.com")
	evt := &event.Event{
		TokenID:  tok.ID,
		SourceIP: clientIP,
		Extra:    json.RawMessage(`{"initial":"value"}`),
	}
	require.NoError(t, evtRepo.Insert(ctx, evt))

	handler := slowredirect.NewFingerprintHandler(evtRepo)
	router := mountFingerprintRouter(handler)

	req := httptest.NewRequest(
		http.MethodPost,
		"/c/"+tok.ID+"/fingerprint",
		bytes.NewReader([]byte("not-json-at-all")),
	)
	req.Header.Set("CF-Connecting-IP", clientIP)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)

	got, err := evtRepo.GetByID(ctx, evt.ID)
	require.NoError(t, err)

	var stored map[string]any
	require.NoError(t, json.Unmarshal(got.Extra, &stored))
	require.Equal(
		t,
		"value",
		stored["initial"],
		"invalid JSON must not corrupt the stored Extra JSONB",
	)
	_, hasInvalid := stored["not-json"]
	require.False(t, hasInvalid)
}
