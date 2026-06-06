package principal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/connector"
)

func TestOpenValidatesRequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr string
	}{
		{
			name: "login URL",
			config: Config{
				ExchangeURL:          "https://principal.example/exchange",
				ApplicationBindingID: "binding-1",
				ClientID:             "dex",
				ClientSecret:         "secret",
			},
			wantErr: "loginURL is required",
		},
		{
			name: "application binding",
			config: Config{
				LoginURL:     "https://principal.example/login",
				ExchangeURL:  "https://principal.example/exchange",
				ClientID:     "dex",
				ClientSecret: "secret",
			},
			wantErr: "applicationBindingID is required",
		},
		{
			name: "client secret",
			config: Config{
				LoginURL:             "https://principal.example/login",
				ExchangeURL:          "https://principal.example/exchange",
				ApplicationBindingID: "binding-1",
				ClientID:             "dex",
			},
			wantErr: "clientSecret is required",
		},
		{
			name: "URL user info",
			config: Config{
				LoginURL:             "https://user:pass@principal.example/login",
				ExchangeURL:          "https://principal.example/exchange",
				ApplicationBindingID: "binding-1",
				ClientID:             "dex",
				ClientSecret:         "secret",
			},
			wantErr: "loginURL must not include user info",
		},
		{
			name: "timeout",
			config: Config{
				LoginURL:             "https://principal.example/login",
				ExchangeURL:          "https://principal.example/exchange",
				ApplicationBindingID: "binding-1",
				ClientID:             "dex",
				ClientSecret:         "secret",
				Timeout:              "0s",
			},
			wantErr: "timeout must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.config.Open("principal-app", testLogger())
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestLoginURLBuildsPrincipalRedirect(t *testing.T) {
	conn := newTestConnector(t, Config{
		LoginURL:             "https://principal.example/login?existing=1",
		ExchangeURL:          "https://principal.example/exchange",
		ApplicationBindingID: "binding-1",
		ClientID:             "dex-client",
		ClientSecret:         "secret",
	})

	loginURL, connData, err := conn.LoginURL(
		connector.Scopes{Groups: true, OfflineAccess: true},
		"https://dex.example/callback",
		"dex-state",
	)
	require.NoError(t, err)

	u, err := url.Parse(loginURL)
	require.NoError(t, err)
	require.Equal(t, "https://principal.example/login", u.Scheme+"://"+u.Host+u.Path)

	q := u.Query()
	require.Equal(t, "1", q.Get("existing"))
	require.Equal(t, "principal-app", q.Get("connector_id"))
	require.Equal(t, "binding-1", q.Get("application_binding_id"))
	require.Equal(t, "https://dex.example/callback", q.Get("callback_url"))
	require.Equal(t, "dex-state", q.Get("state"))
	require.Equal(t, "true", q.Get("scope_groups"))
	require.Equal(t, "true", q.Get("scope_offline_access"))
	require.NotEmpty(t, q.Get("nonce"))

	require.NotContains(t, string(connData), "secret")

	var data loginData
	require.NoError(t, json.Unmarshal(connData, &data))
	require.Equal(t, "principal-app", data.ConnectorID)
	require.Equal(t, "binding-1", data.ApplicationBindingID)
	require.Equal(t, "https://dex.example/callback", data.CallbackURL)
	require.Equal(t, "dex-state", data.State)
	require.Equal(t, q.Get("nonce"), data.Nonce)
}

func TestLoginURLRejectsCallbackMismatch(t *testing.T) {
	conn := newTestConnector(t, Config{
		LoginURL:             "https://principal.example/login",
		ExchangeURL:          "https://principal.example/exchange",
		ApplicationBindingID: "binding-1",
		RedirectURI:          "https://dex.example/callback",
		ClientID:             "dex-client",
		ClientSecret:         "secret",
	})

	_, _, err := conn.LoginURL(connector.Scopes{}, "https://dex.example/other", "dex-state")
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected callback URL")
}

func TestHandleCallbackExchangesCode(t *testing.T) {
	var got exchangeRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/exchange", r.URL.Path)
		user, password, ok := r.BasicAuth()
		require.True(t, ok)
		require.Equal(t, "dex-client", user)
		require.Equal(t, "secret", password)

		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		require.NoError(t, json.NewEncoder(w).Encode(identityResponse{
			UserID:            "user-1",
			Username:          "user",
			PreferredUsername: "User",
			Email:             "user@example.com",
			EmailVerified:     true,
			Groups:            []string{"team-a", "team-b"},
			RefreshHandle:     "refresh-1",
		}))
	}))
	defer srv.Close()

	conn := newTestConnector(t, Config{
		LoginURL:             srv.URL + "/login",
		ExchangeURL:          srv.URL + "/exchange",
		RefreshURL:           srv.URL + "/refresh",
		ApplicationBindingID: "binding-1",
		ClientID:             "dex-client",
		ClientSecret:         "secret",
	})

	scopes := connector.Scopes{Groups: true, OfflineAccess: true}
	_, connData, err := conn.LoginURL(scopes, "https://dex.example/callback", "dex-state")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "https://dex.example/callback?state=dex-state&code=code-1", nil)
	identity, err := conn.HandleCallback(scopes, connData, req)
	require.NoError(t, err)

	require.Equal(t, "principal-app", got.ConnectorID)
	require.Equal(t, "binding-1", got.ApplicationBindingID)
	require.Equal(t, "https://dex.example/callback", got.CallbackURL)
	require.Equal(t, "dex-state", got.State)
	require.Equal(t, "code-1", got.Code)
	require.True(t, got.Scopes.Groups)
	require.True(t, got.Scopes.OfflineAccess)
	require.NotEmpty(t, got.Nonce)

	require.Equal(t, "user-1", identity.UserID)
	require.Equal(t, "user", identity.Username)
	require.Equal(t, "User", identity.PreferredUsername)
	require.Equal(t, "user@example.com", identity.Email)
	require.True(t, identity.EmailVerified)
	require.Equal(t, []string{"team-a", "team-b"}, identity.Groups)

	var refresh refreshData
	require.NoError(t, json.Unmarshal(identity.ConnectorData, &refresh))
	require.Equal(t, "refresh-1", refresh.RefreshHandle)
}

func TestHandleCallbackRejectsStateMismatch(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	conn := newTestConnector(t, Config{
		LoginURL:             srv.URL + "/login",
		ExchangeURL:          srv.URL + "/exchange",
		ApplicationBindingID: "binding-1",
		ClientID:             "dex-client",
		ClientSecret:         "secret",
	})
	_, connData, err := conn.LoginURL(connector.Scopes{}, "https://dex.example/callback", "dex-state")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "https://dex.example/callback?state=other-state&code=code-1", nil)
	_, err = conn.HandleCallback(connector.Scopes{}, connData, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "state mismatch")
	require.False(t, called)
}

func TestHandleCallbackMapsForbiddenToRequiredGroupsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		require.NoError(t, json.NewEncoder(w).Encode(errorResponse{
			UserID: "user-1",
			Groups: []string{
				"team-a",
				"team-b",
			},
		}))
	}))
	defer srv.Close()

	conn := newTestConnector(t, Config{
		LoginURL:             srv.URL + "/login",
		ExchangeURL:          srv.URL + "/exchange",
		ApplicationBindingID: "binding-1",
		ClientID:             "dex-client",
		ClientSecret:         "secret",
	})
	_, connData, err := conn.LoginURL(connector.Scopes{Groups: true}, "https://dex.example/callback", "dex-state")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "https://dex.example/callback?state=dex-state&code=code-1", nil)
	_, err = conn.HandleCallback(connector.Scopes{Groups: true}, connData, req)
	require.Error(t, err)

	var groupsErr *connector.UserNotInRequiredGroupsError
	require.True(t, errors.As(err, &groupsErr))
	require.Equal(t, "user-1", groupsErr.UserID)
	require.Equal(t, []string{"team-a", "team-b"}, groupsErr.Groups)
}

func TestHandleCallbackRequiresRefreshURLForOfflineAccess(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	conn := newTestConnector(t, Config{
		LoginURL:             srv.URL + "/login",
		ExchangeURL:          srv.URL + "/exchange",
		ApplicationBindingID: "binding-1",
		ClientID:             "dex-client",
		ClientSecret:         "secret",
	})
	_, connData, err := conn.LoginURL(connector.Scopes{OfflineAccess: true}, "https://dex.example/callback", "dex-state")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "https://dex.example/callback?state=dex-state&code=code-1", nil)
	_, err = conn.HandleCallback(connector.Scopes{OfflineAccess: true}, connData, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "refreshURL is required")
	require.False(t, called)
}

func TestHandleCallbackRequiresRefreshHandleForOfflineAccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(identityResponse{
			UserID: "user-1",
		}))
	}))
	defer srv.Close()

	conn := newTestConnector(t, Config{
		LoginURL:             srv.URL + "/login",
		ExchangeURL:          srv.URL + "/exchange",
		RefreshURL:           srv.URL + "/refresh",
		ApplicationBindingID: "binding-1",
		ClientID:             "dex-client",
		ClientSecret:         "secret",
	})
	_, connData, err := conn.LoginURL(connector.Scopes{OfflineAccess: true}, "https://dex.example/callback", "dex-state")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "https://dex.example/callback?state=dex-state&code=code-1", nil)
	_, err = conn.HandleCallback(connector.Scopes{OfflineAccess: true}, connData, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing refreshHandle")
}

func TestRefreshExchangesRefreshHandle(t *testing.T) {
	var got refreshRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/refresh", r.URL.Path)

		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		require.NoError(t, json.NewEncoder(w).Encode(identityResponse{
			UserID:        "user-1",
			Username:      "updated-user",
			Email:         "updated@example.com",
			EmailVerified: true,
			Groups:        []string{"team-c"},
			RefreshHandle: "refresh-2",
		}))
	}))
	defer srv.Close()

	conn := newTestConnector(t, Config{
		LoginURL:             srv.URL + "/login",
		ExchangeURL:          srv.URL + "/exchange",
		RefreshURL:           srv.URL + "/refresh",
		ApplicationBindingID: "binding-1",
		ClientID:             "dex-client",
		ClientSecret:         "secret",
	})
	connData, err := encodeRefreshData("refresh-1")
	require.NoError(t, err)

	identity, err := conn.Refresh(
		context.Background(),
		connector.Scopes{Groups: true, OfflineAccess: true},
		connector.Identity{UserID: "user-1", ConnectorData: connData},
	)
	require.NoError(t, err)

	require.Equal(t, "principal-app", got.ConnectorID)
	require.Equal(t, "binding-1", got.ApplicationBindingID)
	require.Equal(t, "refresh-1", got.RefreshHandle)
	require.True(t, got.Scopes.Groups)
	require.True(t, got.Scopes.OfflineAccess)

	require.Equal(t, "user-1", identity.UserID)
	require.Equal(t, "updated-user", identity.Username)
	require.Equal(t, "updated@example.com", identity.Email)
	require.Equal(t, []string{"team-c"}, identity.Groups)

	var refresh refreshData
	require.NoError(t, json.Unmarshal(identity.ConnectorData, &refresh))
	require.Equal(t, "refresh-2", refresh.RefreshHandle)
}

func TestRefreshReusesExistingRefreshHandle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(identityResponse{
			UserID: "user-1",
		}))
	}))
	defer srv.Close()

	conn := newTestConnector(t, Config{
		LoginURL:             srv.URL + "/login",
		ExchangeURL:          srv.URL + "/exchange",
		RefreshURL:           srv.URL + "/refresh",
		ApplicationBindingID: "binding-1",
		ClientID:             "dex-client",
		ClientSecret:         "secret",
	})
	connData, err := encodeRefreshData("refresh-1")
	require.NoError(t, err)

	identity, err := conn.Refresh(
		context.Background(),
		connector.Scopes{OfflineAccess: true},
		connector.Identity{UserID: "user-1", ConnectorData: connData},
	)
	require.NoError(t, err)

	var refresh refreshData
	require.NoError(t, json.Unmarshal(identity.ConnectorData, &refresh))
	require.Equal(t, "refresh-1", refresh.RefreshHandle)
}

func TestRefreshRejectsUserIDChange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(identityResponse{
			UserID: "user-2",
		}))
	}))
	defer srv.Close()

	conn := newTestConnector(t, Config{
		LoginURL:             srv.URL + "/login",
		ExchangeURL:          srv.URL + "/exchange",
		RefreshURL:           srv.URL + "/refresh",
		ApplicationBindingID: "binding-1",
		ClientID:             "dex-client",
		ClientSecret:         "secret",
	})
	connData, err := encodeRefreshData("refresh-1")
	require.NoError(t, err)

	_, err = conn.Refresh(
		context.Background(),
		connector.Scopes{OfflineAccess: true},
		connector.Identity{UserID: "user-1", ConnectorData: connData},
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "changed userID")
}

func TestRefreshRequiresRefreshURL(t *testing.T) {
	conn := newTestConnector(t, Config{
		LoginURL:             "https://principal.example/login",
		ExchangeURL:          "https://principal.example/exchange",
		ApplicationBindingID: "binding-1",
		ClientID:             "dex-client",
		ClientSecret:         "secret",
	})
	connData, err := encodeRefreshData("refresh-1")
	require.NoError(t, err)

	_, err = conn.Refresh(context.Background(), connector.Scopes{}, connector.Identity{ConnectorData: connData})
	require.Error(t, err)
	require.Contains(t, err.Error(), "refreshURL is required")
}

func newTestConnector(t *testing.T, config Config) *principalConnector {
	t.Helper()

	conn, err := config.Open("principal-app", testLogger())
	require.NoError(t, err)

	principalConn, ok := conn.(*principalConnector)
	require.True(t, ok)
	return principalConn
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestPrincipalError(t *testing.T) {
	err := principalError("", "fallback")
	require.EqualError(t, err, "fallback")

	err = principalError("description", "fallback")
	require.EqualError(t, err, "description")
}

func TestPostJSONDoesNotExposeErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("secret response detail"))
	}))
	defer srv.Close()

	conn := newTestConnector(t, Config{
		LoginURL:             srv.URL + "/login",
		ExchangeURL:          srv.URL + "/exchange",
		ApplicationBindingID: "binding-1",
		ClientID:             "dex-client",
		ClientSecret:         "secret",
	})

	req := httptest.NewRequest(http.MethodGet, "https://dex.example/callback?state=dex-state&code=code-1", nil)
	_, connData, err := conn.LoginURL(connector.Scopes{}, "https://dex.example/callback", "dex-state")
	require.NoError(t, err)

	_, err = conn.HandleCallback(connector.Scopes{}, connData, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not in any of the required groups")
	require.NotContains(t, err.Error(), "secret response detail")
}
