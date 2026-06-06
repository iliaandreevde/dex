// Package principal implements a Principal-backed Dex connector.
package principal

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/httpclient"
)

const defaultTimeout = 10 * time.Second

var (
	_ connector.CallbackConnector = (*principalConnector)(nil)
	_ connector.RefreshConnector  = (*principalConnector)(nil)
)

// Config holds configuration for the Principal connector.
type Config struct {
	LoginURL             string   `json:"loginURL"`
	ExchangeURL          string   `json:"exchangeURL"`
	RefreshURL           string   `json:"refreshURL"`
	ApplicationBindingID string   `json:"applicationBindingID"`
	RedirectURI          string   `json:"redirectURI"`
	ClientID             string   `json:"clientID"`
	ClientSecret         string   `json:"clientSecret"`
	RootCAs              []string `json:"rootCAs"`
	InsecureSkipVerify   bool     `json:"insecureSkipVerify"`
	Timeout              string   `json:"timeout"`
}

// Open returns a Principal-backed callback connector.
func (c *Config) Open(id string, logger *slog.Logger) (connector.Connector, error) {
	loginURL, err := requiredHTTPURL("loginURL", c.LoginURL)
	if err != nil {
		return nil, err
	}
	exchangeURL, err := requiredHTTPURL("exchangeURL", c.ExchangeURL)
	if err != nil {
		return nil, err
	}
	refreshURL, err := optionalHTTPURL("refreshURL", c.RefreshURL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(c.ApplicationBindingID) == "" {
		return nil, errors.New("applicationBindingID is required")
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return nil, errors.New("clientID is required")
	}
	if strings.TrimSpace(c.ClientSecret) == "" {
		return nil, errors.New("clientSecret is required")
	}

	redirectURI := strings.TrimSpace(c.RedirectURI)
	if redirectURI != "" {
		if _, err := requiredHTTPURL("redirectURI", redirectURI); err != nil {
			return nil, err
		}
	}

	timeout := defaultTimeout
	if c.Timeout != "" {
		timeout, err = time.ParseDuration(c.Timeout)
		if err != nil {
			return nil, fmt.Errorf("invalid timeout: %w", err)
		}
		if timeout <= 0 {
			return nil, errors.New("timeout must be positive")
		}
	}

	httpClient, err := httpclient.NewHTTPClient(c.RootCAs, c.InsecureSkipVerify)
	if err != nil {
		return nil, err
	}
	httpClient.Timeout = timeout

	return &principalConnector{
		id:                   id,
		loginURL:             loginURL,
		exchangeURL:          exchangeURL,
		refreshURL:           refreshURL,
		applicationBindingID: strings.TrimSpace(c.ApplicationBindingID),
		redirectURI:          redirectURI,
		clientID:             strings.TrimSpace(c.ClientID),
		clientSecret:         c.ClientSecret,
		httpClient:           httpClient,
		logger:               logger.With(slog.Group("connector", "type", "principal", "id", id)),
	}, nil
}

type principalConnector struct {
	id                   string
	loginURL             *url.URL
	exchangeURL          *url.URL
	refreshURL           *url.URL
	applicationBindingID string
	redirectURI          string
	clientID             string
	clientSecret         string
	httpClient           *http.Client
	logger               *slog.Logger
}

type scopePayload struct {
	Groups        bool `json:"groups"`
	OfflineAccess bool `json:"offlineAccess"`
}

type loginData struct {
	ConnectorID          string `json:"connectorID"`
	ApplicationBindingID string `json:"applicationBindingID"`
	CallbackURL          string `json:"callbackURL"`
	State                string `json:"state"`
	Nonce                string `json:"nonce"`
}

type exchangeRequest struct {
	ConnectorID          string       `json:"connectorID"`
	ApplicationBindingID string       `json:"applicationBindingID"`
	CallbackURL          string       `json:"callbackURL"`
	State                string       `json:"state"`
	Nonce                string       `json:"nonce"`
	Code                 string       `json:"code"`
	Scopes               scopePayload `json:"scopes"`
}

type refreshRequest struct {
	ConnectorID          string       `json:"connectorID"`
	ApplicationBindingID string       `json:"applicationBindingID"`
	RefreshHandle        string       `json:"refreshHandle"`
	Scopes               scopePayload `json:"scopes"`
}

type identityResponse struct {
	UserID            string   `json:"userID"`
	Username          string   `json:"username"`
	PreferredUsername string   `json:"preferredUsername"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"emailVerified"`
	Groups            []string `json:"groups"`
	RefreshHandle     string   `json:"refreshHandle"`
}

type errorResponse struct {
	UserID string   `json:"userID"`
	Groups []string `json:"groups"`
}

type statusError struct {
	code   int
	userID string
	groups []string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("Principal returned status %d", e.code)
}

type refreshData struct {
	RefreshHandle string `json:"refreshHandle"`
}

// LoginURL returns the Principal browser login URL.
func (c *principalConnector) LoginURL(s connector.Scopes, callbackURL, state string) (string, []byte, error) {
	if c.redirectURI != "" && callbackURL != c.redirectURI {
		return "", nil, fmt.Errorf("expected callback URL %q did not match the URL in the config %q", callbackURL, c.redirectURI)
	}
	if _, err := requiredHTTPURL("callbackURL", callbackURL); err != nil {
		return "", nil, err
	}
	if state == "" {
		return "", nil, errors.New("state is required")
	}

	nonce, err := newNonce()
	if err != nil {
		return "", nil, err
	}

	connData := loginData{
		ConnectorID:          c.id,
		ApplicationBindingID: c.applicationBindingID,
		CallbackURL:          callbackURL,
		State:                state,
		Nonce:                nonce,
	}
	data, err := json.Marshal(connData)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal principal connector data: %w", err)
	}

	u := *c.loginURL
	q := u.Query()
	q.Set("connector_id", c.id)
	q.Set("application_binding_id", c.applicationBindingID)
	q.Set("callback_url", callbackURL)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("scope_groups", boolString(s.Groups))
	q.Set("scope_offline_access", boolString(s.OfflineAccess))
	u.RawQuery = q.Encode()

	return u.String(), data, nil
}

// HandleCallback exchanges the Principal one-time code for a Dex identity.
func (c *principalConnector) HandleCallback(s connector.Scopes, connData []byte, r *http.Request) (connector.Identity, error) {
	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		return connector.Identity{}, principalError(q.Get("error_description"), errType)
	}
	if s.OfflineAccess && c.refreshURL == nil {
		return connector.Identity{}, errors.New("refreshURL is required for Principal offline access")
	}

	code := q.Get("code")
	if code == "" {
		return connector.Identity{}, errors.New("principal connector callback missing code")
	}
	state := q.Get("state")
	if state == "" {
		return connector.Identity{}, errors.New("principal connector callback missing state")
	}

	data, err := decodeLoginData(connData)
	if err != nil {
		return connector.Identity{}, err
	}
	if err := c.validateLoginData(data, state); err != nil {
		return connector.Identity{}, err
	}

	req := exchangeRequest{
		ConnectorID:          c.id,
		ApplicationBindingID: c.applicationBindingID,
		CallbackURL:          data.CallbackURL,
		State:                state,
		Nonce:                data.Nonce,
		Code:                 code,
		Scopes:               scopesPayload(s),
	}

	var resp identityResponse
	if err := c.postJSON(r.Context(), c.exchangeURL, req, &resp); err != nil {
		return connector.Identity{}, mapAccessDenied(err)
	}

	return resp.identity(s, s.OfflineAccess)
}

// Refresh refreshes Principal-backed identity claims.
func (c *principalConnector) Refresh(ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	if c.refreshURL == nil {
		return connector.Identity{}, errors.New("refreshURL is required for Principal refresh")
	}

	data, err := decodeRefreshData(identity.ConnectorData)
	if err != nil {
		return connector.Identity{}, err
	}

	req := refreshRequest{
		ConnectorID:          c.id,
		ApplicationBindingID: c.applicationBindingID,
		RefreshHandle:        data.RefreshHandle,
		Scopes:               scopesPayload(s),
	}

	var resp identityResponse
	if err := c.postJSON(ctx, c.refreshURL, req, &resp); err != nil {
		return connector.Identity{}, mapAccessDenied(err)
	}
	if identity.UserID != "" && resp.UserID != identity.UserID {
		return connector.Identity{}, fmt.Errorf("Principal refresh changed userID from %q to %q", identity.UserID, resp.UserID)
	}

	refreshed, err := resp.identity(s, false)
	if err != nil {
		return connector.Identity{}, err
	}
	if resp.RefreshHandle == "" {
		resp.RefreshHandle = data.RefreshHandle
	}
	refreshed.ConnectorData, err = encodeRefreshData(resp.RefreshHandle)
	if err != nil {
		return connector.Identity{}, err
	}
	return refreshed, nil
}

func (c *principalConnector) validateLoginData(data loginData, state string) error {
	if data.ConnectorID != c.id {
		return fmt.Errorf("principal connector data belongs to connector %q, expected %q", data.ConnectorID, c.id)
	}
	if data.ApplicationBindingID != c.applicationBindingID {
		return fmt.Errorf(
			"principal connector data belongs to application binding %q, expected %q",
			data.ApplicationBindingID,
			c.applicationBindingID,
		)
	}
	if data.State != state {
		return errors.New("principal connector callback state mismatch")
	}
	if data.Nonce == "" {
		return errors.New("principal connector data missing nonce")
	}
	if data.CallbackURL == "" {
		return errors.New("principal connector data missing callback URL")
	}
	if c.redirectURI != "" && data.CallbackURL != c.redirectURI {
		return fmt.Errorf("principal connector data callback URL %q does not match configured redirectURI", data.CallbackURL)
	}
	return nil
}

func (c *principalConnector) postJSON(ctx context.Context, endpoint *url.URL, requestBody, responseBody any) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(requestBody); err != nil {
		return fmt.Errorf("failed to encode Principal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), &buf)
	if err != nil {
		return fmt.Errorf("failed to build Principal request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.clientID, c.clientSecret)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call Principal: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return newStatusError(resp)
	}

	if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil {
		return fmt.Errorf("failed to decode Principal response: %w", err)
	}
	return nil
}

func (r identityResponse) identity(s connector.Scopes, requireRefreshHandle bool) (connector.Identity, error) {
	if r.UserID == "" {
		return connector.Identity{}, errors.New("Principal response missing userID")
	}

	identity := connector.Identity{
		UserID:            r.UserID,
		Username:          r.Username,
		PreferredUsername: r.PreferredUsername,
		Email:             r.Email,
		EmailVerified:     r.EmailVerified,
	}
	if s.Groups {
		identity.Groups = append([]string(nil), r.Groups...)
	}
	if s.OfflineAccess && r.RefreshHandle != "" {
		data, err := encodeRefreshData(r.RefreshHandle)
		if err != nil {
			return connector.Identity{}, err
		}
		identity.ConnectorData = data
	} else if requireRefreshHandle {
		return connector.Identity{}, errors.New("Principal response missing refreshHandle for offline access")
	}
	return identity, nil
}

func decodeLoginData(connData []byte) (loginData, error) {
	if len(connData) == 0 {
		return loginData{}, errors.New("principal connector data is empty")
	}
	var data loginData
	if err := json.Unmarshal(connData, &data); err != nil {
		return loginData{}, fmt.Errorf("failed to unmarshal principal connector data: %w", err)
	}
	return data, nil
}

func decodeRefreshData(connData []byte) (refreshData, error) {
	if len(connData) == 0 {
		return refreshData{}, errors.New("principal refresh data is empty")
	}
	var data refreshData
	if err := json.Unmarshal(connData, &data); err != nil {
		return refreshData{}, fmt.Errorf("failed to unmarshal principal refresh data: %w", err)
	}
	if data.RefreshHandle == "" {
		return refreshData{}, errors.New("principal refresh data missing refreshHandle")
	}
	return data, nil
}

func encodeRefreshData(refreshHandle string) ([]byte, error) {
	if refreshHandle == "" {
		return nil, errors.New("refreshHandle is required")
	}
	data, err := json.Marshal(refreshData{RefreshHandle: refreshHandle})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal principal refresh data: %w", err)
	}
	return data, nil
}

func requiredHTTPURL(field, raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("%s is required", field)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", field, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%s must use http or https", field)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%s must include host", field)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%s must not include user info", field)
	}
	if u.Fragment != "" {
		return nil, fmt.Errorf("%s must not include fragment", field)
	}
	return u, nil
}

func optionalHTTPURL(field, raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	return requiredHTTPURL(field, raw)
}

func newNonce() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func scopesPayload(s connector.Scopes) scopePayload {
	return scopePayload{Groups: s.Groups, OfflineAccess: s.OfflineAccess}
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func principalError(description, fallback string) error {
	if description != "" {
		return errors.New(description)
	}
	return errors.New(fallback)
}

func newStatusError(resp *http.Response) error {
	errResp := errorResponse{}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&errResp)
	return &statusError{
		code:   resp.StatusCode,
		userID: errResp.UserID,
		groups: append([]string(nil), errResp.Groups...),
	}
}

func mapAccessDenied(err error) error {
	var statusErr *statusError
	if errors.As(err, &statusErr) && statusErr.code == http.StatusForbidden {
		return &connector.UserNotInRequiredGroupsError{
			UserID: statusErr.userID,
			Groups: statusErr.groups,
		}
	}
	return err
}
