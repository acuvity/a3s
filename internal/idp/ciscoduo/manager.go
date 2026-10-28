package ciscoduo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/netsafe"
	"go.acuvity.ai/elemental"
)

// duoGroupsPageSize is the page size used to retrieve user groups. 500 is the
// maximum allowed by the Admin API.
const duoGroupsPageSize = 500

var (
	duoRetryWait    = time.Second
	duoRetryMaxWait = 2 * time.Second
)

type Manager struct {
	client       *http.Client
	requestMaker netsafe.RequestMaker
}

func NewManager(client *http.Client, requestMaker netsafe.RequestMaker) *Manager {

	return &Manager{
		client:       client,
		requestMaker: requestMaker,
	}
}

// GetUser retrieves the Duo user whose username, or one of its aliases,
// matches the given principal. If there is none, the principal is tried as a Duo user ID.
func (m *Manager) GetUser(ctx context.Context, creds *api.MTLSSourceCiscoDuo, principal string) (*User, error) {

	if creds == nil {
		return nil, elemental.NewError("Invalid MTLS source", "No ciscoDuoApplicationCredentials set", "a3s:ciscoduo", http.StatusInternalServerError)
	}

	// An empty username filter could be ignored and match every user.
	if principal == "" {
		return nil, elemental.NewError("Unable to find user", "Empty principal", "a3s:ciscoduo", http.StatusBadRequest)
	}

	users := response[[]User]{}
	if err := m.get(ctx, creds, "/admin/v1/users", url.Values{"username": {principal}}, &users, "user info"); err != nil {
		return nil, err
	}

	if len(users.Response) > 1 {
		return nil, elemental.NewError("Unable to find user", fmt.Sprintf("Multiple Duo users found with username '%s'", principal), "a3s:ciscoduo", http.StatusBadRequest)
	}

	if len(users.Response) == 1 {
		return &users.Response[0], nil
	}

	// No username matched: try the principal as a Duo user ID.
	user := response[User]{}
	err := m.get(ctx, creds, fmt.Sprintf("/admin/v1/users/%s", url.PathEscape(principal)), nil, &user, "user info")
	if err == nil {
		return &user.Response, nil
	}

	if eerr := (elemental.Error{}); !errors.As(err, &eerr) || eerr.Code != http.StatusNotFound {
		return nil, err
	}

	return nil, elemental.NewError("Unable to find user", fmt.Sprintf("No Duo user found with username or user ID '%s'", principal), "a3s:ciscoduo", http.StatusBadRequest)
}

// GetMembership retrieves all the groups the given user belongs to, following
// the Admin API pagination.
func (m *Manager) GetMembership(ctx context.Context, creds *api.MTLSSourceCiscoDuo, ruser *User) ([]Group, error) {

	if creds == nil {
		return nil, elemental.NewError("Invalid MTLS source", "No ciscoDuoApplicationCredentials set", "a3s:ciscoduo", http.StatusInternalServerError)
	}

	rmember := []Group{}
	offset := 0

	for {
		params := url.Values{
			"limit":  {strconv.Itoa(duoGroupsPageSize)},
			"offset": {strconv.Itoa(offset)},
		}

		page := response[[]Group]{}
		if err := m.get(ctx, creds, fmt.Sprintf("/admin/v1/users/%s/groups", url.PathEscape(ruser.ID)), params, &page, "user groups"); err != nil {
			return nil, err
		}

		rmember = append(rmember, page.Response...)

		// Stop on the last page, and never go backwards to avoid looping forever.
		if page.Metadata.NextOffset == nil || *page.Metadata.NextOffset <= offset {
			break
		}
		offset = *page.Metadata.NextOffset
	}

	return rmember, nil
}

// get sends a signed GET request to the Duo Admin API and decodes the response
// envelope into out. what describes the requested resource in error messages.
func (m *Manager) get(ctx context.Context, creds *api.MTLSSourceCiscoDuo, path string, params url.Values, out envelope, what string) error {

	resp, err := m.send(ctx, creds, path, params, what)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusTooManyRequests {

		wait := retryAfter(resp.Header.Get("Retry-After"))
		_ = resp.Body.Close()

		select {
		case <-ctx.Done():
			return elemental.NewError(fmt.Sprintf("Unable to send request to retrieve %s", what), ctx.Err().Error(), "a3s:ciscoduo", http.StatusBadRequest)
		case <-time.After(wait):
		}

		// The request is signed again, as the signature covers the date.
		if resp, err = m.send(ctx, creds, path, params, what); err != nil {
			return err
		}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Not found is kept so callers can tell it apart from other failures.
		code := http.StatusBadRequest
		if resp.StatusCode == http.StatusNotFound {
			code = http.StatusNotFound
		}
		d, _ := io.ReadAll(resp.Body)
		return elemental.NewError(fmt.Sprintf("Invalid status code returned from request to retrieve %s", what), fmt.Sprintf("(%s): %s", resp.Status, string(d)), "a3s:ciscoduo", code)
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return elemental.NewError(fmt.Sprintf("Unable to decode %s", what), err.Error(), "a3s:ciscoduo", http.StatusBadRequest)
	}

	if failed, desc := out.failure(); failed {
		return elemental.NewError(fmt.Sprintf("Invalid response returned from request to retrieve %s", what), desc, "a3s:ciscoduo", http.StatusBadRequest)
	}

	return nil
}

// send builds, signs and sends a GET request to the Duo Admin API.
func (m *Manager) send(ctx context.Context, creds *api.MTLSSourceCiscoDuo, path string, params url.Values, what string) (*http.Response, error) {

	query := canonicalParams(params)
	u := fmt.Sprintf("https://%s%s", creds.APIHostname, path)
	if query != "" {
		u += "?" + query
	}

	r, err := m.requestMaker(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, elemental.NewError(fmt.Sprintf("Unable to create request to retrieve %s", what), err.Error(), "a3s:ciscoduo", http.StatusBadRequest)
	}
	signRequest(r, creds.APIHostname, path, query, creds.IntegrationKey, creds.SecretKey, time.Now())

	resp, err := m.client.Do(r)
	if err != nil {
		return nil, elemental.NewError(fmt.Sprintf("Unable to send request to retrieve %s", what), err.Error(), "a3s:ciscoduo", http.StatusBadRequest)
	}

	return resp, nil
}

// retryAfter returns how long to wait before retrying a rate limited request,
// from the number of seconds in the Retry-After header.
func retryAfter(header string) time.Duration {

	secs, err := strconv.Atoi(header)
	if err != nil || secs < 0 {
		return duoRetryWait
	}

	return min(time.Duration(secs)*time.Second, duoRetryMaxWait)
}
