package entra

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/karlseguin/ccache/v3"
	"go.acuvity.ai/a3s/internal/idp/utils"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/netsafe"
	"go.acuvity.ai/elemental"
)

type Manager struct {
	client       *http.Client
	requestMaker netsafe.RequestMaker
	tokenCache   *ccache.Cache[*AccessToken]
}

func NewEntraManager(client *http.Client, requestMaker netsafe.RequestMaker) *Manager {

	return &Manager{
		tokenCache:   ccache.New(ccache.Configure[*AccessToken]().MaxSize(1024)),
		client:       client,
		requestMaker: requestMaker,
	}
}

func (m *Manager) GetAccessToken(ctx context.Context, creds *api.MTLSSourceEntra) (*AccessToken, error) {

	if creds == nil {
		return nil, elemental.NewError("Invalid MTLS Source", "no entraApplicationCredentials set", "a3s:entra", http.StatusInternalServerError)
	}

	ckey := fmt.Sprintf(
		"%s:%s:%s",
		creds.ClientID,
		creds.ClientSecret,
		creds.ClientTenantID,
	)

	rtoken := &AccessToken{}

	if item := m.tokenCache.Get(ckey); item != nil && !item.Expired() {

		rtoken = item.Value()

	} else {

		form := url.Values{
			"client_id":     {creds.ClientID},
			"client_secret": {creds.ClientSecret},
			"scope":         {"https://graph.microsoft.com/.default"},
			"grant_type":    {"client_credentials"},
		}

		r, err := m.requestMaker(ctx, http.MethodPost, fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", creds.ClientTenantID), strings.NewReader(form.Encode()))
		if err != nil {
			return nil, elemental.NewError("Unable to create oauth2 client token request", err.Error(), "a3s:entra", http.StatusBadRequest)
		}
		r.Header = http.Header{
			"Content-Type": {"application/x-www-form-urlencoded"},
		}

		resp, err := m.client.Do(r)
		if err != nil {
			return nil, elemental.NewError("Unable to send request to retrieve client access token", err.Error(), "a3s:entra", http.StatusBadRequest)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			d, _ := io.ReadAll(resp.Body)
			return nil, elemental.NewError("Invalid status code returned from request to retrieve client access token", fmt.Sprintf("(%s) %s", resp.Status, string(d)), "a3s:entra", http.StatusBadRequest)
		}

		// utils.PeekBody(resp)

		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(rtoken); err != nil {
			return nil, elemental.NewError("Unable to decode client access token", err.Error(), "a3s:entra", http.StatusBadRequest)
		}

		cls := jwt.MapClaims{}
		if _, _, err := jwt.NewParser().ParseUnverified(rtoken.Token, &cls); err != nil {
			return nil, elemental.NewError("Unable to extract appid (oid) from access token claims", err.Error(), "a3s:entra", http.StatusBadRequest)
		}

		expireIn := time.Duration(rtoken.ExpireIn)

		rtoken.Claims = cls
		rtoken.ExpirationTime = time.Now().Add(expireIn)
		rtoken.ClientID = creds.ClientID

		m.tokenCache.Set(ckey, rtoken, expireIn)
	}

	return rtoken, nil
}

func (m *Manager) GetUser(ctx context.Context, rtoken *AccessToken, principalName string) (*User, error) {

	r, err := m.requestMaker(ctx, http.MethodGet, fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s", principalName), nil)
	if err != nil {
		return nil, elemental.NewError("Unable to create request to retrieve user info", err.Error(), "a3s:entra", http.StatusBadRequest)
	}
	r.Header = http.Header{
		"Authorization": {"Bearer " + rtoken.Token},
	}

	resp, err := m.client.Do(r)
	if err != nil {
		return nil, elemental.NewError("Unable to send request to retrieve user", err.Error(), "a3s:entra", http.StatusBadRequest)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		d, _ := io.ReadAll(resp.Body)
		return nil, elemental.NewError("Invalid status code returned from request to retrieve user", fmt.Sprintf("(%s) %s", resp.Status, string(d)), "a3s:entra", http.StatusBadRequest)
	}

	// utils.PeekBody(resp)

	ruser := &User{}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(ruser); err != nil {
		return nil, elemental.NewError("Unable to decode user", err.Error(), "a3s:entra", http.StatusBadRequest)
	}

	return ruser, nil
}

func (m *Manager) GetGroup(ctx context.Context, rtoken *AccessToken, principalName string) (*Group, error) {

	r, err := m.requestMaker(ctx, http.MethodGet, fmt.Sprintf("https://graph.microsoft.com/v1.0/groups/%s", principalName), nil)
	if err != nil {
		return nil, elemental.NewError("Unable to create request to retrieve group info", err.Error(), "a3s:entra", http.StatusBadRequest)
	}
	r.Header = http.Header{
		"Authorization": {"Bearer " + rtoken.Token},
	}

	resp, err := m.client.Do(r)
	if err != nil {
		return nil, elemental.NewError("Unable to send request to retrieve group", err.Error(), "a3s:entra", http.StatusBadRequest)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		d, _ := io.ReadAll(resp.Body)
		return nil, elemental.NewError("Invalid status code returned from request to retrieve group", fmt.Sprintf("(%s) %s", resp.Status, string(d)), "a3s:entra", http.StatusBadRequest)
	}

	utils.PeekBody(resp)

	rgroup := &Group{}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(rgroup); err != nil {
		return nil, elemental.NewError("Unable to decode group", err.Error(), "a3s:entra", http.StatusBadRequest)
	}

	return rgroup, nil
}

func (m *Manager) GetMembership(ctx context.Context, rtoken *AccessToken, ruser *User) (*Membership, error) {

	r, err := m.requestMaker(ctx, http.MethodGet, fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s/memberOf/microsoft.graph.group?$select=displayName,id", ruser.ID), nil)
	if err != nil {
		return nil, elemental.NewError("Unable to create request to retrieve groups of user", err.Error(), "a3s:entra", http.StatusBadRequest)
	}
	r.Header = http.Header{
		"Authorization": {"Bearer " + rtoken.Token},
	}

	resp, err := m.client.Do(r)
	if err != nil {
		return nil, elemental.NewError("Unable to send request to retrieve user groups", err.Error(), "a3s:entra", http.StatusBadRequest)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		d, _ := io.ReadAll(resp.Body)
		return nil, elemental.NewError("Invalid status code returned from request to retrieve user groups", fmt.Sprintf("(%s) %s", resp.Status, string(d)), "a3s:entra", http.StatusBadRequest)
	}

	// utils.PeekBody(resp)

	rmember := &Membership{}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(rmember); err != nil {
		return nil, elemental.NewError("Unable to decode user groups", err.Error(), "a3s:entra", http.StatusBadRequest)
	}

	return rmember, nil
}

func (m *Manager) GetAppRoles(ctx context.Context, rtoken *AccessToken, ruser *User) (*AppRoles, error) {

	r, err := m.requestMaker(ctx, http.MethodGet, fmt.Sprintf("https://graph.microsoft.com/v1.0/servicePrincipals(appId='%s')?$select=id,displayName,appRoles", rtoken.ClientID), nil)
	if err != nil {
		return nil, elemental.NewError("Unable to create request to retrieve app roles", err.Error(), "a3s:entra", http.StatusBadRequest)
	}
	r.Header = http.Header{
		"Authorization": {"Bearer " + rtoken.Token},
	}

	resp, err := m.client.Do(r)
	if err != nil {
		return nil, elemental.NewError("Unable to send request to retrieve app roles", err.Error(), "a3s:entra", http.StatusBadRequest)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		d, _ := io.ReadAll(resp.Body)
		return nil, elemental.NewError("Invalid status code returned from request to retrieve app roles", fmt.Sprintf("(%s) %s", resp.Status, string(d)), "a3s:entra", http.StatusBadRequest)
	}

	appRoles := &AppRoles{}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(appRoles); err != nil {
		return nil, elemental.NewError("Unable to decode app roles:  %w", err.Error(), "a3s:entra", http.StatusBadRequest)
	}

	return appRoles, nil
}

func (m *Manager) GetRoles(ctx context.Context, rtoken *AccessToken, ruser *User) (*Roles, error) {

	r, err := m.requestMaker(ctx, http.MethodGet, fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s/appRoleAssignments?$filter=resourceId%%20eq%%20%s&$count=true", ruser.ID, rtoken.Claims["oid"]), nil)
	if err != nil {
		return nil, elemental.NewError("Unable to create request to retrieve app role assignment of user", err.Error(), "a3s:entra", http.StatusBadRequest)
	}
	r.Header = http.Header{
		"Authorization": {"Bearer " + rtoken.Token},
	}

	resp, err := m.client.Do(r)
	if err != nil {
		return nil, elemental.NewError("Unable to send request to retrieve app role assignments", err.Error(), "a3s:entra", http.StatusBadRequest)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		d, _ := io.ReadAll(resp.Body)
		return nil, elemental.NewError("Invalid status code returned from request to retrieve app role assignments", fmt.Sprintf("(%s) %s", resp.Status, string(d)), "a3s:entra", http.StatusBadRequest)
	}

	rmaprole := &Roles{}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(rmaprole); err != nil {
		return nil, elemental.NewError("Unable to decode app role assignments", err.Error(), "a3s:entra", http.StatusBadRequest)
	}

	return rmaprole, nil
}

func (m *Manager) Subscribe(ctx context.Context, creds *api.MTLSSourceEntra, resource string, notificationURL string, lifecycleNotificationURL string, exp time.Duration, changeType string) (*Subscription, error) {

	sreq := Subscription{
		ChangeType:               changeType,
		NotificationURL:          notificationURL,
		Resource:                 resource,
		ExpirationDateTime:       time.Now().Add(exp),
		ClientState:              creds.GraphEventSecret,
		LifecycleNotificationURL: lifecycleNotificationURL,
	}

	data, err := elemental.Encode(elemental.EncodingTypeJSON, sreq)
	if err != nil {
		return nil, elemental.NewError("Unable to encode subscription request", err.Error(), "a3s:entra", http.StatusBadRequest)
	}

	req, err := m.requestMaker(ctx, http.MethodPost, "https://graph.microsoft.com/v1.0/subscriptions", bytes.NewBuffer(data))
	if err != nil {
		return nil, elemental.NewError("Unable to build ms graph subscription request", err.Error(), "a3s:entra", http.StatusBadRequest)
	}

	rtoken, err := m.GetAccessToken(ctx, creds)
	if err != nil {
		return nil, elemental.NewError("Unable retrieve access token for subscription", err.Error(), "a3s:entra", http.StatusBadRequest)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", rtoken.Token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, elemental.NewError("Unable to send ms graph subscription request", err.Error(), "a3s:entra", http.StatusBadRequest)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		d, _ := io.ReadAll(resp.Body)
		return nil, elemental.NewError("Invalid status code returned from request for subscription", fmt.Sprintf("(%s) %s", resp.Status, string(d)), "a3s:entra", http.StatusBadRequest)
	}

	// utils.PeekBody(resp)

	sub := &Subscription{}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(sub); err != nil {
		return nil, elemental.NewError("Unable to decode subscription", err.Error(), "a3s:entra", http.StatusBadRequest)
	}

	return sub, nil
}

func (m *Manager) RenewSubscription(ctx context.Context, creds *api.MTLSSourceEntra, id string, exp time.Duration) (*Subscription, error) {

	sreq := Subscription{
		ExpirationDateTime: time.Now().Add(exp),
	}

	data, err := elemental.Encode(elemental.EncodingTypeJSON, sreq)
	if err != nil {
		return nil, elemental.NewError("Unable to encode subscription renewal request", err.Error(), "a3s:entra", http.StatusBadRequest)
	}

	req, err := m.requestMaker(ctx, http.MethodPatch, fmt.Sprintf("https://graph.microsoft.com/v1.0/subscriptions/%s", id), bytes.NewBuffer(data))
	if err != nil {
		return nil, elemental.NewError("Unable to build ms graph subscription renewal request", err.Error(), "a3s:entra", http.StatusBadRequest)
	}

	rtoken, err := m.GetAccessToken(ctx, creds)
	if err != nil {
		return nil, elemental.NewError("Unable retrieve access token for renewing subscription", err.Error(), "a3s:entra", http.StatusBadRequest)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", rtoken.Token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, elemental.NewError("Unable to send ms graph subscription renewal request", err.Error(), "a3s:entra", http.StatusBadRequest)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		d, _ := io.ReadAll(resp.Body)
		return nil, elemental.NewError("Invalid status code returned from request for renewal subscription", fmt.Sprintf("(%s) %s", resp.Status, string(d)), "a3s:entra", http.StatusBadRequest)
	}

	// utils.PeekBody(resp)

	sub := &Subscription{}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(sub); err != nil {
		return nil, elemental.NewError("Unable to decode renewal subscription", err.Error(), "a3s:entra", http.StatusBadRequest)
	}

	return sub, nil
}

func (m *Manager) Unsubscribe(ctx context.Context, creds *api.MTLSSourceEntra, id string) error {

	req, err := m.requestMaker(ctx, http.MethodDelete, fmt.Sprintf("https://graph.microsoft.com/v1.0/subscriptions/%s", id), nil)
	if err != nil {
		return elemental.NewError("Unable to build ms graph subscription delete request", err.Error(), "a3s:entra", http.StatusBadRequest)
	}

	rtoken, err := m.GetAccessToken(ctx, creds)
	if err != nil {
		return elemental.NewError("Unable retrieve access token for deleting subscription", err.Error(), "a3s:entra", http.StatusBadRequest)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", rtoken.Token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return elemental.NewError("Unable to send ms graph subscription deleting request", err.Error(), "a3s:entra", http.StatusBadRequest)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil
	}

	if resp.StatusCode == http.StatusNoContent {
		d, _ := io.ReadAll(resp.Body)
		return elemental.NewError("Invalid status code returned from request for deleting subscription", fmt.Sprintf("(%s) %s", resp.Status, string(d)), "a3s:entra", http.StatusBadRequest)
	}

	return nil
}
