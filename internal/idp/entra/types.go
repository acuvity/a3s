package entra

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AccessToken struct {
	Token    string `json:"access_token"`
	ExpireIn int    `json:"expires_in"`

	Claims         jwt.MapClaims `json:"-"`
	ClientID       string        `json:"-"`
	ExpirationTime time.Time     `json:"-"`
}

type User struct {
	EMail             string `json:"mail"`
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	GivenName         string `json:"givenName"`
	Surname           string `json:"surname"`
	UserPrincipalName string `json:"userPrincipalName"`
}

type Group struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

type Membership struct {
	Values []Group `json:"value"`
}

type Subscription struct {
	ID                       string    `json:"id,omitempty"`
	Resource                 string    `json:"resource,omitempty"`
	ApplicationID            string    `json:"applicationId,omitempty"`
	ChangeType               string    `json:"changeType,omitempty"`
	ClientState              string    `json:"clientState,omitempty"`
	NotificationURL          string    `json:"notificationUrl,omitempty"`
	LifecycleNotificationURL string    `json:"lifecycleNotificationUrl,omitempty"`
	ExpirationDateTime       time.Time `json:"expirationDateTime"`
	CreatorID                string    `json:"creatorId,omitempty"`
	IncludeResourceData      string    `json:"includeResourceData,omitempty"`
	EncryptionCertificate    string    `json:"encryptionCertificate,omitempty"`
	EncryptionCertificateID  string    `json:"encryptionCertificateId,omitempty"`
	NotificationURLAppID     string    `json:"notificationUrlAppId,omitempty"`
}

type AppRole struct {
	ID   string `json:"id"`
	Name string `json:"value"`
}

type AppRoles struct {
	AppRoles []AppRole `json:"appRoles"`
}

type Roles struct {
	Values []struct {
		AppRoleID     string `json:"appRoleId"`
		PrincipalType string `json:"principalType"`
	} `json:"value"`
}
