package ciscoduo

import "fmt"

// Duo user statuses, as returned by the Admin API.
const (
	UserStatusActive = "active"
	UserStatusBypass = "bypass"
)

// GroupStatusDisabled is the status of a Duo group whose members are denied
// authentication, whatever their own user status is.
const GroupStatusDisabled = "disabled"

// response is the envelope of every Duo Admin API response. On success, Stat is
// "OK" and Response holds the payload. On failure, Stat is "FAIL" and Code,
// Message and MessageDetail describe the error.
type response[T any] struct {
	Stat          string   `json:"stat"`
	Response      T        `json:"response"`
	Metadata      metadata `json:"metadata"`
	Code          int      `json:"code"`
	Message       string   `json:"message"`
	MessageDetail string   `json:"message_detail"`
}

// envelope gives access to the status of a decoded response.
type envelope interface {
	failure() (bool, string)
}

// failure returns true and a description of the error if the response is not OK.
func (r *response[T]) failure() (bool, string) {
	if r.Stat == "OK" {
		return false, ""
	}
	return true, fmt.Sprintf("(stat: %s, code: %d) %s %s", r.Stat, r.Code, r.Message, r.MessageDetail)
}

// metadata holds the pagination information of a paged response. NextOffset
// is absent on the last page.
type metadata struct {
	NextOffset *int `json:"next_offset"`
}

// User represents a Duo Admin API user.
type User struct {
	ID        string `json:"user_id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	RealName  string `json:"realname"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	Status    string `json:"status"`
}

// Group represents a Duo Admin API group the user belongs to.
type Group struct {
	ID     string `json:"group_id"`
	Name   string `json:"name"`
	Desc   string `json:"desc"`
	Status string `json:"status"`
}
