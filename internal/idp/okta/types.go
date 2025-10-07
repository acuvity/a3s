package okta

type AccessToken struct {
	AccessToken string `json:"access_token"`

	Domain string `json:"-"`
}

type User struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Profile struct {
		EMail     string `json:"email"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
		Login     string `json:"login"`
	} `json:"profile"`
}

type Membership struct {
	ID      string `json:"id"`
	Profile struct {
		Name string `json:"name"`
	} `json:"profile"`
}
