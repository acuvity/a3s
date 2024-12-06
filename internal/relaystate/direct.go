package relaystate

// IsDirect returns true if the relay state is
// in the format of predefined relay state, like
// the okta tiles and SSO like that.
func IsDirect(relayState string) bool {
	return relayState == "_direct"
}
