package oauth

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestApplicationFromClaims(t *testing.T) {

	Convey("Given identity claims that name an OAuth application", t, func() {

		app := ApplicationFromClaims([]string{"color=blue", "@oauthapp:id=1", "@oauthapp:namespace=/orgs/acme", "@oauthapp:name=app"})

		So(app, ShouldResemble, Application{ID: "1", Namespace: "/orgs/acme", Name: "app"})
		So(app.IsEmpty(), ShouldBeFalse)
	})

	Convey("Given identity claims that name no OAuth application", t, func() {

		app := ApplicationFromClaims([]string{"color=blue", "@source:type=test"})

		So(app, ShouldResemble, Application{})
		So(app.IsEmpty(), ShouldBeTrue)
	})
}
