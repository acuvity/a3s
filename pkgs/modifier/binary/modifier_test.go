package binary

import (
	"context"
	"fmt"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"go.acuvity.ai/a3s/pkgs/conf"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/elemental"
)

func TestBinaryModifier(t *testing.T) {

	modifierErrorHash, _ := computeHash("fixtures/modifier-error.sh")
	modifierWorkingHash, _ := computeHash("fixtures/modifier-working.sh")

	Convey("I have a binary.Modifier with an empty hash", t, func() {

		m, err := New(
			"fixtures/modifier-working.sh",
			"",
			conf.MongoConf{MongoURL: "mongodb://127.0.0.1"},
		)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, "missing hash")
		So(m, ShouldBeNil)
	})

	Convey("I have a binary.Modifier that points to a non existing file", t, func() {

		m, err := New(
			"fixtures/modifier-not-exist.sh",
			"h",
			conf.MongoConf{MongoURL: "mongodb://127.0.0.1"},
		)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, "unable to read binary modifier: open fixtures/modifier-not-exist.sh: no such file or directory")
		So(m, ShouldBeNil)
	})

	Convey("I have a binary.Modifier with a hash mismatch", t, func() {

		m, err := New(
			"fixtures/modifier-working.sh",
			"h",
			conf.MongoConf{MongoURL: "mongodb://127.0.0.1"},
		)
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, fmt.Sprintf("hash mismatch: want: h got: %s", modifierWorkingHash))
		So(m, ShouldBeNil)
	})

	Convey("I have a binary.Modifier that returns an controlled error", t, func() {

		m, err := New(
			"fixtures/modifier-error.sh",
			modifierErrorHash,
			conf.MongoConf{MongoURL: "mongodb://127.0.0.1"},
		)
		So(err, ShouldBeNil)
		So(m, ShouldNotBeNil)

		m.encoding = elemental.EncodingTypeJSON

		err = m.Run(context.Background())
		So(err, ShouldBeNil)

		idt := &token.IdentityToken{Identity: []string{"a=a", "b=b"}}

		time.Sleep(time.Second)
		nidt, err := m.Write(context.Background(), idt, "iss")
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldEqual, "binary modifier: error from binary: oh noes")
		So(nidt, ShouldBeNil)
	})

	Convey("I have a binary.Modifier that returns a modifier token", t, func() {

		m, err := New(
			"fixtures/modifier-working.sh",
			modifierWorkingHash,
			conf.MongoConf{MongoURL: "mongodb://127.0.0.1"},
		)
		So(err, ShouldBeNil)
		So(m, ShouldNotBeNil)

		m.encoding = elemental.EncodingTypeJSON

		err = m.Run(context.Background())
		So(err, ShouldBeNil)

		idt := &token.IdentityToken{Identity: []string{"a=a", "b=b"}}

		time.Sleep(time.Second)
		nidt, err := m.Write(context.Background(), idt, "iss")
		So(err, ShouldBeNil)
		So(nidt, ShouldNotBeNil)
		So(nidt.Identity, ShouldResemble, []string{"z=z"})
	})
}
