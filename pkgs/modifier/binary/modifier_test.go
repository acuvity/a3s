package binary

import (
	"context"
	"fmt"
	"sync"
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

func TestBinaryModifierConcurrentWrites(t *testing.T) {

	hash, _ := computeHash("fixtures/modifier-echo.sh")

	Convey("I have a running binary.Modifier that answers each token with its own identity", t, func() {

		m, err := New("fixtures/modifier-echo.sh", hash, conf.MongoConf{MongoURL: "mongodb://127.0.0.1"})
		So(err, ShouldBeNil)
		m.encoding = elemental.EncodingTypeJSON

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		So(m.Run(ctx), ShouldBeNil)
		time.Sleep(time.Second)

		Convey("When 50 tokens are written at the same time", func() {

			const n = 50
			type result struct {
				identity []string
				err      error
			}
			results := make([]result, n)

			var wg sync.WaitGroup
			for i := range n {
				wg.Go(func() {
					idt := &token.IdentityToken{Identity: []string{fmt.Sprintf("n=%d", i)}}
					nidt, err := m.Write(context.Background(), idt, "iss")
					if err != nil {
						results[i] = result{err: err}
						return
					}
					results[i] = result{identity: nidt.Identity}
				})
			}
			wg.Wait()

			Convey("Then each caller gets the answer to its own token", func() {
				for i, r := range results {
					So(r.err, ShouldBeNil)
					So(r.identity, ShouldResemble, []string{fmt.Sprintf("n=%d", i), "m=m"})
				}
			})
		})

		Convey("When the answer to a token comes after the modifier stopped waiting", func() {

			slow, err := m.Write(context.Background(), &token.IdentityToken{Identity: []string{"slow=slow"}}, "iss")
			So(err, ShouldBeNil)

			// Let the late answer arrive before the next write.
			time.Sleep(time.Second)

			next, err := m.Write(context.Background(), &token.IdentityToken{Identity: []string{"n=next"}}, "iss")

			Convey("Then that token is returned unmodified", func() {
				So(slow.Identity, ShouldResemble, []string{"slow=slow"})
			})

			Convey("Then the next token gets its own answer, not the late one", func() {
				So(err, ShouldBeNil)
				So(next.Identity, ShouldResemble, []string{"n=next", "m=m"})
			})
		})
	})
}
