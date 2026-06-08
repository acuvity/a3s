package importing

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"github.com/spaolacci/murmur3"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/sharder"
	"go.acuvity.ai/elemental"
	testmodel "go.acuvity.ai/elemental/test/model"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/maniptest"
)

// testHasher is a sharder.Hasher that computes the zhash of an
// Authorization from its name only
type testHasher struct{}

func (testHasher) Zone(elemental.Identity) int { return 0 }

func (h testHasher) Hash(z sharder.Shardable) error {
	z.SetZone(h.Zone(z.Identity()))
	key := z.Identifier()
	switch a := z.(type) {
	case *api.Authorization:
		key = a.Name
	case *testmodel.List:
		key = a.Name
	}
	z.SetZHash(int(murmur3.Sum64([]byte(key)) & 0x7FFFFFFFFFFFFFFF)) // #nosec G115
	return nil
}

func TestImport(t *testing.T) {

	Convey("Given a manipulator", t, func() {

		m := maniptest.NewTestManipulator()
		_ = m

		Convey("When I call Import with missing label, it should error", func() {
			err := Import(
				context.Background(),
				api.Manager(),
				m,
				"",
				"",
				nil,
				false,
				false,
				nil,
			)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "namespace must not be empty")
		})

		Convey("When I call Import with missing namespace, it should error", func() {
			err := Import(
				context.Background(),
				api.Manager(),
				m,
				"ns",
				"",
				nil,
				false,
				false,
				nil,
			)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "label must not be empty")
		})

		Convey("When I pass a non Importable", func() {
			err := Import(
				context.Background(),
				api.Manager(),
				m,
				"ns",
				"label",
				api.NamespaceDeletionRecordsList{api.NewNamespaceDeletionRecord()},
				false,
				false,
				nil,
			)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "object 'namespacedeletionrecord[0]' is not importable")
		})

		Convey("When I pass a a list containing a nil manager", func() {
			err := Import(
				context.Background(),
				nil,
				m,
				"ns",
				"label",
				api.AuthorizationsList{nil},
				false,
				false,
				nil,
			)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "manager must not be nil")
		})

		Convey("When I import, but retrieve many returns an error", func() {
			{

				m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
					return fmt.Errorf("boom")
				})

				objs := api.AuthorizationsList{
					&api.Authorization{
						Name: "1",
					},
					&api.Authorization{
						Name:        "2",
						Description: "new",
					},
					&api.Authorization{
						Name: "4",
					},
				}

				err := Import(context.Background(), api.Manager(), m, "/ns", "label", objs, false, false, nil)
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "unable to retrieve list of current authorizations: boom")
			}
		})

		Convey("When I import a list of objects but delete returns an error", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				*dest.(*api.AuthorizationsList) = append(
					*dest.(*api.AuthorizationsList),
					&api.Authorization{
						ID:          "1",
						Name:        "1",
						ImportHash:  "3132303033343839333331383835343436343834e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						ImportLabel: "label",
					},
					&api.Authorization{
						ID:          "2",
						Name:        "2",
						ImportHash:  "3132363235373937303539373039393132333639e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						ImportLabel: "label",
					},
					&api.Authorization{
						ID:          "3",
						Name:        "3",
						ImportHash:  "3",
						ImportLabel: "label",
					},
				)
				return nil
			})

			m.MockDelete(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				return fmt.Errorf("paf")
			})

			objs := api.AuthorizationsList{
				&api.Authorization{
					Name: "1",
				},
				&api.Authorization{
					Name:        "2",
					Description: "new",
				},
				&api.Authorization{
					Name: "4",
				},
			}

			err := Import(context.Background(), api.Manager(), m, "/ns", "label", objs, false, false, nil)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "unable to delete existing authorization: paf")
		})

		Convey("When I import a list of objects but creates returns an error", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				*dest.(*api.AuthorizationsList) = append(
					*dest.(*api.AuthorizationsList),
					&api.Authorization{
						ID:          "1",
						Name:        "1",
						ImportHash:  "3132303033343839333331383835343436343834e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						ImportLabel: "label",
					},
					&api.Authorization{
						ID:          "2",
						Name:        "2",
						ImportHash:  "3132363235373937303539373039393132333639e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						ImportLabel: "label",
					},
					&api.Authorization{
						ID:          "3",
						Name:        "3",
						ImportHash:  "3",
						ImportLabel: "label",
					},
				)
				return nil
			})

			m.MockDelete(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				return nil
			})

			m.MockCreate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				return fmt.Errorf("bim")
			})

			objs := api.AuthorizationsList{
				&api.Authorization{
					Name: "1",
				},
				&api.Authorization{
					Name:        "2",
					Description: "new",
				},
				&api.Authorization{
					Name: "4",
				},
			}

			err := Import(context.Background(), api.Manager(), m, "/ns", "label", objs, false, false, nil)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "unable to create object 'authorization': bim")
		})

		Convey("When I import a list of objects and there are some existing", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				*dest.(*api.AuthorizationsList) = append(
					*dest.(*api.AuthorizationsList),
					&api.Authorization{
						ID:          "1",
						Name:        "1",
						ImportHash:  "3132383335303230383330363332323439343833e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						ImportLabel: "label",
					},
					&api.Authorization{
						ID:          "2",
						Name:        "2",
						ImportHash:  "3133353237363932393233333130393837353032e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						ImportLabel: "label",
					},
					&api.Authorization{
						ID:          "3",
						Name:        "3",
						ImportHash:  "3",
						ImportLabel: "label",
					},
				)
				return nil
			})

			// fmt.Println(Hash(&api.Authorization{
			// 	ID:          "2",
			// 	Name:        "2",
			// 	Namespace:   "/ns",
			// 	ImportHash:  "3132303033343839333331383835343436343834e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			// 	ImportLabel: "label",
			// }, api.Manager()))

			toDelete := elemental.IdentifiablesList{}
			m.MockDelete(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				// fmt.Println("delete ID:", object.Identifier(), "hash:", object.(Importable).GetImportHash())
				toDelete = append(toDelete, object)
				return nil
			})

			toCreate := elemental.IdentifiablesList{}
			m.MockCreate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				// fmt.Println("create ID:", object.Identifier(), "hash:", object.(Importable).GetImportHash())
				toCreate = append(toCreate, object)
				return nil
			})

			objs := api.AuthorizationsList{
				&api.Authorization{
					Name: "1",
				},
				&api.Authorization{
					Name:        "2",
					Description: "new",
				},
				&api.Authorization{
					Name: "4",
				},
			}

			err := Import(context.Background(), api.Manager(), m, "/ns", "label", objs, false, false, nil)
			So(err, ShouldBeNil)

			sort.Slice(toDelete, func(i, j int) bool {
				return strings.Compare(toDelete[i].(*api.Authorization).Name, toDelete[j].(*api.Authorization).Name) != 1
			})
			sort.Slice(toCreate, func(i, j int) bool {
				return strings.Compare(toCreate[i].(*api.Authorization).Name, toCreate[j].(*api.Authorization).Name) != 1
			})

			So(len(toDelete), ShouldEqual, 2)
			So(toDelete[0].(*api.Authorization).Name, ShouldEqual, "2")
			So(toDelete[1].(*api.Authorization).Name, ShouldEqual, "3")
			So(len(toCreate), ShouldEqual, 2)
			So(toCreate[0].(*api.Authorization).Name, ShouldEqual, "2")
			So(toCreate[1].(*api.Authorization).Name, ShouldEqual, "4")
		})

		Convey("When I import a list of objects with remove mode set to true", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				*dest.(*api.AuthorizationsList) = append(
					*dest.(*api.AuthorizationsList),
					&api.Authorization{
						ID:          "1",
						Name:        "1",
						ImportHash:  "3132383335303230383330363332323439343833e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						ImportLabel: "label",
					},
					&api.Authorization{
						ID:          "2",
						Name:        "2",
						ImportHash:  "3133353237363932393233333130393837353032e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						ImportLabel: "label",
					},
					&api.Authorization{
						ID:          "3",
						Name:        "3",
						ImportHash:  "3",
						ImportLabel: "label",
					},
				)
				return nil
			})

			toDelete := elemental.IdentifiablesList{}
			m.MockDelete(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				// fmt.Println("delete ID:", object.Identifier(), "hash:", object.(Importable).GetImportHash())
				toDelete = append(toDelete, object)
				return nil
			})

			toCreate := elemental.IdentifiablesList{}
			m.MockCreate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				// fmt.Println("create ID:", object.Identifier(), "hash:", object.(Importable).GetImportHash())
				toCreate = append(toCreate, object)
				return nil
			})

			objs := api.AuthorizationsList{
				&api.Authorization{
					Name: "1",
				},
				&api.Authorization{
					Name:        "2",
					Description: "new",
				},
				&api.Authorization{
					Name: "4",
				},
			}

			err := Import(context.Background(), api.Manager(), m, "/ns", "label", objs, true, false, nil)
			So(err, ShouldBeNil)

			sort.Slice(toDelete, func(i, j int) bool {
				return strings.Compare(toDelete[i].(*api.Authorization).Name, toDelete[j].(*api.Authorization).Name) != 1
			})
			sort.Slice(toCreate, func(i, j int) bool {
				return strings.Compare(toCreate[i].(*api.Authorization).Name, toCreate[j].(*api.Authorization).Name) != 1
			})

			So(len(toDelete), ShouldEqual, 3)
			So(toDelete[0].(*api.Authorization).Name, ShouldEqual, "1")
			So(toDelete[1].(*api.Authorization).Name, ShouldEqual, "2")
			So(toDelete[2].(*api.Authorization).Name, ShouldEqual, "3")
			So(len(toCreate), ShouldEqual, 0)
		})

		Convey("When I import a list of objects and there are some existing but they 404 on delete", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				*dest.(*api.AuthorizationsList) = append(
					*dest.(*api.AuthorizationsList),
					&api.Authorization{
						ID:          "1",
						Name:        "1",
						ImportHash:  "3132383335303230383330363332323439343833e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						ImportLabel: "label",
					},
					&api.Authorization{
						ID:          "2",
						Name:        "2",
						ImportHash:  "3133353237363932393233333130393837353032e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						ImportLabel: "label",
					},
					&api.Authorization{
						ID:          "3",
						Name:        "3",
						ImportHash:  "3",
						ImportLabel: "label",
					},
				)
				return nil
			})

			toDelete := elemental.IdentifiablesList{}
			m.MockDelete(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				return elemental.NewError("title", "desc", "sub", http.StatusNotFound)
			})

			toCreate := elemental.IdentifiablesList{}
			m.MockCreate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				toCreate = append(toCreate, object)
				return nil
			})

			objs := api.AuthorizationsList{
				&api.Authorization{
					Name: "1",
				},
				&api.Authorization{
					Name:        "2",
					Description: "new",
				},
				&api.Authorization{
					Name: "4",
				},
			}

			err := Import(context.Background(), api.Manager(), m, "/ns", "label", objs, false, false, nil)
			So(err, ShouldBeNil)

			sort.Slice(toDelete, func(i, j int) bool {
				return strings.Compare(toDelete[i].(*api.Authorization).Name, toDelete[j].(*api.Authorization).Name) != 1
			})
			sort.Slice(toCreate, func(i, j int) bool {
				return strings.Compare(toCreate[i].(*api.Authorization).Name, toCreate[j].(*api.Authorization).Name) != 1
			})

			So(len(toDelete), ShouldEqual, 0)
			So(len(toCreate), ShouldEqual, 2)
			So(toCreate[0].(*api.Authorization).Name, ShouldEqual, "2")
			So(toCreate[1].(*api.Authorization).Name, ShouldEqual, "4")
		})

		Convey("When I import a list of objects using subnamespace with bad relative ns format", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				*dest.(*api.AuthorizationsList) = append(
					*dest.(*api.AuthorizationsList),
					&api.Authorization{
						ID:          "1",
						Name:        "1",
						ImportHash:  "3132303033343839333331383835343436343834e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						ImportLabel: "label",
					},
					&api.Authorization{
						ID:          "2",
						Name:        "2",
						ImportHash:  "3132363235373937303539373039393132333639e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						ImportLabel: "label",
					},
					&api.Authorization{
						ID:          "3",
						Name:        "3",
						ImportHash:  "3",
						ImportLabel: "label",
					},
				)
				return nil
			})

			m.MockDelete(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				return nil
			})

			m.MockCreate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				return nil
			})

			objs := api.AuthorizationsList{
				&api.Authorization{
					Name: "1",
				},
				&api.Authorization{
					Name:        "2",
					Description: "new",
				},
				&api.Authorization{
					Namespace: "/not/a/relative/ns",
					Name:      "4",
				},
			}

			err := Import(context.Background(), api.Manager(), m, "/ns", "label", objs, false, false, nil)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "object '<Identity authorization|authorizations>[2] has a non relative namespace set: /not/a/relative/ns")
		})

		Convey("When I import a list of objects using subnamespace", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				*dest.(*api.AuthorizationsList) = append(
					*dest.(*api.AuthorizationsList),
					&api.Authorization{
						ID:          "1",
						Name:        "1",
						ImportHash:  "3132303033343839333331383835343436343834e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						ImportLabel: "label",
					},
					&api.Authorization{
						ID:          "2",
						Name:        "2",
						ImportHash:  "3132303033343839333331383835343436343834e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						ImportLabel: "label",
					},
				)
				return nil
			})

			var deleteNamespaces []string
			m.MockDelete(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				deleteNamespaces = append(deleteNamespaces, mctx.Namespace())
				return nil
			})

			var createNamespaces []string
			m.MockCreate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				createNamespaces = append(createNamespaces, mctx.Namespace())
				return nil
			})

			objs := api.AuthorizationsList{
				&api.Authorization{
					Name:        "1",
					Description: "new",
				},
				&api.Authorization{
					Name:      "2",
					Namespace: "./subns",
				},
			}

			slices.Sort(deleteNamespaces)
			slices.Sort(createNamespaces)

			err := Import(context.Background(), api.Manager(), m, "/ns", "label", objs, false, false, nil)
			So(err, ShouldBeNil)
			So(objs[1].Namespace, ShouldEqual, "")
			So(deleteNamespaces, ShouldResemble, []string{"", ""}) // empty means default manip namespace.
			So(len(createNamespaces), ShouldEqual, 2)
			So(createNamespaces, ShouldContain, "/ns")
			So(createNamespaces, ShouldContain, "/ns/subns")
		})

		Convey("When I import a list of objects using subnamespace relative to /", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				*dest.(*api.AuthorizationsList) = append(
					*dest.(*api.AuthorizationsList),
					&api.Authorization{
						ID:          "1",
						Name:        "1",
						ImportHash:  "3132303033343839333331383835343436343834e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						ImportLabel: "label",
					},
					&api.Authorization{
						ID:          "2",
						Name:        "2",
						ImportHash:  "3132303033343839333331383835343436343834e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						ImportLabel: "label",
					},
				)
				return nil
			})

			var deleteNamespaces []string
			m.MockDelete(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				deleteNamespaces = append(deleteNamespaces, mctx.Namespace())
				return nil
			})

			var createNamespaces []string
			m.MockCreate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				createNamespaces = append(createNamespaces, mctx.Namespace())
				return nil
			})

			objs := api.AuthorizationsList{
				&api.Authorization{
					Name:        "1",
					Description: "new",
				},
				&api.Authorization{
					Name:      "2",
					Namespace: "./subns",
				},
			}

			slices.Sort(deleteNamespaces)
			slices.Sort(createNamespaces)

			err := Import(context.Background(), api.Manager(), m, "/", "label", objs, false, false, nil)
			So(err, ShouldBeNil)
			So(objs[1].Namespace, ShouldEqual, "")
			So(deleteNamespaces, ShouldResemble, []string{"", ""}) // empty means default manip namespace.
			So(len(createNamespaces), ShouldEqual, 2)
			So(createNamespaces, ShouldContain, "/")
			So(createNamespaces, ShouldContain, "/subns")
		})

		// Update mode.

		Convey("When I call Import in update mode with missing label, it should error", func() {
			err := Import(
				context.Background(),
				api.Manager(),
				m,
				"",
				"",
				nil,
				false,
				true,
				testHasher{},
			)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "namespace must not be empty")
		})

		Convey("When I call Import in update mode with missing namespace, it should error", func() {
			err := Import(
				context.Background(),
				api.Manager(),
				m,
				"ns",
				"",
				nil,
				false,
				true,
				testHasher{},
			)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "label must not be empty")
		})

		Convey("When I pass a non Importable in update mode", func() {
			err := Import(
				context.Background(),
				api.Manager(),
				m,
				"ns",
				"label",
				api.NamespaceDeletionRecordsList{api.NewNamespaceDeletionRecord()},
				false,
				true,
				testHasher{},
			)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "object 'namespacedeletionrecord[0]' is not importable")
		})

		Convey("When I pass a a list containing a nil manager in update mode", func() {
			err := Import(
				context.Background(),
				nil,
				m,
				"ns",
				"label",
				api.AuthorizationsList{nil},
				false,
				true,
				testHasher{},
			)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "manager must not be nil")
		})

		Convey("When I import in update mode, but retrieve many returns an error", func() {
			{

				m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
					return fmt.Errorf("boom")
				})

				objs := api.AuthorizationsList{
					&api.Authorization{
						Name: "1",
					},
					&api.Authorization{
						Name:        "2",
						Description: "new",
					},
					&api.Authorization{
						Name: "4",
					},
				}

				err := Import(context.Background(), api.Manager(), m, "/ns", "label", objs, false, true, testHasher{})
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "unable to retrieve list of current authorizations: boom")
			}
		})

		Convey("When I import a list of objects in update mode but create returns an error", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				*dest.(*api.AuthorizationsList) = append(
					*dest.(*api.AuthorizationsList),
					&api.Authorization{
						ID:          "1",
						Name:        "1",
						ImportHash:  "3132303033343839333331383835343436343834e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						ImportLabel: "label",
					},
					&api.Authorization{
						ID:          "2",
						Name:        "2",
						ImportHash:  "3132363235373937303539373039393132333639e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						ImportLabel: "label",
					},
					&api.Authorization{
						ID:          "3",
						Name:        "3",
						ImportHash:  "3",
						ImportLabel: "label",
					},
				)
				return nil
			})

			m.MockDelete(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				return fmt.Errorf("paf")
			})

			objs := api.AuthorizationsList{
				&api.Authorization{
					Name: "1",
				},
				&api.Authorization{
					Name:        "2",
					Description: "new",
				},
				&api.Authorization{
					Name: "4",
				},
			}

			err := Import(context.Background(), api.Manager(), m, "/ns", "label", objs, false, true, testHasher{})
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "unable to update objects: unable to delete existing authorization: paf")
		})

		Convey("When I import a list of objects in update mode but update returns an error", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				*dest.(*api.AuthorizationsList) = append(
					*dest.(*api.AuthorizationsList),
					&api.Authorization{
						ID:          "1",
						Name:        "1",
						Namespace:   "/ns",
						ImportHash:  "stale",
						ImportLabel: "label",
					},
				)
				return nil
			})

			m.MockUpdate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				return fmt.Errorf("bam")
			})

			objs := api.AuthorizationsList{
				&api.Authorization{
					Name:        "1",
					Description: "changed",
				},
			}

			err := Import(context.Background(), api.Manager(), m, "/ns", "label", objs, false, true, testHasher{})
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "unable to update objects: unable to update authorization during import: bam")
		})

		Convey("When I import a list of objects in update mode and there are some existing", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				*dest.(*api.AuthorizationsList) = append(
					*dest.(*api.AuthorizationsList),
					// Name "1" exists at /ns with a stale hash, so it
					// must be updated in place.
					&api.Authorization{
						ID:          "1",
						Name:        "1",
						Namespace:   "/ns",
						ImportHash:  "stale",
						ImportLabel: "label",
					},
					// Name "2" exists at /ns with a stale hash, so it
					// must be updated in place.
					&api.Authorization{
						ID:          "2",
						Name:        "2",
						Namespace:   "/ns",
						ImportHash:  "stale",
						ImportLabel: "label",
					},
					// Name "3" exists but is not in the imported set, so
					// it must be deleted.
					&api.Authorization{
						ID:          "3",
						Name:        "3",
						Namespace:   "/ns",
						ImportHash:  "stale",
						ImportLabel: "label",
					},
				)
				return nil
			})

			toUpdate := elemental.IdentifiablesList{}
			m.MockUpdate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				toUpdate = append(toUpdate, object)
				return nil
			})

			toCreate := elemental.IdentifiablesList{}
			m.MockCreate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				toCreate = append(toCreate, object)
				return nil
			})

			toDelete := elemental.IdentifiablesList{}
			m.MockDelete(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				toDelete = append(toDelete, object)
				return nil
			})

			objs := api.AuthorizationsList{
				&api.Authorization{
					Name:        "1",
					Description: "new",
				},
				&api.Authorization{
					Name:        "2",
					Description: "new",
				},
				// Name "4" does not exist, so it must be created.
				&api.Authorization{
					Name: "4",
				},
			}

			err := Import(context.Background(), api.Manager(), m, "/ns", "label", objs, false, true, testHasher{})
			So(err, ShouldBeNil)

			sort.Slice(toUpdate, func(i, j int) bool {
				return strings.Compare(toUpdate[i].(*api.Authorization).Name, toUpdate[j].(*api.Authorization).Name) != 1
			})

			So(len(toUpdate), ShouldEqual, 2)
			So(toUpdate[0].(*api.Authorization).Name, ShouldEqual, "1")
			So(toUpdate[0].(*api.Authorization).ID, ShouldEqual, "1")
			So(toUpdate[1].(*api.Authorization).Name, ShouldEqual, "2")
			So(toUpdate[1].(*api.Authorization).ID, ShouldEqual, "2")
			So(len(toCreate), ShouldEqual, 1)
			So(toCreate[0].(*api.Authorization).Name, ShouldEqual, "4")
			So(len(toDelete), ShouldEqual, 1)
			So(toDelete[0].(*api.Authorization).Name, ShouldEqual, "3")
		})

		Convey("When I import a list of objects in update mode and they are unchanged", func() {

			existing := &api.Authorization{
				ID:          "1",
				Name:        "1",
				Namespace:   "/ns",
				ImportLabel: "label",
			}
			h, herr := Hash(existing, api.Manager())
			So(herr, ShouldBeNil)
			existing.ImportHash = h

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				*dest.(*api.AuthorizationsList) = append(
					*dest.(*api.AuthorizationsList),
					existing,
				)
				return nil
			})

			updated := false
			m.MockUpdate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				updated = true
				return nil
			})

			created := false
			m.MockCreate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				created = true
				return nil
			})

			objs := api.AuthorizationsList{
				&api.Authorization{
					Name: "1",
				},
			}

			err := Import(context.Background(), api.Manager(), m, "/ns", "label", objs, false, true, testHasher{})
			So(err, ShouldBeNil)
			So(updated, ShouldBeFalse)
			So(created, ShouldBeFalse)
		})

		Convey("When I import a list of objects in update mode where the existing object is dirty", func() {

			existing := &api.Authorization{
				ID:          "1",
				Name:        "1",
				Namespace:   "/ns",
				ImportLabel: "label",
			}
			h, herr := Hash(existing, api.Manager())
			So(herr, ShouldBeNil)
			// The stored hash is "dirty", forcing a rehash that ends
			// up matching the incoming object, so it is left untouched.
			existing.ImportHash = "dirty"
			_ = h

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				*dest.(*api.AuthorizationsList) = append(
					*dest.(*api.AuthorizationsList),
					existing,
				)
				return nil
			})

			updated := false
			m.MockUpdate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				updated = true
				return nil
			})

			created := false
			m.MockCreate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				created = true
				return nil
			})

			objs := api.AuthorizationsList{
				&api.Authorization{
					Name: "1",
				},
			}

			err := Import(context.Background(), api.Manager(), m, "/ns", "label", objs, false, true, testHasher{})
			So(err, ShouldBeNil)
			So(updated, ShouldBeFalse)
			So(created, ShouldBeFalse)
		})

		Convey("When I import a list of objects in update mode using subnamespace with bad relative ns format", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				return nil
			})

			m.MockCreate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				return nil
			})

			objs := api.AuthorizationsList{
				&api.Authorization{
					Name: "1",
				},
				&api.Authorization{
					Namespace: "/not/a/relative/ns",
					Name:      "4",
				},
			}

			err := Import(context.Background(), api.Manager(), m, "/ns", "label", objs, false, true, testHasher{})
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "object '<Identity authorization|authorizations>[1] has a non relative namespace set: /not/a/relative/ns")
		})

		Convey("When I import a list of objects in update mode using subnamespace", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				*dest.(*api.AuthorizationsList) = append(
					*dest.(*api.AuthorizationsList),
					&api.Authorization{
						ID:          "1",
						Name:        "1",
						ImportHash:  "3132303033343839333331383835343436343834e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						ImportLabel: "label",
					},
					&api.Authorization{
						ID:          "2",
						Name:        "2",
						ImportHash:  "3132303033343839333331383835343436343834e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						ImportLabel: "label",
					},
				)
				return nil
			})

			var deleteNamespaces []string
			m.MockDelete(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				deleteNamespaces = append(deleteNamespaces, mctx.Namespace())
				return nil
			})

			var createNamespaces []string
			m.MockCreate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				createNamespaces = append(createNamespaces, mctx.Namespace())
				return nil
			})

			objs := api.AuthorizationsList{
				&api.Authorization{
					Name:        "1",
					Description: "new",
				},
				&api.Authorization{
					Name:      "2",
					Namespace: "./subns",
				},
			}

			slices.Sort(deleteNamespaces)
			slices.Sort(createNamespaces)

			err := Import(context.Background(), api.Manager(), m, "/ns", "label", objs, false, true, testHasher{})
			So(err, ShouldBeNil)
			So(objs[1].Namespace, ShouldEqual, "")
			So(deleteNamespaces, ShouldResemble, []string{"", ""}) // empty means default manip namespace.
			So(len(createNamespaces), ShouldEqual, 2)
			So(createNamespaces, ShouldContain, "/ns")
			So(createNamespaces, ShouldContain, "/ns/subns")
		})

		Convey("When I import a list of objects in update mode using subnamespace relative to /", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				*dest.(*api.AuthorizationsList) = append(
					*dest.(*api.AuthorizationsList),
					&api.Authorization{
						ID:          "1",
						Name:        "1",
						ImportHash:  "3132303033343839333331383835343436343834e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						ImportLabel: "label",
					},
					&api.Authorization{
						ID:          "2",
						Name:        "2",
						ImportHash:  "3132303033343839333331383835343436343834e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						ImportLabel: "label",
					},
				)
				return nil
			})

			var deleteNamespaces []string
			m.MockDelete(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				deleteNamespaces = append(deleteNamespaces, mctx.Namespace())
				return nil
			})

			var createNamespaces []string
			m.MockCreate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				createNamespaces = append(createNamespaces, mctx.Namespace())
				return nil
			})

			objs := api.AuthorizationsList{
				&api.Authorization{
					Name:        "1",
					Description: "new",
				},
				&api.Authorization{
					Name:      "2",
					Namespace: "./subns",
				},
			}

			err := Import(context.Background(), api.Manager(), m, "/", "label", objs, false, true, testHasher{})
			So(err, ShouldBeNil)
			So(objs[1].Namespace, ShouldEqual, "")

			slices.Sort(deleteNamespaces)
			slices.Sort(createNamespaces)

			So(deleteNamespaces, ShouldResemble, []string{"", ""}) // empty means default manip namespace.
			So(len(createNamespaces), ShouldEqual, 2)
			So(createNamespaces, ShouldContain, "/")
			So(createNamespaces, ShouldContain, "/subns")
		})

		Convey("When I import a list of nested objects in update mode and the object does not exist, it should create", func() {

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				// Nothing exists yet.
				return nil
			})

			toCreate := elemental.IdentifiablesList{}
			m.MockCreate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				toCreate = append(toCreate, object)
				return nil
			})

			updated := false
			m.MockUpdate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				updated = true
				return nil
			})

			deleted := false
			m.MockDelete(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				deleted = true
				return nil
			})

			objs := testmodel.ListsList{
				&testmodel.List{
					Name: "1",
					RefList: testmodel.TasksList{
						{
							Name: "task1",
							SubtaskList: testmodel.SubtasksList{
								{Name: "sub1"},
							},
						},
					},
				},
			}

			err := Import(context.Background(), testmodel.Manager(), m, "/ns", "label", objs, false, true, testHasher{})
			So(err, ShouldBeNil)
			So(len(toCreate), ShouldEqual, 1)
			So(toCreate[0].(*testmodel.List).Name, ShouldEqual, "1")
			So(updated, ShouldBeFalse)
			So(deleted, ShouldBeFalse)
		})

		Convey("When I import a nested object in update mode and it is unchanged, it should skip", func() {

			existing := &testmodel.List{
				ID:          "1",
				Name:        "1",
				Namespace:   "/ns",
				ImportLabel: "label",
				RefList: testmodel.TasksList{
					{
						Name: "task1",
						SubtaskList: testmodel.SubtasksList{
							{Name: "sub1", ID: "id1"},
						},
					},
				},
			}
			h, herr := Hash(existing, testmodel.Manager())
			So(herr, ShouldBeNil)
			existing.ImportHash = h

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				*dest.(*testmodel.ListsList) = append(*dest.(*testmodel.ListsList), existing)
				return nil
			})

			updated := false
			m.MockUpdate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				updated = true
				return nil
			})
			created := false
			m.MockCreate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				created = true
				return nil
			})
			deleted := false
			m.MockDelete(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				deleted = true
				return nil
			})

			// Same content (same nested subtaskList) => same hash => skip.
			objs := testmodel.ListsList{
				&testmodel.List{
					Name: "1",
					RefList: testmodel.TasksList{
						{
							Name: "task1",
							SubtaskList: testmodel.SubtasksList{
								{Name: "sub1"},
							},
						},
					},
				},
			}

			err := Import(context.Background(), testmodel.Manager(), m, "/ns", "label", objs, false, true, testHasher{})
			So(err, ShouldBeNil)
			So(updated, ShouldBeFalse)
			So(created, ShouldBeFalse)
			So(deleted, ShouldBeFalse)
		})

		Convey("When I import a nested object in update mode and its nested refList changed, it should update", func() {

			existing := &testmodel.List{
				ID:          "1",
				Name:        "1",
				Namespace:   "/ns",
				ImportLabel: "label",
				RefList: testmodel.TasksList{
					{
						Name: "task1",
						SubtaskList: testmodel.SubtasksList{
							{Name: "sub1"},
						},
					},
				},
			}
			h, herr := Hash(existing, testmodel.Manager())
			So(herr, ShouldBeNil)
			existing.ImportHash = h

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				*dest.(*testmodel.ListsList) = append(*dest.(*testmodel.ListsList), existing)
				return nil
			})

			toUpdate := elemental.IdentifiablesList{}
			m.MockUpdate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				toUpdate = append(toUpdate, object)
				return nil
			})
			created := false
			m.MockCreate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				created = true
				return nil
			})
			deleted := false
			m.MockDelete(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				deleted = true
				return nil
			})

			// Same name (matches by zhash) but a different nested subtask
			// => different hash => in-place update.
			objs := testmodel.ListsList{
				&testmodel.List{
					Name: "1",
					RefList: testmodel.TasksList{
						{
							Name: "task1",
							SubtaskList: testmodel.SubtasksList{
								{Name: "sub1-changed"},
							},
						},
					},
				},
			}

			err := Import(context.Background(), testmodel.Manager(), m, "/ns", "label", objs, false, true, testHasher{})
			So(err, ShouldBeNil)
			So(len(toUpdate), ShouldEqual, 1)
			So(toUpdate[0].(*testmodel.List).Name, ShouldEqual, "1")
			So(toUpdate[0].(*testmodel.List).ID, ShouldEqual, "1")
			So(created, ShouldBeFalse)
			So(deleted, ShouldBeFalse)
		})

		Convey("When I import a nested object in update mode that resolves to a different namespace, it should delete and create", func() {

			existing := &testmodel.List{
				ID:          "1",
				Name:        "1",
				Namespace:   "/ns",
				ImportLabel: "label",
				RefList: testmodel.TasksList{
					{
						Name: "task1",
						SubtaskList: testmodel.SubtasksList{
							{Name: "sub1"},
						},
					},
				},
			}
			h, herr := Hash(existing, testmodel.Manager())
			So(herr, ShouldBeNil)
			existing.ImportHash = h

			m.MockRetrieveMany(t, func(mctx manipulate.Context, dest elemental.Identifiables) error {
				*dest.(*testmodel.ListsList) = append(*dest.(*testmodel.ListsList), existing)
				return nil
			})

			updated := false
			m.MockUpdate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				updated = true
				return nil
			})

			toCreate := elemental.IdentifiablesList{}
			var createNamespaces []string
			m.MockCreate(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				toCreate = append(toCreate, object)
				createNamespaces = append(createNamespaces, mctx.Namespace())
				return nil
			})

			toDelete := elemental.IdentifiablesList{}
			var deleteNamespaces []string
			m.MockDelete(t, func(mctx manipulate.Context, object elemental.Identifiable) error {
				toDelete = append(toDelete, object)
				deleteNamespaces = append(deleteNamespaces, mctx.Namespace())
				return nil
			})

			// Same name (matches by zhash) but resolves to a subnamespace,
			// so it cannot be updated in place: the existing one is deleted
			// and a new one is created in the new namespace.
			objs := testmodel.ListsList{
				&testmodel.List{
					Name:      "1",
					Namespace: "./subns",
					RefList: testmodel.TasksList{
						{
							Name: "task1",
							SubtaskList: testmodel.SubtasksList{
								{Name: "sub1"},
							},
						},
					},
				},
			}

			err := Import(context.Background(), testmodel.Manager(), m, "/ns", "label", objs, false, true, testHasher{})
			So(err, ShouldBeNil)
			So(updated, ShouldBeFalse)
			So(len(toDelete), ShouldEqual, 1)
			So(toDelete[0].(*testmodel.List).ID, ShouldEqual, "1")
			So(deleteNamespaces, ShouldResemble, []string{"/ns"})
			So(len(toCreate), ShouldEqual, 1)
			So(toCreate[0].(*testmodel.List).Name, ShouldEqual, "1")
			So(createNamespaces, ShouldResemble, []string{"/ns/subns"})
		})
	})

}
