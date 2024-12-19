package claims

import (
	"reflect"
	"slices"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestMap(t *testing.T) {

	Convey("Given I have a claim map", t, func() {

		cmap := Map{}

		cmap.Set("a", "b")
		So(cmap["a"], ShouldResemble, []string{"b"})
		So(cmap.Get("a"), ShouldEqual, "b")

		cmap.Add("a", "c")
		So(cmap["a"], ShouldResemble, []string{"b", "c"})
		So(cmap.Get("a"), ShouldEqual, "b")

		cmap.Set("a", "d")
		So(cmap["a"], ShouldResemble, []string{"d"})
		So(cmap.Get("a"), ShouldEqual, "d")

		cmap.Add("a", "b")
		cmap.Add("test", "value")
		cmap.Add("hello", "world", "monde")

		claims := cmap.ToClaims()
		slices.Sort(claims)
		So(claims, ShouldResemble, []string{
			"a=b",
			"a=d",
			"hello=monde",
			"hello=world",
			"test=value",
		})
	})
}

type filter struct {
	included []string
	ignored  []string
}

func (f filter) GetIncludedKeys() []string { return f.included }
func (f filter) GetIgnoredKeys() []string  { return f.ignored }

func TestFilter(t *testing.T) {
	type args struct {
		claims []string
		filter Filterable
	}
	tests := []struct {
		name string
		args func(t *testing.T) args

		want1 []string
	}{
		{
			"nothing",
			func(*testing.T) args {
				return args{
					claims: []string{"a=a", "b=b", "b=c", "d=d"},
				}
			},
			[]string{"a=a", "b=b", "b=c", "d=d"},
		},
		{
			"excluded partial",
			func(*testing.T) args {
				return args{
					[]string{"a=a", "b=b", "b=c", "d=d"},
					filter{ignored: []string{"b="}},
				}
			},
			[]string{"a=a", "d=d"},
		},
		{
			"excluded full",
			func(*testing.T) args {
				return args{
					[]string{"a=a", "b=b", "b=c", "d=d"},
					filter{ignored: []string{"b=c"}},
				}
			},
			[]string{"a=a", "b=b", "d=d"},
		},
		{
			"included partial",
			func(*testing.T) args {
				return args{
					[]string{"a=a", "b=b", "b=c", "d=d"},
					filter{included: []string{"b="}},
				}
			},
			[]string{"b=b", "b=c"},
		},
		{
			"included full",
			func(*testing.T) args {
				return args{
					[]string{"a=a", "b=b", "b=c", "d=d"},
					filter{included: []string{"b=c"}},
				}
			},
			[]string{"b=c"},
		},
		{
			"mixed full",
			func(*testing.T) args {
				return args{
					[]string{"a=a", "b=b", "b=c", "b=d", "d=d"},
					filter{
						included: []string{"b="},
						ignored:  []string{"b=c"},
					},
				}
			},
			[]string{"b=b", "b=d"},
		},
		{
			"excluded and included",
			func(*testing.T) args {
				return args{
					[]string{"a=a", "b=b", "b=c", "b=d", "d=d"},
					filter{
						included: []string{"b="},
						ignored:  []string{"b="},
					},
				}
			},
			[]string{},
		},
		{
			"included and excluded",
			func(*testing.T) args {
				return args{
					[]string{"a=a", "b=b", "b=c", "b=d", "d=d"},
					filter{
						included: []string{"b="},
						ignored:  []string{"b=b"},
					},
				}
			},
			[]string{"b=c", "b=d"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tArgs := tt.args(t)

			got1 := Filter(tArgs.claims, tArgs.filter)

			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("Filter got1 = %v, want1: %v", got1, tt.want1)
			}
		})
	}
}
