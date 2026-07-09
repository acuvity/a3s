// Copyright 2026 Proofpoint Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lombric

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// marshalRedacted exercises the recursive redaction logic against purpose-built
// fixtures, mirroring what RedactedJSON does.
func marshalRedacted(v any) ([]byte, error) {
	return json.Marshal(redact(reflect.ValueOf(v)))
}

func toMap(t *testing.T, b []byte) map[string]any {
	t.Helper()
	m := map[string]any{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("result is not a JSON object: %v (%s)", err, b)
	}
	return m
}

func TestRedact_TopLevelSecret(t *testing.T) {

	type s struct {
		Public string `mapstructure:"public"`
		Secret string `mapstructure:"secret" secret:"true"`
	}

	b, err := marshalRedacted(s{Public: "visible", Secret: "s3cr3t"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := toMap(t, b)
	if m["public"] != "visible" {
		t.Errorf("public field mangled: got %v", m["public"])
	}
	if m["secret"] != redactedValue {
		t.Errorf("secret not redacted: got %v", m["secret"])
	}
}

func TestRedact_NestedStruct(t *testing.T) {

	type inner struct {
		Token string `mapstructure:"token" secret:"true"`
		Keep  int    `mapstructure:"keep"`
	}
	type outer struct {
		Inner inner `mapstructure:"inner"`
	}

	b, err := marshalRedacted(outer{Inner: inner{Token: "abc", Keep: 42}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := toMap(t, b)
	in, ok := m["inner"].(map[string]any)
	if !ok {
		t.Fatalf("inner not an object: %v", m["inner"])
	}
	if in["token"] != redactedValue {
		t.Errorf("nested secret not redacted: got %v", in["token"])
	}
	if in["keep"] != float64(42) {
		t.Errorf("nested non-secret mangled: got %v", in["keep"])
	}
}

func TestRedact_SquashInlining(t *testing.T) {

	type embedded struct {
		EmbeddedSecret string `mapstructure:"embedded-secret" secret:"true"`
		EmbeddedPublic string `mapstructure:"embedded-public"`
	}
	type named struct {
		NamedSecret string `mapstructure:"named-secret" secret:"true"`
		NamedPublic string `mapstructure:"named-public"`
	}
	type outer struct {
		embedded `mapstructure:",squash"`
		Named    named  `mapstructure:",squash"`
		Own      string `mapstructure:"own"`
	}

	b, err := marshalRedacted(outer{
		embedded: embedded{EmbeddedSecret: "leak1", EmbeddedPublic: "ok1"},
		Named:    named{NamedSecret: "leak2", NamedPublic: "ok2"},
		Own:      "mine",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := toMap(t, b)

	// Squashed sub-structs (anonymous and named) must be inlined, not nested.
	if _, exists := m["Named"]; exists {
		t.Errorf("squashed named field should be inlined, not nested: %v", m)
	}
	if _, exists := m["embedded"]; exists {
		t.Errorf("squashed embed should be inlined, not nested: %v", m)
	}

	if m["embedded-secret"] != redactedValue {
		t.Errorf("embedded secret not redacted: got %v", m["embedded-secret"])
	}
	if m["embedded-public"] != "ok1" {
		t.Errorf("embedded public mangled: got %v", m["embedded-public"])
	}
	if m["named-secret"] != redactedValue {
		t.Errorf("named-squashed secret not redacted: got %v", m["named-secret"])
	}
	if m["named-public"] != "ok2" {
		t.Errorf("named-squashed public mangled: got %v", m["named-public"])
	}
	if m["own"] != "mine" {
		t.Errorf("own field mangled: got %v", m["own"])
	}
	if strings.Contains(string(b), "leak") {
		t.Errorf("cleartext secret leaked: %s", b)
	}
}

func TestRedact_PointerFields(t *testing.T) {

	type inner struct {
		Pass string `mapstructure:"pass" secret:"true"`
	}
	type outer struct {
		In     *inner  `mapstructure:"in"`
		Nilptr *inner  `mapstructure:"nilptr"`
		Sptr   *string `mapstructure:"sptr" secret:"true"`
	}

	secret := "hunter2"
	b, err := marshalRedacted(outer{In: &inner{Pass: "pw"}, Sptr: &secret})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := toMap(t, b)
	in, ok := m["in"].(map[string]any)
	if !ok {
		t.Fatalf("in not an object: %v", m["in"])
	}
	if in["pass"] != redactedValue {
		t.Errorf("secret through pointer not redacted: got %v", in["pass"])
	}
	if m["nilptr"] != nil {
		t.Errorf("nil pointer should marshal to null: got %v", m["nilptr"])
	}
	// A secret pointer field is redacted wholesale, never dereferenced.
	if m["sptr"] != redactedValue {
		t.Errorf("secret pointer not redacted: got %v", m["sptr"])
	}
}

func TestRedact_SliceAndMapOfStructs(t *testing.T) {

	type item struct {
		Key string `mapstructure:"key" secret:"true"`
		ID  int    `mapstructure:"id"`
	}
	type outer struct {
		Items []item          `mapstructure:"items"`
		ByKey map[string]item `mapstructure:"by-key"`
	}

	b, err := marshalRedacted(outer{
		Items: []item{{Key: "k1", ID: 1}, {Key: "k2", ID: 2}},
		ByKey: map[string]item{"a": {Key: "k3", ID: 3}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := toMap(t, b)

	items, ok := m["items"].([]any)
	if !ok || len(items) != 2 {
		t.Fatalf("items not a 2-element array: %v", m["items"])
	}
	for i, raw := range items {
		it := raw.(map[string]any)
		if it["key"] != redactedValue {
			t.Errorf("items[%d] secret not redacted: got %v", i, it["key"])
		}
		if it["id"] != float64(i+1) {
			t.Errorf("items[%d] id mangled: got %v", i, it["id"])
		}
	}

	byKey := m["by-key"].(map[string]any)
	if byKey["a"].(map[string]any)["key"] != redactedValue {
		t.Errorf("map value secret not redacted: got %v", byKey["a"])
	}
}

func TestRedact_DeeplyNestedSecret(t *testing.T) {

	type l3 struct {
		Deep string `mapstructure:"deep" secret:"true"`
	}
	type l2 struct {
		L3 *l3 `mapstructure:"l3"`
	}
	type l1 struct {
		L2 []l2 `mapstructure:"l2"`
	}

	b, err := marshalRedacted(l1{L2: []l2{{L3: &l3{Deep: "buried"}}}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := toMap(t, b)
	deep := m["l2"].([]any)[0].(map[string]any)["l3"].(map[string]any)["deep"]
	if deep != redactedValue {
		t.Errorf("deeply nested secret not redacted: got %v", deep)
	}
	if strings.Contains(string(b), "buried") {
		t.Errorf("cleartext secret leaked: %s", b)
	}
}

func TestRedact_NonStringSecretRedactedAsString(t *testing.T) {

	type s struct {
		Numbers []int `mapstructure:"numbers" secret:"true"`
		Count   int   `mapstructure:"count" secret:"true"`
	}

	b, err := marshalRedacted(s{Numbers: []int{1, 2, 3}, Count: 99})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := toMap(t, b)
	// Regardless of the field's underlying type, a secret becomes the string
	// placeholder.
	if m["numbers"] != redactedValue {
		t.Errorf("non-string (slice) secret not redacted: got %v", m["numbers"])
	}
	if m["count"] != redactedValue {
		t.Errorf("non-string (int) secret not redacted: got %v", m["count"])
	}
}

func TestRedact_SelfMarshalingTypePreserved(t *testing.T) {

	type s struct {
		When   time.Time `mapstructure:"when"`
		Secret string    `mapstructure:"secret" secret:"true"`
	}

	ts := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	b, err := marshalRedacted(s{When: ts, Secret: "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := toMap(t, b)
	// time.Time must keep its RFC3339 representation, not be decomposed into its
	// unexported wall/ext/loc fields.
	if m["when"] != ts.Format(time.RFC3339) {
		t.Errorf("time.Time not preserved: got %v", m["when"])
	}
	if m["secret"] != redactedValue {
		t.Errorf("secret alongside marshaler not redacted: got %v", m["secret"])
	}
}

func TestRedact_MapstructureTagOptions(t *testing.T) {

	type s struct {
		Renamed  string `mapstructure:"renamed-field"`
		Skipped  string `mapstructure:"-"`
		Omitted  string `mapstructure:"omitted,omitempty"`
		Present  string `mapstructure:"present,omitempty"`
		Untagged string // no mapstructure tag: not a config key
		private  string //nolint:unused // exercises unexported field skipping
	}

	b, err := marshalRedacted(s{
		Renamed:  "r",
		Skipped:  "should-not-appear",
		Present:  "here",
		Untagged: "internal-state",
		private:  "x",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := toMap(t, b)
	if m["renamed-field"] != "r" {
		t.Errorf("mapstructure rename not honored: %v", m)
	}
	if _, ok := m["Skipped"]; ok {
		t.Errorf("mapstructure:\"-\" field should be skipped: %v", m)
	}
	if _, ok := m["omitted"]; ok {
		t.Errorf("empty omitempty field should be omitted: %v", m)
	}
	if m["present"] != "here" {
		t.Errorf("non-empty omitempty field should be present: %v", m)
	}
	if _, ok := m["Untagged"]; ok {
		t.Errorf("field without mapstructure tag should be skipped: %v", m)
	}
	if _, ok := m["private"]; ok {
		t.Errorf("unexported field should be skipped: %v", m)
	}
}

func TestRedact_EdgeKinds(t *testing.T) {

	type s struct {
		NilSlice []string       `mapstructure:"nil-slice"`
		NilMap   map[string]int `mapstructure:"nil-map"`
		Bytes    []byte         `mapstructure:"bytes"`
		Arr      [2]int         `mapstructure:"arr"`
		Iface    any            `mapstructure:"iface"`
	}

	b, err := marshalRedacted(s{Bytes: []byte("hi"), Arr: [2]int{7, 8}, Iface: "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := toMap(t, b)
	if m["nil-slice"] != nil {
		t.Errorf("nil slice should marshal to null: got %v", m["nil-slice"])
	}
	if m["nil-map"] != nil {
		t.Errorf("nil map should marshal to null: got %v", m["nil-map"])
	}
	// []byte marshals to base64, same as encoding/json ("hi" -> "aGk=").
	if m["bytes"] != "aGk=" {
		t.Errorf("[]byte should be base64: got %v", m["bytes"])
	}
	arr, ok := m["arr"].([]any)
	if !ok || len(arr) != 2 || arr[0] != float64(7) || arr[1] != float64(8) {
		t.Errorf("array mangled: got %v", m["arr"])
	}
	if m["iface"] != "x" {
		t.Errorf("interface field mangled: got %v", m["iface"])
	}
}

// jwtConf mirrors the shape of a real lombric sub-configuration squashed into a
// parent (e.g. a3s' JWTConf), carrying a secret field.
type jwtConf struct {
	JWTIssuer  string `mapstructure:"jwt-issuer"`
	JWTKeyPass string `mapstructure:"jwt-key-pass" secret:"true" file:"true"`
}

// realishConf mimics a lombric top-level Conf: flat mapstructure leaves plus a
// squashed sub-configuration.
type realishConf struct {
	APIURL   string  `mapstructure:"api-url"`
	APIToken string  `mapstructure:"api-token" secret:"true" file:"true"`
	JWT      jwtConf `mapstructure:",squash"`
}

// TestRedactedJSON_RealishConf verifies the public entry point produces a flat,
// mapstructure-keyed object with every secret redacted and no cleartext leak.
func TestRedactedJSON_RealishConf(t *testing.T) {

	c := &realishConf{
		APIURL:   "https://api.example.com",
		APIToken: "SENTINEL-api-token",
		JWT: jwtConf{
			JWTIssuer:  "https://issuer.example.com",
			JWTKeyPass: "SENTINEL-jwt-key-pass",
		},
	}

	b, err := RedactedJSON(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := string(b)
	for _, sentinel := range []string{"SENTINEL-api-token", "SENTINEL-jwt-key-pass"} {
		if strings.Contains(out, sentinel) {
			t.Errorf("cleartext secret %q leaked into output: %s", sentinel, out)
		}
	}

	m := toMap(t, b)

	// Squashed sub-config keys are promoted to the top level (flat key space).
	if _, ok := m["JWT"]; ok {
		t.Errorf("squashed JWT sub-config should be inlined, not nested: %v", m)
	}

	if m["api-token"] != redactedValue {
		t.Errorf("expected api-token to be redacted: got %v", m["api-token"])
	}
	if m["jwt-key-pass"] != redactedValue {
		t.Errorf("expected squashed jwt-key-pass to be redacted: got %v", m["jwt-key-pass"])
	}
	if m["api-url"] != "https://api.example.com" {
		t.Errorf("non-secret api-url should be preserved: got %v", m["api-url"])
	}
	if m["jwt-issuer"] != "https://issuer.example.com" {
		t.Errorf("non-secret jwt-issuer should be preserved: got %v", m["jwt-issuer"])
	}
}
