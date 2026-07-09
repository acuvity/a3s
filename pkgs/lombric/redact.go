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
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// redactedValue is the placeholder substituted for the value of any struct
// field tagged with `secret:"true"` when redacting via [Redact].
const redactedValue = "[REDACTED]"

var (
	jsonMarshalerType = reflect.TypeFor[json.Marshaler]()
	textMarshalerType = reflect.TypeFor[encoding.TextMarshaler]()
)

// Redact returns an encoder-neutral value tree (maps, slices and scalars)
// mirroring what an encoder such as encoding/json or a YAML marshaller would
// produce for conf, except that the value of every struct field carrying the
// `secret:"true"` struct tag is replaced by "[REDACTED]" (redactedValue).
//
// Object keys are taken from the `mapstructure` tag (the tag lombric already
// uses to bind flags and environment variables), so the redacted output reads
// with the same keys an operator sets on the command line or in the
// environment. Fields with no `mapstructure` tag (or `mapstructure:"-"`) are
// omitted, matching lombric's own notion of what is a configuration key.
// Sub-configurations inlined with `mapstructure:",squash"` are promoted into
// their parent, so the result is as flat as the flag namespace itself.
func Redact(conf Configurable) any {
	return redact(reflect.ValueOf(conf))
}

// RedactedJSON marshals the redacted tree returned by [Redact] to JSON.
func RedactedJSON(conf Configurable) ([]byte, error) {
	return json.Marshal(Redact(conf))
}

// redact converts v into a value tree (maps, slices and scalars) mirroring what
// an encoder would produce, with secret fields replaced by redactedValue.
func redact(v reflect.Value) any {

	if !v.IsValid() {
		return nil
	}

	switch v.Kind() {

	case reflect.Interface:
		if v.IsNil() {
			return nil
		}
		return redact(v.Elem())

	case reflect.Pointer:
		if v.IsNil() {
			return nil
		}
		// A pointer type may be the one implementing the marshaler interface;
		// preserve it before dereferencing.
		if implementsMarshaler(v.Type()) {
			return v.Interface()
		}
		return redact(v.Elem())
	}

	// Anything that knows how to marshal itself is emitted as-is. This both
	// preserves its intended representation (e.g. time.Time -> RFC3339 string)
	// and avoids reflecting into its unexported fields.
	if implementsMarshaler(v.Type()) || (v.CanAddr() && implementsMarshaler(reflect.PointerTo(v.Type()))) {
		return v.Interface()
	}

	switch v.Kind() {

	case reflect.Struct:
		out := map[string]any{}
		addStructFields(v, out)
		return out

	case reflect.Slice:
		if v.IsNil() {
			return nil
		}
		// []byte and named byte slices marshal to a base64 string in
		// encoding/json; keep that behaviour.
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return v.Interface()
		}
		fallthrough

	case reflect.Array:
		out := make([]any, v.Len())
		for i := 0; i < v.Len(); i++ {
			out[i] = redact(v.Index(i))
		}
		return out

	case reflect.Map:
		if v.IsNil() {
			return nil
		}
		out := make(map[string]any, v.Len())
		iter := v.MapRange()
		for iter.Next() {
			out[fmt.Sprint(iter.Key().Interface())] = redact(iter.Value())
		}
		return out

	default:
		return v.Interface()
	}
}

// addStructFields walks the fields of struct value v, adding each to out under
// its mapstructure name (redacting secrets), and inlining the fields of
// sub-structs tagged `mapstructure:",squash"` to match how lombric flattens
// embedded and named sub-configurations into a single flat key space.
func addStructFields(v reflect.Value, out map[string]any) {

	t := v.Type()

	for i := 0; i < t.NumField(); i++ {

		field := t.Field(i)

		// Unexported, non-embedded fields cannot be read and are never config
		// keys.
		if field.PkgPath != "" && !field.Anonymous {
			continue
		}

		name, squash, omitempty, skip := mapstructureName(field)
		if skip {
			continue
		}

		fv := v.Field(i)

		// Inline the fields of a squashed sub-struct into the parent, just like
		// lombric does when binding flags. Applies to both anonymous embeds and
		// named fields (e.g. `JWT JWTConf `mapstructure:",squash"``).
		if squash {
			ev := fv
			for ev.Kind() == reflect.Pointer {
				if ev.IsNil() {
					break
				}
				ev = ev.Elem()
			}
			if ev.Kind() == reflect.Struct && !implementsMarshaler(fv.Type()) {
				addStructFields(ev, out)
			}
			continue
		}

		if omitempty && isEmptyValue(fv) {
			continue
		}

		// Secrets are redacted regardless of their underlying type.
		if field.Tag.Get("secret") == "true" {
			out[name] = redactedValue
			continue
		}

		out[name] = redact(fv)
	}
}

// mapstructureName returns the object key for a struct field from its
// `mapstructure` tag, whether it is squashed into its parent, whether it
// carries the omitempty option, and whether it must be skipped entirely.
//
// A field with no `mapstructure` tag, or with `mapstructure:"-"`, is skipped:
// lombric does not treat such fields as configuration keys.
func mapstructureName(f reflect.StructField) (name string, squash bool, omitempty bool, skip bool) {

	tag, ok := f.Tag.Lookup("mapstructure")
	if !ok {
		return "", false, false, true
	}

	// A bare "-" means skip; "-," means a field literally named "-".
	if tag == "-" {
		return "", false, false, true
	}

	parts := strings.Split(tag, ",")
	name = parts[0]
	for _, opt := range parts[1:] {
		switch opt {
		case "squash":
			squash = true
		case "omitempty":
			omitempty = true
		}
	}

	// A non-squashed field with an empty name carries no key: nothing to emit.
	if name == "" && !squash {
		return "", false, false, true
	}

	return name, squash, omitempty, false
}

// implementsMarshaler reports whether t implements json.Marshaler or
// encoding.TextMarshaler.
func implementsMarshaler(t reflect.Type) bool {
	return t.Implements(jsonMarshalerType) || t.Implements(textMarshalerType)
}

// isEmptyValue mirrors encoding/json's notion of an empty value for omitempty.
func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Pointer:
		return v.IsNil()
	}
	return false
}
