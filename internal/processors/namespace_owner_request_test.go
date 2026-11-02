package processors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
)

func TestOwnerNamespaceRequestDistinguishesEmptySchemaQuery(t *testing.T) {
	for _, query := range []string{"", "?q=", "?q=name%3D%3Downed", "?recursive=true", "?unknown=value"} {
		t.Run(query, func(t *testing.T) {
			h := httptest.NewRequest(http.MethodDelete, "http://127.0.0.1/namespaces/111111111111111111111111"+query, nil)
			h.Header.Set("X-Namespace", "/")
			r, err := elemental.NewRequestFromHTTPRequest(h, api.Manager())
			if err != nil {
				if query == "" {
					t.Fatal(err)
				}
				return
			}
			err = ownerNamespaceRequest(bahamut.NewContext(context.Background(), r))
			if query == "" && err != nil {
				t.Fatalf("default empty schema parameter rejected: %v parameters=%v", err, r.Parameters)
			}
			if query != "" && err == nil {
				t.Fatal("caller query options accepted")
			}
		})
	}
}
