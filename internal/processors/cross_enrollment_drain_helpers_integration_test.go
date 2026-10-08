//go:build integration

package processors

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/notification"
	"go.acuvity.ai/bahamut"
	"go.acuvity.ai/elemental"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type crossFence struct {
	DeletionIntentID string `json:"deletionIntentID"`
	NamespaceID      string `json:"namespaceID"`
	Namespace        string `json:"namespace"`
}

type crossDrainStatus struct {
	Registry struct {
		ID, NamespaceName                 string
		Revision, Issued, TerminalThrough int64
		Slot                              json.RawMessage
		DeletionFence                     *crossFence
	}
	Control struct {
		ID          string
		CASRevision int64
		Active      *struct {
			ID            string `json:"admissionID"`
			ReceiptID     string `json:"receiptID"`
			BindingDigest string `json:"bindingDigest"`
		}
		DeletionFence *crossFence
	}
	Receipt                                               struct{ PublicationKey, CommandDigest, Status, CanonicalFamily, CanonicalID, CanonicalEpisodeID string }
	ReceiptID, DispatchPhase, Snapshot                    string
	ControlCount, ReceiptCount, FindingCount, WriteChecks int64
}

func (f *crossFixture) publication(h crossHelper) crossDrainStatus {
	f.t.Helper()
	r, err := http.NewRequestWithContext(f.ctx, http.MethodGet, h.URL+"/_cross/publication/status", nil)
	crossMust(f.t, err)
	r.Header.Set("X-Cross-Nonce", h.Nonce)
	r.Header.Set("X-Namespace", "/drain")
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(r)
	crossMust(f.t, err)
	defer response.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(io.LimitReader(response.Body, 32769))
	crossMust(f.t, err)
	if response.StatusCode != 200 || len(body) > 32768 {
		f.t.Fatalf("publication status=%d body=%s", response.StatusCode, body)
	}
	var out crossDrainStatus
	crossMust(f.t, json.Unmarshal(body, &out))
	return out
}

// A local notification sink, never a cleaner. Once Create is complete it
// accepts ONLY Update invalidation; a destructive name-only Delete fails.
type crossUpdateSink struct {
	bahamut.PubSubClient
	t        *testing.T
	mu       sync.Mutex
	armed    bool
	updates  int
	dropNext bool
}

func (s *crossUpdateSink) Publish(p *bahamut.Publication, _ ...bahamut.PubSubOptPublish) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var message notification.Message
	if err := p.Decode(&message); err != nil {
		s.t.Error(err)
		return err
	}
	if !s.armed && message.Type == string(elemental.OperationCreate) {
		return nil
	}
	if message.Type != string(elemental.OperationUpdate) || message.Data != "/drain" {
		s.t.Errorf("unsafe namespace notification: %+v", message)
	} else {
		if s.dropNext {
			s.dropNext = false
			return errors.New("owned fixture lost invalidation")
		}
		s.updates++
	}
	return nil
}
func (s *crossUpdateSink) loseNext()  { s.mu.Lock(); defer s.mu.Unlock(); s.dropNext = true }
func (s *crossUpdateSink) arm()       { s.mu.Lock(); defer s.mu.Unlock(); s.armed = true }
func (s *crossUpdateSink) count() int { s.mu.Lock(); defer s.mu.Unlock(); return s.updates }

func (f *crossFixture) nativeDeletes() int64 {
	f.t.Helper()
	n, err := f.db.Collection("system.profile").CountDocuments(f.ctx, bson.M{"op": "remove", "ns": f.db.Name() + "." + api.NamespaceIdentity.Name})
	crossMust(f.t, err)
	return n
}

func (f *crossFixture) assertNoLegacyDeletion() {
	f.t.Helper()
	n, err := f.db.Collection(api.NamespaceDeletionRecordIdentity.Name).CountDocuments(f.ctx, bson.M{})
	crossMust(f.t, err)
	attempts, err := f.db.Collection("system.profile").CountDocuments(f.ctx, bson.M{"op": "insert", "ns": f.db.Name() + "." + api.NamespaceDeletionRecordIdentity.Name})
	crossMust(f.t, err)
	if n != 0 || attempts != 0 {
		f.t.Fatalf("legacy deletion records=%d insert attempts=%d", n, attempts)
	}
}
