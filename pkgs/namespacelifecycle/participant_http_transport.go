package namespacelifecycle

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

func (p *HTTPParticipants) post(ctx context.Context, namespace string, body []byte) ([]byte, error) {
	if p == nil || ctx == nil || len(body) == 0 || len(body) > participantHTTPMaxBytes {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	bearer, err := p.token(ctx)
	if err != nil || bearer == "" || len(bearer) > participantHTTPMaxBytes || strings.ContainsAny(bearer, " \t\r\n") || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	// No rewind callback or idempotency header: no transport POST replay.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, io.NopCloser(bytes.NewReader(body)))
	if err != nil {
		return nil, ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("X-Namespace", namespace)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	if (resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated) || resp.ContentLength > participantHTTPMaxBytes {
		return nil, ErrPending
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, participantHTTPMaxBytes+1))
	if err != nil || len(data) > participantHTTPMaxBytes || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	return data, nil
}
