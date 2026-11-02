//go:build integration

package processors

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"go.acuvity.ai/a3s/pkgs/namespacelifecycle"
)

type crossHelper struct{ URL, Nonce string }
type crossStatus struct {
	Count, Inserts int64
	Registry       *struct {
		ID, NamespaceName                 string
		Revision, Issued, TerminalThrough int64
		Enrollment                        struct {
			OperationID string                             `json:"operationID"`
			Digest      string                             `json:"digest"`
			Scope       namespacelifecycle.EnrollmentScope `json:"scope"`
		}
	}
}

func (f *crossFixture) startHelper(binary string) crossHelper {
	f.t.Helper()
	nonceBytes := make([]byte, 24)
	_, err := rand.Read(nonceBytes)
	crossMust(f.t, err)
	nonce := hex.EncodeToString(nonceBytes)
	config, _ := json.Marshal(struct{ Dir, OwnerURL, Nonce string }{f.dir, f.server.URL, nonce})
	configPath := filepath.Join(f.dir, "helper.json")
	crossMust(f.t, os.WriteFile(configPath, config, 0600))
	logPath := filepath.Join(f.dir, "helper.log")
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY, 0600)
	crossMust(f.t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	cmd := exec.CommandContext(ctx, binary, "-test.run=^TestCrossEnrollmentHelper$", "-test.v", "-test.timeout=130s")
	cmd.Env = append(os.Environ(), "CROSS_ENROLLMENT_CONFIG="+configPath, "TMPDIR="+f.dir)
	cmd.Stdout, cmd.Stderr = log, log
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 20 * time.Second
	crossMust(f.t, cmd.Start())
	exited := make(chan struct{})
	var exitErr error
	go func() { exitErr = cmd.Wait(); close(exited) }()
	f.t.Cleanup(func() {
		select {
		case <-exited:
			f.t.Errorf("helper exited before cleanup: %v", exitErr)
		default:
			if err := cmd.Process.Signal(os.Interrupt); err != nil {
				f.t.Error(err)
			}
			select {
			case <-exited:
				if exitErr != nil {
					f.t.Errorf("helper shutdown: %v", exitErr)
				}
			case <-time.After(25 * time.Second):
				_ = cmd.Process.Kill() // Only this owned test process.
				<-exited
				f.t.Error("helper required forced shutdown")
			}
		}
		cancel()
		_ = log.Close()
		data, _ := os.ReadFile(logPath)
		if len(data) > 24000 {
			data = data[len(data)-24000:]
		}
		f.t.Logf("owned helper pid=%d reaped; output:\n%s", cmd.Process.Pid, data)
	})
	deadline := time.NewTimer(25 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-f.ctx.Done():
			f.t.Fatal("owner context ended before readiness")
		case <-exited:
			f.t.Fatalf("helper startup failed: %v", exitErr)
		case <-deadline.C:
			f.t.Fatal("helper nonce readiness timed out")
		case <-tick.C:
			data, err := os.ReadFile(filepath.Join(f.dir, "ready.json"))
			if os.IsNotExist(err) {
				continue
			}
			crossMust(f.t, err)
			var ready struct {
				URL, Nonce string
				PID        int
			}
			crossMust(f.t, json.Unmarshal(data, &ready))
			u, err := url.Parse(ready.URL)
			crossMust(f.t, err)
			ip := net.ParseIP(u.Hostname())
			if ready.Nonce != nonce || ready.PID != cmd.Process.Pid || u.Scheme != "http" || ip == nil || !ip.IsLoopback() || u.Path != "" || u.RawQuery != "" || u.User != nil {
				f.t.Fatal("unowned readiness")
			}
			f.t.Logf("nonce readiness verified for owned helper pid=%d", ready.PID)
			return crossHelper{ready.URL, nonce}
		}
	}
}

func (f *crossFixture) control(h crossHelper, method, path, namespace, id string) crossStatus {
	f.t.Helper()
	r, err := http.NewRequestWithContext(f.ctx, method, h.URL+path, nil)
	crossMust(f.t, err)
	r.Header.Set("X-Cross-Nonce", h.Nonce)
	r.Header.Set("X-Namespace", namespace)
	r.Header.Set("X-Registry-ID", id)
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(r)
	crossMust(f.t, err)
	defer response.Body.Close() //nolint:errcheck
	if method == http.MethodPost {
		if response.StatusCode != 204 {
			body, _ := io.ReadAll(io.LimitReader(response.Body, 32768))
			f.t.Fatalf("owned helper action %s status=%d body=%s", path, response.StatusCode, body)
		}
		return crossStatus{}
	}
	if response.StatusCode != 200 {
		f.t.Fatalf("owned status=%d", response.StatusCode)
	}
	var status crossStatus
	crossMust(f.t, json.NewDecoder(io.LimitReader(response.Body, 32768)).Decode(&status))
	return status
}
