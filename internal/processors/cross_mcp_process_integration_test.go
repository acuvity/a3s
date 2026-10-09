//go:build integration

package processors

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type crossMCPPeer struct {
	URL, ControlURL, Nonce string
	PID                    int
}

// Only these two fixed test binaries/entrypoints may be launched. Reuse owned
// process/nonce/private-file lifecycle, not a general executable/plugin harness.
func (f *crossFixture) startMCPPeer(binary, role, mode, hanniURL, nonce string) crossMCPPeer {
	f.t.Helper()
	if nonce == "" {
		raw := make([]byte, 24)
		_, err := rand.Read(raw)
		crossMust(f.t, err)
		nonce = hex.EncodeToString(raw)
	}
	var test, readyName string
	switch role {
	case "hanni":
		test = "TestCrossMCPA3SHanniHelper"
		readyName = "hanni-a3s-ready.json"
	case "torii":
		test = "TestCrossMCPA3SToriiHelper"
		readyName = "torii-a3s-ready.json"
	default:
		f.t.Fatal("unknown fixed peer")
	}
	configPath := filepath.Join(f.dir, role+"-mcp-config.json")
	var config []byte
	if role == "hanni" {
		config, _ = json.Marshal(struct{ Dir, OwnerURL, Nonce, Mode string }{f.dir, f.server.URL, nonce, mode})
	} else {
		config, _ = json.Marshal(struct{ Dir, OwnerURL, HanniURL, Nonce, Mode string }{f.dir, f.server.URL, hanniURL, nonce, mode})
	}
	crossMust(f.t, os.WriteFile(configPath, config, 0600))
	logPath := filepath.Join(f.dir, role+"-mcp.log")
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY, 0600)
	crossMust(f.t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 125*time.Second)
	command := exec.CommandContext(ctx, binary, "-test.run=^"+test+"$", "-test.v", "-test.timeout=130s")
	command.Env = append(os.Environ(), "CROSS_MCP_A3S_CONFIG="+configPath, "TMPDIR="+f.dir)
	command.Stdout, command.Stderr = log, log
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 20 * time.Second
	crossMust(f.t, command.Start())
	exited := make(chan struct{})
	var exitErr error
	go func() { exitErr = command.Wait(); close(exited) }()
	f.t.Cleanup(func() {
		select {
		case <-exited:
			f.t.Errorf("owned MCP peer exited before cleanup: %v", exitErr)
		default:
			if err := command.Process.Signal(os.Interrupt); err != nil {
				f.t.Error(err)
			}
			select {
			case <-exited:
				if exitErr != nil {
					f.t.Error(exitErr)
				}
			case <-time.After(25 * time.Second):
				_ = command.Process.Kill()
				<-exited
				f.t.Error("owned MCP peer required forced shutdown")
			}
		}
		cancel()
		_ = log.Close()
		raw, _ := os.ReadFile(logPath)
		if len(raw) > 18000 {
			raw = raw[len(raw)-18000:]
		}
		f.t.Logf("owned %s MCP peer pid%d reaped:\n%s", role, command.Process.Pid, raw)
	})
	deadline := time.Now().Add(30 * time.Second)
	for {
		select {
		case <-exited:
			f.t.Fatalf("owned MCP peer startup failed: %v", exitErr)
		default:
		}
		path := filepath.Join(f.dir, readyName)
		if stat, err := os.Stat(path); err == nil {
			if !stat.Mode().IsRegular() || stat.Mode().Perm() != 0600 || stat.Size() > 64*1024 {
				f.t.Fatal("invalid peer readiness file")
			}
			data, err := os.ReadFile(path)
			crossMust(f.t, err)
			var ready crossMCPPeer
			crossMust(f.t, json.Unmarshal(data, &ready))
			valid := func(raw string) bool {
				u, err := url.Parse(raw)
				return err == nil && u.Scheme == "http" && u.User == nil && u.Path == "" && u.RawQuery == "" && net.ParseIP(u.Hostname()).IsLoopback()
			}
			if ready.Nonce != nonce || ready.PID != command.Process.Pid || !valid(ready.URL) || (role == "torii" && !valid(ready.ControlURL)) {
				f.t.Fatal("peer ownership mismatch")
			}
			return ready
		}
		if time.Now().After(deadline) {
			f.t.Fatal("MCP peer readiness timeout")
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (f *crossFixture) mcpControl(peer crossMCPPeer, method, path string, out any) {
	f.t.Helper()
	endpoint := peer.ControlURL
	if endpoint == "" {
		endpoint = peer.URL
	}
	r, err := http.NewRequestWithContext(f.ctx, method, endpoint+path, nil)
	crossMust(f.t, err)
	r.Header.Set("X-Cross-Nonce", peer.Nonce)
	response, err := (&http.Client{Timeout: 15 * time.Second}).Do(r)
	crossMust(f.t, err)
	defer func() { _ = response.Body.Close() }()
	if method == http.MethodPost {
		if response.StatusCode != 204 {
			f.t.Fatalf("MCP control %s status%d", path, response.StatusCode)
		}
		return
	}
	if response.StatusCode != 200 {
		f.t.Fatalf("MCP status %s status%d", path, response.StatusCode)
	}
	crossMust(f.t, json.NewDecoder(http.MaxBytesReader(nil, response.Body, 64*1024)).Decode(out))
}
