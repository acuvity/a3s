//go:build integration

package mongofixture

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"go.acuvity.ai/a3s/internal/hasher"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/sharder"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/manipmongo"
)

// New follows the pinned manipmongo integration fixture's New/CRUD
// pattern. Its _test.go helper is not importable and can use external endpoints;
// this fixture deliberately accepts neither a URI nor a shared data directory.
// Missing mongod is a failure, never a skipped qualification.
func New(t *testing.T) manipulate.Manipulator {
	t.Helper()
	binary, err := exec.LookPath("mongod")
	if err != nil {
		t.Fatalf("owned Mongo qualification requires mongod on PATH: %v", err)
	}
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	if err := os.Mkdir(data, 0700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "mongod.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logFile.Close() })

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	// The port reservation has a handoff gap. Do not connect until THIS child's
	// private log confirms it bound successfully; a collision fails closed.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, binary,
		"--bind_ip", "127.0.0.1", "--port", strconv.Itoa(port),
		"--nounixsocket", "--dbpath", data, "--wiredTigerCacheSizeGB", "0.25",
		"--setParameter", "diagnosticDataCollectionEnabled=false")
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start owned mongod: %v", err)
	}
	exited := make(chan struct{})
	var exitErr error
	go func() {
		exitErr = cmd.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		select {
		case <-exited:
			t.Errorf("owned mongod exited before cleanup: %v", exitErr)
		default:
			if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Errorf("stop owned mongod: %v", err)
			}
			select {
			case <-exited:
				if exitErr != nil {
					t.Errorf("owned mongod shutdown: %v", exitErr)
				}
			case <-time.After(10 * time.Second):
				_ = cmd.Process.Kill() // Only the process spawned above.
				<-exited
				t.Error("owned mongod required forced shutdown")
			}
		}
		if t.Failed() {
			logs, _ := os.ReadFile(logPath)
			if len(logs) > 12000 {
				logs = logs[len(logs)-12000:]
			}
			t.Logf("owned mongod log tail:\n%s", logs)
		}
	})
	t.Logf("owned mongod pid=%d endpoint=127.0.0.1:%d dbpath=%s", cmd.Process.Pid, port, data)
	deadline := time.Now().Add(20 * time.Second)
	for {
		select {
		case <-exited:
			t.Fatalf("owned mongod exited during startup: %v", exitErr)
		default:
		}
		logs, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(logs, []byte(`"msg":"Waiting for connections"`)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("owned mongod readiness timed out; log:\n%s", logs)
		}
		time.Sleep(25 * time.Millisecond)
	}
	m, err := manipmongo.New(fmt.Sprintf("mongodb://127.0.0.1:%d/?directConnection=true&retryWrites=false", port), "namespace_lifecycle_qualification",
		manipmongo.OptionSharder(sharder.New(&hasher.Hasher{})),
		manipmongo.OptionTranslateKeysFromModelManager(api.Manager()),
		manipmongo.OptionConnectionTimeout(5*time.Second),
		manipmongo.OptionSocketTimeout(5*time.Second),
		manipmongo.OptionDefaultReadConsistencyMode(manipulate.ReadConsistencyStrong),
		manipmongo.OptionDefaultWriteConsistencyMode(manipulate.WriteConsistencyStrong))
	if err != nil {
		t.Fatalf("connect to owned mongod: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := manipmongo.Disconnect(m, ctx); err != nil {
			t.Errorf("disconnect owned Mongo client: %v", err)
		}
	})
	if err := m.(interface{ Ping(time.Duration) error }).Ping(5 * time.Second); err != nil {
		t.Fatalf("ping owned mongod: %v", err)
	}
	return m
}
