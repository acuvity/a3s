package binary

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"time"

	"github.com/fatih/structs"
	"go.acuvity.ai/a3s/pkgs/conf"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/elemental"
)

// A Request represents the data
// structure use to send a request to a
// running BinaryModifier.
type Request struct {
	Token  *token.IdentityToken `json:"token" msgpack:"token"`
	Issuer string               `json:"issue" msgpack:"issuer"`
}

// A Response represents the data
// structure use to send as a response to a
// ModifierRequest.
type Response struct {
	Token *token.IdentityToken `json:"token" msgpack:"token"`
	Error string               `json:"error" msgpack:"error"`
}

func computeHash(path string) (string, error) {

	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("unable to read binary modifier: %w", err)
	}
	defer f.Close() // nolint

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("unable to compute sha256 of the binary modifier: %w", err)
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// A Modifier is a token modifier that is backed
// by a binary. The binary will be passed standard
// [conf.MongoConf] flags if it needs to connect.
// The communication happens using [Request] and [Response].
// Encoding of Requests and Responses must be iun msgpack.
// through the stdin/stderr of the modifier.
// Requests will be sent to the binary's stdin and
// and Response will be read from stdout.
// If the binary writes to stderr, the content
// will be logged by a3s.
type Modifier struct {
	stdin    chan []byte
	stdout   chan []byte
	stderr   chan []byte
	cmd      *exec.Cmd
	path     string
	args     []string
	encoding elemental.EncodingType
	hash     string
}

// New returns a new Modifier.
func New(path string, hash string, c conf.MongoConf) (*Modifier, error) {

	if hash == "" {
		return nil, fmt.Errorf("missing hash")
	}

	sum, err := computeHash(path)
	if err != nil {
		return nil, err
	}

	if sum != hash {
		return nil, fmt.Errorf("hash mismatch: want: %s got: %s", hash, sum)
	}

	args := []string{}

	for _, f := range structs.Fields(c) {
		if f.IsZero() {
			continue
		}
		args = append(args, "--"+f.Tag("mapstructure"), fmt.Sprintf("%v", f.Value()))
	}

	return &Modifier{
		args:     args,
		path:     path,
		stdin:    make(chan []byte, 64),
		stdout:   make(chan []byte, 64),
		stderr:   make(chan []byte, 64),
		encoding: elemental.EncodingTypeMSGPACK,
		hash:     hash,
	}, nil
}

// Run starts the modifier.
func (b *Modifier) Run(ctx context.Context) error {

	b.cmd = exec.CommandContext(ctx, b.path, b.args...)

	stdin, err := b.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("unable to get stdin: %w", err)
	}

	stdout, err := b.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("unable to get stdout: %w", err)
	}

	stderr, err := b.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("unable to get stderr: %w", err)
	}

	go func() {

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {

			data := scanner.Bytes()
			slog.Debug("Binary modifier: scanned stdout", "data", string(data))

			select {
			case b.stdout <- data:
			default:
				slog.Error("Unable to read stdout from plugin modifier")
			}
		}
	}()

	go func() {

		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {

			data := scanner.Bytes()
			slog.Debug("Binary modifier: message from plugin", "data", string(data))

			select {
			case b.stderr <- data:
			default:
				slog.Error("Unable to read stderr from plugin modifier")
			}
		}
	}()

	go func() {

		for {
			select {
			case in := <-b.stdin:

				slog.Debug("Binary modifier: sending in stdin", "data", string(in))

				if _, err := stdin.Write(append(in, '\n')); err != nil {
					slog.Error("Unable to send data to plugin modifier", err)
				}

			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		if err := b.cmd.Run(); err != nil {
			slog.Error("modifier binary exited", err)
		}
	}()

	return nil
}

// Write sends the token and the issuer to the running binary.
func (b *Modifier) Write(ctx context.Context, idt *token.IdentityToken, issuer string) (*token.IdentityToken, error) {

	data, err := elemental.Encode(b.encoding, Request{Token: idt, Issuer: issuer})
	if err != nil {
		return nil, fmt.Errorf("unable to encode idt: %w", err)
	}

	select {
	case b.stdin <- data:
	default:
		return nil, fmt.Errorf("unable to send idt to binary modifier: queue full")
	}

	subctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	select {
	case data := <-b.stdout:
		response := Response{}
		if err := elemental.Decode(b.encoding, data, &response); err != nil {
			return nil, fmt.Errorf("unable to decode modifier output '%s': %w", string(data), err)
		}
		if response.Error != "" {
			return nil, fmt.Errorf("binary modifier: error from binary: %s", response.Error)
		}
		return response.Token, nil

	case <-subctx.Done():
		return idt, nil
	}
}
