package token

import (
	"fmt"
	"io"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hokaccha/go-prettyjson"
	"github.com/mdp/qrterminal"
)

type printCfg struct {
	raw     bool
	decoded bool
	qrcode  bool
}

// PrintOption represents options that can be passed to token.Print
type PrintOption func(*printCfg)

// PrintOptionRaw sets the printer to
// print the raw token.
func PrintOptionRaw(enabled bool) PrintOption {
	return func(cfg *printCfg) {
		cfg.raw = enabled
	}
}

// PrintOptionDecoded prints the information
// contained in the token.
func PrintOptionDecoded(enabled bool) PrintOption {
	return func(cfg *printCfg) {
		cfg.decoded = enabled
	}
}

// PrintOptionQRCode prints the token as a QRCode.
func PrintOptionQRCode(enabled bool) PrintOption {
	return func(cfg *printCfg) {
		cfg.qrcode = enabled
	}
}

// Fprint prints the given token string using
// the methods passed as options in the given io.Writer.
// If you pass no option, this function is a noop
func Fprint(w io.Writer, token string, opts ...PrintOption) error {

	cfg := printCfg{}
	for _, o := range opts {
		o(&cfg)
	}

	var addLine bool

	if cfg.decoded {
		if err := printDecoded(w, token); err != nil {
			return err
		}
		addLine = true
	}

	if cfg.qrcode {
		if addLine {
			fmt.Fprintln(w) // nolint: errcheck
		}
		printQRCode(w, token)
		addLine = true
	}

	if cfg.raw {
		if addLine {
			fmt.Fprintln(w) // nolint: errcheck
		}
		printRaw(w, token)
	}

	return nil
}

func printDecoded(w io.Writer, token string) error {

	claims := jwt.MapClaims{}
	p := jwt.Parser{}

	t, _, err := p.ParseUnverified(token, &claims)
	if err != nil {
		return err
	}

	data, err := prettyjson.Marshal(claims)
	if err != nil {
		return err
	}

	fmt.Fprintln(w, "alg:", t.Method.Alg())  // nolint: errcheck
	fmt.Fprintln(w, "kid:", t.Header["kid"]) // nolint: errcheck
	if exp, ok := claims["exp"].(float64); ok {
		expt := time.Unix(int64(exp), 0)
		remaining := time.Until(expt)
		if remaining <= 0 {
			fmt.Fprintln(w, "exp: the token has expired", -remaining.Truncate(time.Second), "ago") // nolint: errcheck
		} else {
			fmt.Fprintf(w, "exp: %s (%s)\n", remaining.Truncate(time.Second), expt.Format(time.RFC3339)) // nolint: errcheck
		}
	}
	fmt.Fprintln(w, string(data)) // nolint: errcheck

	return nil
}

func printQRCode(w io.Writer, token string) {

	qrterminal.GenerateWithConfig(
		token,
		qrterminal.Config{
			Writer:         w,
			Level:          qrterminal.M,
			HalfBlocks:     true,
			QuietZone:      1,
			BlackChar:      qrterminal.BLACK_BLACK,
			WhiteBlackChar: qrterminal.WHITE_BLACK,
			WhiteChar:      qrterminal.WHITE_WHITE,
			BlackWhiteChar: qrterminal.BLACK_WHITE,
		},
	)
}

func printRaw(w io.Writer, token string) {
	fmt.Fprintln(w, token) // nolint: errcheck
}
