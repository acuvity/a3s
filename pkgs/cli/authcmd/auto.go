package authcmd

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"path"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.acuvity.ai/a3s/pkgs/cli/helpers"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/manipulate/manipcli"
)

func makeAutoCmd(mmaker manipcli.ManipulatorMaker) *cobra.Command {

	cmd := &cobra.Command{
		Use:              "auto",
		Short:            "Use config file auto auth and cache a token",
		TraverseChildren: true,
		RunE: func(cmd *cobra.Command, args []string) error {

			if viper.ConfigFileUsed() == "" {
				return fmt.Errorf("auto subcommand is available only when using a config file")
			}

			if err := HandleAutoAuth(
				mmaker,
				viper.GetString("auto-auth-method"),
				viper.GetStringSlice("audience"),
				viper.GetStringSlice("cloak"),
				viper.GetBool("refresh"),
				true,
			); err != nil {
				return err
			}

			fCheck := viper.GetBool("check")
			fQRCode := viper.GetBool("qrcode")
			fToken := viper.GetString("token")

			return token.Fprint(
				os.Stdout,
				fToken,
				token.PrintOptionDecoded(fCheck),
				token.PrintOptionQRCode(fQRCode),
				token.PrintOptionRaw(true),
			)
		},
	}

	cmd.Flags().Bool("check", false, "Display information about the token")

	cmd.Flags().AddFlagSet(MakeAutoAuthFlags())

	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		_ = cmd.Flags().MarkHidden("namespace")
		_ = cmd.Flags().MarkHidden("renew-cached-token")
		_ = cmd.Flags().MarkHidden("token")
		cmd.Parent().HelpFunc()(cmd, args)
	})

	return cmd
}

// HandleAutoAuth handles automatic retrieval of tokens based on
// the current config file.
// If will check for `autoauth.enable` to retrieve desired auto auth
// method. Setting it to empty will disable auto auth.
// Support:
//
// autoauth.enable: mtls
//
//	autoauth.mtls.cert: path to the client certificate
//	autoauth.mtls.key: path to the client certificate key
//	autoauth.mtls.pass: optional passphrase to the certificate.
//	autoauth.mtls.source.name: the name of the MTLS source to use.
//	autoauth.mtls.source.namespace: the namespace of the MTLS source to use.
//
// autoauth.enable: ldap
//
//	autoauth.ldap.user: the username.
//	autoauth.ldap.pass: the password.
//	autoauth.ldap.source.name: the name of the LDAP source to use.
//	autoauth.ldap.source.namespace: the namespace of the LDAP source to use.
//
// autoauth.enable: http
//
//	autoauth.http.user: the username.
//	autoauth.http.pass: the password.
//	autoauth.http.source.name: the name of the HTTP source to use.
//	autoauth.http.source.namespace: the namespace of the HTTP source to use.
//
// autoauth.enable: token
//
//	autoauth.token.path: if set, path to a file containing the token. superseeds autoauth.token.token
//	autoauth.token.token: the actual token to use. superseeded by autoauth.token.path
func HandleAutoAuth(
	mmaker manipcli.ManipulatorMaker,
	method string,
	overrideAudience []string,
	overrideCloak []string,
	refresh bool,
	renewCached bool,
) error {

	if viper.GetString("token") != "" {
		slog.Debug("autoauth: using --token")
		return nil
	}

	home, err := homedir.Dir()
	if err != nil {
		return fmt.Errorf("unable to find home dir: %w", err)
	}

	cache, ok := os.LookupEnv("XDG_HOME_CACHE")
	if ok {
		cache = path.Join(home, cache, viper.GetEnvPrefix())
	} else {
		cache = path.Join(home, ".cache", viper.GetEnvPrefix())
	}

	if _, err := os.Stat(cache); os.IsNotExist(err) {
		if err := os.MkdirAll(cache, 0700); err != nil {
			return fmt.Errorf("failed to create cache %s: %w", cache, err)
		}
	}

	if method == "" {
		method = viper.GetString("autoauth.enable")
	}

	// Here there is no renewal. The token can be used as is.
	if method == "token" {
		var data []byte
		if path := viper.GetString("autoauth.token.path"); path != "" {
			data, err = os.ReadFile(os.ExpandEnv(path))
			if err != nil {
				return fmt.Errorf("unable to read token file at '%s': %w", path, err)
			}
		} else {
			data = []byte(viper.GetString("autoauth.token.token"))
			if len(data) == 0 {
				return fmt.Errorf("empty token provided in autoauth.token.token")
			}
		}
		slog.Debug("autoauth: using token using autoauth.token")
		viper.Set("token", string(bytes.TrimSpace(data)))
		return nil
	}

	tokenCache := path.Join(cache, fmt.Sprintf("token-%s-%x", method, sha256.Sum256([]byte(viper.GetString("api")))))

	if renewCached {
		if err := os.Remove(tokenCache); err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	overrideIfNeeded := func(key string, override []string) []string {
		if override != nil {
			return override
		}
		return viper.GetStringSlice(key)
	}

	data, err := os.ReadFile(tokenCache)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}

		switch method {
		case "mtls", "MTLS":
			slog.Debug("autoauth: retrieving token using autoauth.mtls")
			t, err := GetMTLSToken(
				mmaker,
				os.ExpandEnv(viper.GetString("autoauth.mtls.cert")),
				os.ExpandEnv(viper.GetString("autoauth.mtls.key")),
				helpers.ReadFlag("passphrase: ", "autoauth.mtls.pass", true),
				viper.GetString("autoauth.mtls.source.namespace"),
				viper.GetString("autoauth.mtls.source.name"),
				overrideIfNeeded("autoauth.mtls.audience", overrideAudience),
				overrideIfNeeded("autoauth.mtls.cloak", overrideCloak),
				viper.GetDuration("validity"),
				refresh,
				nil,
			)
			if err != nil {
				return fmt.Errorf("unable to retrieve token from autoauth info: %w", err)
			}
			data = []byte(t)

		case "ldap", "LDAP":
			slog.Debug("autoauth: retrieving token using autoauth.ldap")
			t, err := GetLDAPToken(
				mmaker,
				helpers.ReadFlag("username: ", "autoauth.ldap.user", false),
				helpers.ReadFlag("password: ", "autoauth.ldap.pass", true),
				viper.GetString("autoauth.ldap.source.namespace"),
				viper.GetString("autoauth.ldap.source.name"),
				overrideIfNeeded("autoauth.ldap.audience", overrideAudience),
				overrideIfNeeded("autoauth.ldap.cloak", overrideCloak),
				viper.GetDuration("validity"),
				refresh,
				nil,
			)
			if err != nil {
				return fmt.Errorf("unable to retrieve token from autoauth info: %w", err)
			}
			data = []byte(t)

		case "http", "HTTP":
			slog.Debug("autoauth: retrieving token using autoauth.http")
			t, err := GetHTTPToken(
				mmaker,
				helpers.ReadFlag("username: ", "autoauth.http.user", false),
				helpers.ReadFlag("password: ", "autoauth.http.pass", true),
				"",
				viper.GetString("autoauth.http.source.namespace"),
				viper.GetString("autoauth.http.source.name"),
				overrideIfNeeded("autoauth.http.audience", overrideAudience),
				overrideIfNeeded("autoauth.http.cloak", overrideCloak),
				viper.GetDuration("validity"),
				refresh,
				nil,
			)
			if err != nil {
				return fmt.Errorf("unable to retrieve token from autoauth info: %w", err)
			}
			data = []byte(t)

		case "":
			return nil

		default:
			return fmt.Errorf("unsupported auto auth method: %s", method)
		}

		if err := os.WriteFile(tokenCache, data, 0600); err != nil {
			return fmt.Errorf("unable to write token cache: %w", err)
		}
		slog.Debug("autoauth: token cached",
			"path",
			tokenCache,
		)
	}

	idt := &token.IdentityToken{}
	p := &jwt.Parser{}
	if _, _, err := p.ParseUnverified(string(data), idt); err != nil {
		return fmt.Errorf("unable to parse cached token: %w", err)
	}

	if time.Until(idt.ExpiresAt.Time) <= time.Duration(idt.ExpiresAt.Unix()/2) {
		slog.Debug("autoauth: token about to expire. removing", "path", tokenCache)
		if err := os.Remove(tokenCache); err != nil {
			return fmt.Errorf("unable to clean currently cached token: %w", err)
		}
		return HandleAutoAuth(mmaker, method, overrideAudience, overrideCloak, refresh, false)
	}

	slog.Debug("autoauth: token set from cache", "path", tokenCache)
	viper.Set("token", string(data))

	return nil
}
