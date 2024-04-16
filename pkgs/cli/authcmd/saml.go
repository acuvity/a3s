package authcmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/pkg/browser"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.acuvity.ai/a3s/pkgs/authlib"
	"go.acuvity.ai/a3s/pkgs/permissions"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/manipulate/manipcli"
)

type samlAuthData struct {
	code  string
	state string
}

func makeSAMLCmd(mmaker manipcli.ManipulatorMaker, restrictions *permissions.Restrictions) *cobra.Command {

	cmd := &cobra.Command{
		Use:   "saml",
		Short: "Authenticate using SAML source.",
		RunE: func(cmd *cobra.Command, args []string) error {

			fSourceName := viper.GetString("source-name")
			fSourceNamespace := viper.GetString("source-namespace")
			fAudience := viper.GetStringSlice("audience")
			fCloak := viper.GetStringSlice("cloak")
			fQRCode := viper.GetBool("qrcode")
			fCheck := viper.GetBool("check")
			fRefresh := viper.GetBool("refresh")

			if fSourceNamespace == "" {
				fSourceNamespace = viper.GetString("namespace")
			}

			srvCtx, srvCancel := context.WithCancel(context.Background())
			defer srvCancel()

			authDataCh := make(chan samlAuthData)

			go startSAMLCallbackServer(srvCtx, authDataCh)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			m, err := mmaker()
			if err != nil {
				return err
			}

			client := authlib.NewClient(m)
			url, err := client.AuthFromSAMLStep1(
				ctx,
				fSourceNamespace,
				fSourceName,
				"http://localhost:65333",
			)
			if err != nil {
				return fmt.Errorf("unable to perform first step of saml authentication: %w", err)
			}

			fmt.Fprintln(os.Stderr, "Trying to open your browser...")
			if err := browser.OpenURL(url); err != nil {
				fmt.Fprintln(os.Stderr, "Open this URL in your browser:", url)
			}

			authD := <-authDataCh
			srvCancel()

			t, err := client.AuthFromSAMLStep2(
				ctx,
				fSourceNamespace,
				fSourceName,
				authD.code,
				authD.state,
				authlib.OptAudience(fAudience...),
				authlib.OptCloak(fCloak...),
				authlib.OptRestrictions(*restrictions),
				authlib.OptRefresh(fRefresh),
			)
			if err != nil {
				return fmt.Errorf("unable to perform second step of saml authentication: %w", err)
			}

			return token.Fprint(
				os.Stdout,
				t,
				token.PrintOptionDecoded(fCheck),
				token.PrintOptionQRCode(fQRCode),
				token.PrintOptionRaw(true),
			)
		},
	}
	cmd.Flags().String("source-name", "default", "The name of the auth source.")
	cmd.Flags().String("source-namespace", "", "The namespace of the auth source. If omitted, uses --namespace.")

	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		_ = cmd.Flags().MarkHidden("token")
		cmd.Parent().HelpFunc()(cmd, args)
	})

	return cmd
}

func startSAMLCallbackServer(srvCtx context.Context, out chan samlAuthData) {

	mux := http.NewServeMux()
	mux.HandleFunc("/", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {

		switch req.Method {
		case http.MethodGet:
			out <- samlAuthData{
				code:  req.URL.Query().Get("SAMLResponse"),
				state: req.URL.Query().Get("RelayState"),
			}
		case http.MethodPost:
			out <- samlAuthData{
				code:  req.PostFormValue("SAMLResponse"),
				state: req.PostFormValue("RelayState"),
			}
		default:
			slog.Error("Invalid SAML response method", "method", req.Method)
			os.Exit(1)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`Authenticated. You can close this window`))
	}))

	server := &http.Server{
		Addr:    "localhost:65333",
		Handler: mux,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				slog.Error("Unable to start temporary webserver", err)
				os.Exit(1)
			}
		}
	}()

	<-srvCtx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_ = server.Shutdown(shutdownCtx) // nolint
}
