package authcmd

import (
	"context"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.acuvity.ai/a3s/pkgs/authlib"
	"go.acuvity.ai/a3s/pkgs/permissions"
	"go.acuvity.ai/a3s/pkgs/token"
	"go.acuvity.ai/manipulate/manipcli"
)

func makeEntraCmd(mmaker manipcli.ManipulatorMaker, restrictions *permissions.Restrictions) *cobra.Command {

	cmd := &cobra.Command{
		Use:              "entra",
		Short:            "Use an Entra access token obtained for the A3S Entra API application.",
		TraverseChildren: true,
		RunE: func(cmd *cobra.Command, args []string) error {

			fToken := viper.GetString("access-token")
			fSourceName := viper.GetString("source-name")
			fSourceNamespace := viper.GetString("source-namespace")
			fAudience := viper.GetStringSlice("audience")
			fCloak := viper.GetStringSlice("cloak")
			fQRCode := viper.GetBool("qrcode")
			fCheck := viper.GetBool("check")
			fValidity := viper.GetDuration("validity")
			fRefresh := viper.GetBool("refresh")

			if fSourceNamespace == "" {
				fSourceNamespace = viper.GetString("namespace")
			}

			m, err := mmaker()
			if err != nil {
				return err
			}

			client := authlib.NewClient(m)
			t, err := client.AuthFromEntra(
				context.Background(),
				fToken,
				fSourceNamespace,
				fSourceName,
				authlib.OptAudience(fAudience...),
				authlib.OptCloak(fCloak...),
				authlib.OptRestrictions(*restrictions),
				authlib.OptValidity(fValidity),
				authlib.OptRefresh(fRefresh),
			)
			if err != nil {
				return err
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

	cmd.Flags().String("access-token", "", "Valid Entra access token.")
	cmd.Flags().String("source-name", "default", "The name of the auth source.")
	cmd.Flags().String("source-namespace", "", "The namespace of the auth source. If omitted, uses --namespace.")

	return cmd
}
