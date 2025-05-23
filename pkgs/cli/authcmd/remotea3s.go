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

func makeRemoteA3SCmd(mmaker manipcli.ManipulatorMaker, restrictions *permissions.Restrictions) *cobra.Command {

	cmd := &cobra.Command{
		Use:              "remote-a3s",
		Short:            "Use a remote A3S identity token.",
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

			if fToken == "" {
				fToken = viper.GetString("token")
			}

			m, err := mmaker()
			if err != nil {
				return err
			}

			client := authlib.NewClient(m)
			t, err := client.AuthFromRemoteA3S(
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

	cmd.Flags().String("access-token", "", "Valid remote a3s token. If omitted, uses --token.")
	cmd.Flags().String("source-name", "default", "The name of the auth source.")
	cmd.Flags().String("source-namespace", "", "The namespace of the auth source. If omitted, uses --namespace.")

	return cmd
}
