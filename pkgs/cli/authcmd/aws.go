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

func makeAWSCmd(mmaker manipcli.ManipulatorMaker, restrictions *permissions.Restrictions) *cobra.Command {

	cmd := &cobra.Command{
		Use:              "aws",
		Short:            "Use an AWS identity token.",
		TraverseChildren: true,
		RunE: func(cmd *cobra.Command, args []string) error {

			fToken := viper.GetString("access-token")
			fAccessKeyID := viper.GetString("access-key-id")
			fSecretAccessKey := viper.GetString("access-key-secret")
			fAudience := viper.GetStringSlice("audience")
			fCloak := viper.GetStringSlice("cloak")
			fQRCode := viper.GetBool("qrcode")
			fCheck := viper.GetBool("check")
			fValidity := viper.GetDuration("validity")
			fRefresh := viper.GetBool("refresh")

			m, err := mmaker()
			if err != nil {
				return err
			}

			client := authlib.NewClient(m)
			t, err := client.AuthFromAWS(
				context.Background(),
				fAccessKeyID,
				fSecretAccessKey,
				fToken,
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

	cmd.Flags().String("access-token", "", "Valid AWS token.")
	cmd.Flags().String("access-key-id", "", "Access key ID for the token.")
	cmd.Flags().String("access-key-secret", "", "Secret for access key.")

	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		_ = cmd.Flags().MarkHidden("namespace")
		_ = cmd.Flags().MarkHidden("token")
		cmd.Parent().HelpFunc()(cmd, args)
	})

	return cmd
}
