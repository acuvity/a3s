package importcmd

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.acuvity.ai/elemental"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/manipcli"
)

// MakeImportCmd returns the import sub command.
func MakeImportCmd(mmaker manipcli.ManipulatorMaker, importMaker func() elemental.Identifiable) *cobra.Command {

	cmd := &cobra.Command{
		Use:              "import <path-or-url>",
		Short:            "Manage import files",
		TraverseChildren: true,
		Args:             cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			fFile := args[0]
			fAPI := viper.GetString("api")
			fNamespace := viper.GetString("namespace")
			fSet := viper.GetStringSlice("set")
			fValues := viper.GetString("values")
			fDelete := viper.GetBool("delete")
			fRender := viper.GetBool("render")

			var furl, ffile string
			if strings.HasPrefix(fFile, "http://") || strings.HasPrefix(fFile, "https://") {
				furl = fFile
			} else {
				ffile = fFile
			}

			data, err := manipcli.ReadData(
				fAPI,
				fNamespace,
				ffile,
				furl,
				fValues,
				fSet,
				false,
				true,
			)
			if err != nil {
				return err
			}

			if fRender {
				fmt.Println(string(data))
				return nil
			}

			importFile := importMaker()
			if err := yaml.Unmarshal(data, importFile); err != nil {
				return err
			}

			m, err := mmaker()
			if err != nil {
				return err
			}

			actionString := "imported"
			var opts []manipulate.ContextOption
			if fDelete {
				actionString = "deleted"
				opts = append(
					opts,
					manipulate.ContextOptionParameters(
						url.Values{
							"delete": []string{"true"},
						},
					),
				)
			}

			if err := m.Create(
				manipulate.NewContext(
					context.Background(),
					opts...,
				),
				importFile,
			); err != nil {
				return err
			}

			fmt.Fprintf(os.Stderr, "Successfully %s data in namespace %s\n", actionString, fNamespace) // nolint: errcheck

			return nil
		},
	}

	cmd.Flags().StringSliceP("set", "S", nil, "Set the value for one key in the template.")
	cmd.Flags().StringP("values", "V", "", "Path to a values file.")
	cmd.Flags().BoolP("delete", "D", false, "Delete the previously created data declared in the import file.")
	cmd.Flags().BoolP("render", "R", false, "Only renders the templated information locally.")

	return cmd
}
