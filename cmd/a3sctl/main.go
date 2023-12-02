package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"strings"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.acuvity.ai/a3s/cmd/a3sctl/internal/compcmd"
	"go.acuvity.ai/a3s/cmd/a3sctl/internal/help"
	"go.acuvity.ai/a3s/pkgs/api"
	"go.acuvity.ai/a3s/pkgs/bootstrap"
	"go.acuvity.ai/a3s/pkgs/cli/authcmd"
	"go.acuvity.ai/a3s/pkgs/cli/importcmd"
	"go.acuvity.ai/a3s/pkgs/conf"
	"go.acuvity.ai/manipulate"
	"go.acuvity.ai/manipulate/manipcli"
	"go.acuvity.ai/manipulate/maniphttp"
)

var (
	cfgFile  string
	cfgName  string
	logLevel string
)

var (
	version = "v0.0.0"
	commit  = "dev"
)

func main() {

	cobra.OnInitialize(initCobra)

	rootCmd := &cobra.Command{
		Use:              "a3sctl",
		Short:            "Controls a3s APIs",
		Long:             help.Load("a3sctl"),
		SilenceUsage:     true,
		SilenceErrors:    true,
		TraverseChildren: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := viper.BindPFlags(cmd.PersistentFlags()); err != nil {
				return err
			}

			return viper.BindPFlags(cmd.Flags())
		},
		Run: func(cmd *cobra.Command, args []string) {
			if viper.GetBool("version") {
				fmt.Printf("a3sctl %s (%s)", version, commit)
				os.Exit(0)
			}
		},
	}
	mflags := manipcli.ManipulatorFlagSet()
	_ = mflags.MarkHidden("tracking-id")
	mmaker := manipcli.ManipulatorMakerFromFlags(
		maniphttp.OptionDefaultRetryFunc(
			func(r manipulate.RetryInfo) error {
				slog.Debug("manipulate retrying", r.Err())
				return nil
			},
		),
	)

	rootCmd.PersistentFlags().Bool("version", false, "show version")
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: $HOME/.config/a3sctl/default.yaml)")
	rootCmd.PersistentFlags().StringVar(&cfgName, "config-name", "", "default config name (default: default)")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "warn", "Log level. Can be debug, info, warn or error")

	apiCmd := manipcli.New(api.Manager(), mmaker, manipcli.OptionArgumentsPrefix("with"))
	apiCmd.PersistentFlags().AddFlagSet(mflags)
	apiCmd.PersistentFlags().AddFlagSet(authcmd.MakeAutoAuthFlags())
	apiCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if err := rootCmd.PersistentPreRunE(cmd, args); err != nil {
			return err
		}
		if err := authcmd.HandleAutoAuth(
			mmaker,
			viper.GetString("auto-auth-method"),
			nil,
			nil,
			viper.GetBool("refresh"),
			viper.GetBool("renew-cached-token"),
		); err != nil {
			return fmt.Errorf("auto auth error: %w", err)
		}
		return nil
	}

	authCmd := authcmd.New(mmaker, help.Load("auth"), nil)
	authCmd.PersistentFlags().AddFlagSet(mflags)

	importCmd := importcmd.MakeImportCmd(mmaker)
	importCmd.PersistentFlags().AddFlagSet(mflags)

	compCmd := compcmd.New()

	rootCmd.AddCommand(
		apiCmd,
		authCmd,
		importCmd,
		compCmd,
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}

func initCobra() {

	viper.SetEnvPrefix("a3sctl")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	bootstrap.ConfigureLogger("a3sctl", conf.LoggingConf{
		LogLevel:  logLevel,
		LogFormat: "console",
	})

	home, err := homedir.Dir()
	if err != nil {
		slog.Error("unable to find home dir", err)
		os.Exit(1)
	}

	configPath := path.Join(home, ".config", "a3sctl")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := os.Mkdir(configPath, os.ModePerm); err != nil {
			slog.Error("unable to create config folder",
				"path", configPath,
				err,
			)
			os.Exit(1)
		}
	}

	if cfgFile == "" {
		cfgFile = os.Getenv("A3SCTL_CONFIG")
	}

	if cfgFile != "" {
		if _, err := os.Stat(cfgFile); os.IsNotExist(err) {
			slog.Error("config file does not exist", err)
			os.Exit(1)
		}

		viper.SetConfigType("yaml")
		viper.SetConfigFile(cfgFile)

		if err = viper.ReadInConfig(); err != nil {
			slog.Error("unable to read config",
				"path", cfgFile,
				err,
			)
			os.Exit(1)
		}

		slog.Debug("using config file", "path", cfgFile)
		return
	}

	viper.AddConfigPath(configPath)
	viper.AddConfigPath("/usr/local/etc/a3sctl")
	viper.AddConfigPath("/etc/a3sctl")

	if cfgName == "" {
		cfgName = os.Getenv("A3SCTL_CONFIG_NAME")
	}

	if cfgName == "" {
		cfgName = "default"
	}

	viper.SetConfigName(cfgName)

	if err = viper.ReadInConfig(); err != nil {
		if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
			slog.Error("unable to read config", err)
			os.Exit(1)
		}
	}

	slog.Debug("using config name", "name", cfgName)
}
