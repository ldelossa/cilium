package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/hubble/cmd"
	"github.com/cilium/cilium/hubble/cmd/common/config"
	"github.com/cilium/cilium/hubble/cmd/common/template"
)

func New() *cobra.Command {
	vp := config.NewViper()
	rootCmd := cmd.NewWithViper(vp)
	if err := runCommandPlugins(rootCmd, vp); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	// Re-initialize registered template commands, as we just added some
	template.Initialize()
	return rootCmd
}

func Execute() {
	rootCmd := New()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
