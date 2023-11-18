// Package plugin defines the main interface for an A3S plugin.
// All plugins must implement the [plugin.Modifier] interface.
// The plugin must also have a function `func MakePlugin plugin.Modifier`.
// This function will be called to initialize the plugin.
//
// Here is an example of a plugin
//
//	package main
//
//	import (
//		"context"
//		"fmt"
//
//		"go.acuvity.ai/a3s/pkgs/plugin"
//		"go.acuvity.ai/a3s/pkgs/token"
//		"go.acuvity.ai/manipulate"
//	)
//
//	type PluginModifier struct {
//	}
//
//	func (p *PluginModifier) Token(ctx context.Context, m manipulate.Manipulator, idt *token.IdentityToken) (*token.IdentityToken, error) {
//		fmt.Println("hello world!")
//		return idt, nil
//	}
//
//	func MakePlugin() plugin.Modifier {
//		return &PluginModifier{}
//	}
package plugin

import (
	"context"

	"go.aporeto.io/a3s/pkgs/token"
	"go.aporeto.io/manipulate"
)

// A Modifier is the interface an A3S plugin
// must expose in order to be used in multiple
// places in the a3s code.
type Modifier interface {

	// Token will be called just before A3S returns a token.
	// This gives a chance to modify the token or take additional
	// action upon delivering a token.
	Token(context.Context, manipulate.Manipulator, *token.IdentityToken) (*token.IdentityToken, error)
}

// Maker is the type of the main entry point of a plugin.
// This function will be called
type Maker func() Modifier
