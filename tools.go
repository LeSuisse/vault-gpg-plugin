//go:build tools
// +build tools

package main

import (
	_ "github.com/securego/gosec/cmd/gosec"
	_ "honnef.co/go/tools/cmd/staticcheck"
)
