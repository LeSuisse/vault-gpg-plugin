// +build tools

package main

import (
	_ "honnef.co/go/tools/cmd/staticcheck"
	_ "github.com/securego/gosec/cmd/gosec"
)