// SPDX-License-Identifier: BSD-2-Clause
// Provenance-includes-location: https://github.com/crewjam/saml/blob/a32b643a25a46182499b1278293e265150056d89/logger/logger.go
// Provenance-includes-license: BSD-2-Clause
// Provenance-includes-copyright: 2015-2023 Ross Kinder

// Package logger provides a logging interface.
package logger

import (
	"log"
	"os"
)

// Interface provides the minimal logging interface
type Interface interface {
	// Printf prints to the logger using the format.
	Printf(format string, v ...interface{})
	// Print prints to the logger.
	Print(v ...interface{})
	// Println prints new line.
	Println(v ...interface{})
	// Fatal is equivalent to Print() followed by a call to os.Exit(1).
	Fatal(v ...interface{})
	// Fatalf is equivalent to Printf() followed by a call to os.Exit(1).
	Fatalf(format string, v ...interface{})
	// Fatalln is equivalent to Println() followed by a call to os.Exit(1).
	Fatalln(v ...interface{})
	// Panic is equivalent to Print() followed by a call to panic().
	Panic(v ...interface{})
	// Panicf is equivalent to Printf() followed by a call to panic().
	Panicf(format string, v ...interface{})
	// Panicln is equivalent to Println() followed by a call to panic().
	Panicln(v ...interface{})
}

// DefaultLogger logs messages to os.Stdout
var DefaultLogger = log.New(os.Stdout, "", log.LstdFlags)
