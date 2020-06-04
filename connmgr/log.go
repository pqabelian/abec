// Copyright (c) 2020 The Abelian Foundation
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package connmgr

import "github.com/abesuite/abec/abelog"

// log is a logger that is initialized with no output filters.  This
// means the package will not perform any logging by default until the caller
// requests it.
var log abelog.Logger

// The default amount of logging is none.
func init() {
	DisableLog()
}

// DisableLog disables all library log output.  Logging output is disabled
// by default until either UseLogger or SetLogWriter are called.
func DisableLog() {
	log = abelog.Disabled
}

// UseLogger uses a specified Logger to output package logging info.
// This should be used in preference to SetLogWriter if the caller is also
// using btclog.
func UseLogger(logger abelog.Logger) {
	log = logger
}
