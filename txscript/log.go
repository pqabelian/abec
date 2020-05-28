package txscript

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
// by default until UseLogger is called.
func DisableLog() {
	log = abelog.Disabled
}

// UseLogger uses a specified Logger to output package logging info.
func UseLogger(logger abelog.Logger) {
	log = logger
}

// LogClosure is a closure that can be printed with %v to be used to
// generate expensive-to-create data for a detailed log level and avoid doing
// the work if the data isn't printed.
type logClosure func() string

func (c logClosure) String() string {
	return c()
}

func newLogClosure(c func() string) logClosure {
	return logClosure(c)
}
