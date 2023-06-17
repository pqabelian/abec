package wire

import (
	"github.com/abesuite/abec/abelog"
	"strings"
)

const (
	// maxRejectReasonLen is the maximum length of a sanitized reject reason
	// that will be logged.
	maxRejectReasonLen = 250
)

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

// directionString is a helper function that returns a string that represents
// the direction of a connection (inbound or outbound).
func directionString(inbound bool) string {
	if inbound {
		return "inbound"
	}
	return "outbound"
}

// sanitizeString strips any characters which are even remotely dangerous, such
// as html control characters, from the passed string.  It also limits it to
// the passed maximum size, which can be 0 for unlimited.  When the string is
// limited, it will also add "..." to the string to indicate it was truncated.
func sanitizeString(str string, maxLength uint) string {
	const safeChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY" +
		"Z01234567890 .,;_/:?@"

	// Strip any characters not in the safeChars string removed.
	str = strings.Map(func(r rune) rune {
		if strings.ContainsRune(safeChars, r) {
			return r
		}
		return -1
	}, str)

	// Limit the string to the max allowed length.
	if maxLength > 0 && uint(len(str)) > maxLength {
		str = str[:maxLength]
		str = str + "..."
	}
	return str
}
