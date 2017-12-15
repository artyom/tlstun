// Package logger contains interface that can be used by libraries that want to
// accept abstract interface type to log messages.
package logger

// Interface combines set of methods used for logging. *log.Logger from standard
// library implements this interface. Interface intentionally lacks Panic* and
// Fatal* methods.
type Interface interface {
	Print(v ...interface{})
	Printf(format string, v ...interface{})
	Println(v ...interface{})
}

// Noop is an Interface implementation that does nothing.
var Noop noopLogger

// noopLogger implements Interface which methods does nothing
type noopLogger struct{}

func (n noopLogger) Print(v ...interface{})                 {}
func (n noopLogger) Printf(format string, v ...interface{}) {}
func (n noopLogger) Println(v ...interface{})               {}
