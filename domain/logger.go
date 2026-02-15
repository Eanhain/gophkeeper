package domain

// LoggerI is the application-wide logging interface.
// Implementations are injected into every layer (usecase, handler, middleware)
// so that the choice of logging library stays in the infrastructure layer.
type LoggerI interface {
	// Debug logs a message at debug level. Used for development-time diagnostics.
	Debug(message interface{}, args ...interface{})
	// Info logs a message at info level. Used for normal operational events.
	Info(message string, args ...interface{})
	// Warn logs a message at warn level. Used for non-critical issues.
	Warn(message string, args ...interface{})
	// Error logs a message at error level. Used for runtime errors.
	Error(message interface{}, args ...interface{})
	// Fatal logs a message and terminates the program.
	Fatal(message interface{}, args ...interface{})
}
