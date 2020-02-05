// Package errors provides ability to annotate you regular Go errors with stack traces.
// Code from https://github.com/komuw/komu.engineer/blob/master/blogs/golang-stackTrace/code/errors.go
package dangerous

import (
	"fmt"
	"runtime"
	"strings"
)

const maxStackLength = 50

// Error is the type that implements the error interface.
// It contains the underlying err and the stacktrace of the error site..
type Error struct {
	Err        error
	StackTrace string
}

func (m Error) Error() string {
	return m.Err.Error() + m.StackTrace
}

func New(s string, a ...interface{}) Error {
	err := fmt.Errorf(s, a...)
	return Error{StackTrace: getStackTrace(s), Err: err}
}

// Wrap annotates the given error with a stack trace
func Wrap(new_error string, err error) Error {
	return Error{StackTrace: getStackTrace(new_error), Err: err}
}

func getStackTrace(msg string) string {
	prv_msg := ""
	stackBuf := make([]uintptr, maxStackLength)
	length := runtime.Callers(3, stackBuf[:])
	stack := stackBuf[:length]

	trace := ""
	frames := runtime.CallersFrames(stack)

	for {
		frame, more := frames.Next()
		if prv_msg == msg {
			// To reduce duplicate errors that create at assignment
			// Shortcoming is you can not set identical error message together
			break
		}
		prv_msg = msg
		if !strings.Contains(frame.File, "runtime/") {
			trace = trace + fmt.Sprintf("\n\tFile: %s, Line: %d. Function: %s\n\t\t%s", frame.File, frame.Line, frame.Function, msg)
		}
		if !more {
			break
		}
	}
	return trace
}
