package buildkite

import (
	"fmt"
)

func LogGroup(message string) {
	fmt.Printf("--- %s\n", message)
}

func LogGroupf(format string, a ...interface{}) {
	LogGroup(fmt.Sprintf(format, a...))
}

func LogGroupClosed(message string) {
	fmt.Printf("+++ %s\n", message)
}

func Log(message string) {
	fmt.Println(message)
}

func Logf(format string, a ...interface{}) {
	fmt.Printf(format, a...)
}

func LogFailuref(format string, a ...interface{}) {
	// make sure the current group is expanded
	fmt.Println("^^^ +++")
	fmt.Printf(format, a...)
}
