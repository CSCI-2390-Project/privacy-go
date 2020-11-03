package privacy

import (
	"fmt"
	"github.com/go-stack/stack"
)

func getStackTrace() (stacktrace []string) {
	for _, value := range stack.Trace().TrimRuntime() {
		stacktrace = append(stacktrace, fmt.Sprintf("%+n", value))
	}
	return stacktrace
}
