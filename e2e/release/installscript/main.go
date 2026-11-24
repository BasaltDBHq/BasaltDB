// Command installscript prints the fixed scripts the engine service's
// administrator dialog runs, so the end-to-end test can run them under sudo
// on a runner that has no dialog. It adds no behavior: the text is what
// osservice builds for `basalt init`.
//
//	installscript install <basalt-binary>
//	installscript remove
package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
)

func main() {
	script, err := build(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "installscript:", err)
		os.Exit(1)
	}
	fmt.Print(script)
}

func build(args []string) (string, error) {
	switch {
	case len(args) == 2 && args[0] == "install":
		src, err := osservice.ReadSource(args[1])
		if err != nil {
			return "", err
		}
		return osservice.InstallScript(runtime.GOOS, src)
	case len(args) == 1 && args[0] == "remove":
		return osservice.RemoveScript(runtime.GOOS)
	}
	return "", fmt.Errorf("usage: installscript install <basalt-binary> | installscript remove")
}
