//go:build unix

package engineos

import (
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// dialTimeout bounds one look at whether a socket answers.
const dialTimeout = 200 * time.Millisecond

// SocketAnswers reports whether the socket answers.
func SocketAnswers(socket string) bool {
	c, err := net.DialTimeout("unix", socket, dialTimeout)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// LaunchDetached starts exe args in a new session with no stdin and
// logFile for output, and lets it go: it outlives this process.
func LaunchDetached(exe string, args []string, logFile *os.File) error {
	cmd := exec.Command(exe, args...)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.Dir = "/" // the config path is absolute; nothing depends on the shim's folder
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }() // reap it if it exits while this process lives
	return nil
}

// OpenLog opens the engine log at path for appending, made with
// config.FileMode, never through a link.
func (OS) OpenLog(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, config.FileMode)
}
