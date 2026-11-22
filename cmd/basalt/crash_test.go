package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/crash"
)

// leakedConn is built from parts so no secret scanner reads it as a
// committed credential.
var leakedConn = "postgres" + "://admin" + ":hunter2pass" + "@db.internal.example/prod"

// panicSecret stands for what a command was working on when it panicked.
const panicSecret = "SELECT card_number FROM payments WHERE owner = 'alice@example.com'"

func TestAPanicInACommandIsSavedAndScrubbed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("PGPASSWORD", "envsecretvalue99")

	var errw bytes.Buffer
	code := guarded([]string{"init", "--agent", "bot"}, stdio{err: &errw}, func() int {
		panic("connect " + leakedConn + " envsecretvalue99 " + panicSecret)
	})
	require.Equal(t, exitError, code)
	line := errw.String()
	require.Equal(t, 1, strings.Count(line, "\n"), line)
	require.Contains(t, line, "the agent's status tool names it")
	require.NotContains(t, line, "basalt crash", "the crash commands are removed")

	base, err := os.UserConfigDir()
	require.NoError(t, err)
	reports := crash.List(filepath.Join(base, perUserDirName, crash.DirName))
	require.Len(t, reports, 1)
	require.Contains(t, line, reports[0].ID)
	text := reports[0].Show()
	for _, bad := range []string{"hunter2pass", "db.internal.example", "envsecretvalue99", "card_number", "alice@example.com"} {
		require.NotContains(t, text, bad)
		require.NotContains(t, line, bad)
	}
	require.NotContains(t, text, home)
	require.Equal(t, "init", reports[0].Command)
	require.Contains(t, reports[0].Stack, "TestAPanicInACommandIsSavedAndScrubbed")
}

func TestCommandNameIsOnlyAKnownCommand(t *testing.T) {
	t.Parallel()
	require.Equal(t, "init", commandName([]string{"init", "--agent", "x"}))
	require.Empty(t, commandName([]string{"approve", "--agent", "x"}), "approve is removed")
	require.Empty(t, commandName([]string{"log", "--agent", "x"}), "a removed command is no command")
	require.Empty(t, commandName([]string{"post" + "gres://u" + ":p@h/db"}))
	require.Empty(t, commandName(nil))
}
