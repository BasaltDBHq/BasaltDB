# Crash reports

When basalt crashes, it saves a short report on your computer and tells you. **Basalt sends nothing.** You read the report, and you decide whether to file it as a GitHub issue.

## What you see

After a crash, `basalt` prints one line:

```
basalt: crashed; a report was saved: see what it holds with `basalt crash show <id>`, file it on GitHub with `basalt crash report <id>`
```

If the engine hits a crash inside an agent's tool call, the engine keeps running and the agent gets an `INTERNAL` error. The error's message tells you the same two commands.

## What a report holds

- the basalt version, the OS and architecture, and the Go version
- the name of the command (for example `log`) or the MCP tool (for example `write`)
- the error code (`INTERNAL`)
- for a Go runtime error such as an index out of range, the runtime's own message; for any other crash, only the type of the value, never its text
- the stack trace: function names and source files (`cmd/basalt/main.go:73`, and Go runtime and library frames), with no function arguments

Before anything is saved, basalt removes SQL text, table and column names, row values, connection strings, passwords, this machine's host name, IP addresses, e-mail addresses, the values of your environment variables, and your home directory path. The report is built from a fixed set of fields, so the text of a crash never goes into it.

## See exactly what was saved

```
basalt crash list
basalt crash show <id>
```

`show` prints the report as JSON. That is all `basalt crash report` puts in the issue.

## File it, if you want to

```
basalt crash report <id>
```

This builds a GitHub new-issue link on [BasaltDBHq/BasaltDB](https://github.com/BasaltDBHq/BasaltDB/issues/new), with the title and body filled in, and opens it in your browser. Read it, edit it, and press submit only if you want to. If no browser opens, or you are not at a terminal, basalt prints the link instead. The link has a length limit, so a long stack is cut from the bottom; `basalt crash show <id>` has all of it.

An agent cannot file a report for you. Under an agent, `basalt crash report` opens nothing and tells the agent to ask you to run it in your own terminal.

## Where reports live

| Who saved it | Where |
|---|---|
| A command you ran (or an engine you started yourself, in its `state/crash` next to your config) | `crash/` in your basalt config directory (`~/.config/basalt/crash` on Linux, `~/Library/Application Support/basalt/crash` on macOS), readable only by you |
| The engine service | `crash/` in the engine's state directory (`/var/lib/basalt/crash` on Linux, `/Library/Application Support/Basalt/state/crash` on macOS) |

Look on the machine where the engine runs. Each place keeps the 20 newest reports and deletes older ones. You can delete any file there yourself.

The exact rules are in [CONTRACT.md, Crash reports](../CONTRACT.md#crash-reports).
