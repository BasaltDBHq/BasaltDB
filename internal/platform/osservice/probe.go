package osservice

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// probeIOLimit bounds each read and write of one probe.
const probeIOLimit = 2 * time.Second

// probeInit is the MCP initialize request the probe sends.
const probeInit = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"basalt-init","version":"0"}}}` + "\n"

// probeOnce connects to the agent's socket, sends initialize and checks
// the engine names itself.
func probeOnce(socket string) error {
	conn, err := net.DialTimeout("unix", socket, probeIOLimit)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(probeIOLimit)); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, probeInit); err != nil {
		return err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Errorf("no answer: %w", err)
	}
	if !strings.Contains(line, `"name":"basalt"`) {
		return errors.New("unexpected answer from the socket")
	}
	return nil
}
