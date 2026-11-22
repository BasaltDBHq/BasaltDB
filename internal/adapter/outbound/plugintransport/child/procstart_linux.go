package child

import (
	"os"
	"strconv"
	"strings"
)

// procStart is pid's start-time identity: the boot id and the start time in
// clock ticks since boot, so the same tick count after a reboot differs.
func procStart(pid int) (string, error) {
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", errNoStart
	}
	start, err := parseStatStart(stat)
	if err != nil {
		return "", err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", errNoStart
	}
	return strings.TrimSpace(string(boot)) + "/" + start, nil
}
