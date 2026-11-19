package plugincontract

import (
	_ "embed"
	"slices"
)

// The samples basalt plugin check sends to a notifier hook (CONTRACT.md,
// "What basalt plugin check sends"), embedded from testdata so the command
// sends the contract's own bytes.
var (
	//go:embed testdata/valid-feed-request-check-sample.json
	checkFeed []byte
	//go:embed testdata/valid-deliver-request-check-sample.json
	checkDeliver []byte
)

// CheckFeedSample is the feed.observe params check sends: {agent, events}.
func CheckFeedSample() []byte { return slices.Clone(checkFeed) }

// CheckDeliverSample is the approval.deliver params check sends:
// {agent, event}.
func CheckDeliverSample() []byte { return slices.Clone(checkDeliver) }

// The values check replaces in the samples: the agent each names, and the
// notice's time and expiry.
const (
	CheckSampleAgent     = "product_a"
	CheckSampleTime      = "2026-01-01T00:00:01Z"
	CheckSampleExpiresAt = "2026-01-02T00:00:01Z"
	// CheckFeedLastSeq is the only answer to the feed sample check takes.
	CheckFeedLastSeq = 2
)
