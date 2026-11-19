package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/basaltdbhq/basaltdb/internal/plugin/protocol"
)

// errBadBatch: the engine built a feed batch the contract does not allow. It
// is the engine's fault, so nothing is sent and the plugin is not blamed.
var errBadBatch = errors.New("plugin: a feed batch must be a JSON array of 1 to 100 events, each with data.seq")

// ObserveFeed sends one feed.observe call (feed/1) for one agent and returns
// the seq the plugin handled. events is the CloudEvents JSON batch, sent as
// it is. The answer must be the data.seq of one event of the batch; any
// other answer fails BAD_RESPONSE, so a caller moves its cursor only on a
// nil error. The call runs under Call's rules: a listed agent, the entry's
// slots and deadline.
func (h *Host) ObserveFeed(ctx context.Context, k EntryKey, agent string, events json.RawMessage) (int64, error) {
	seqs, err := batchSeqs(events)
	if err != nil {
		return 0, fmt.Errorf("plugin %s: %w", k, err)
	}
	var res protocol.FeedObserveResponse
	if err := h.Call(ctx, k, []string{agent}, protocol.MethodFeedObserve,
		protocol.FeedObserveRequest{Agent: agent, Events: events}, &res); err != nil {
		return 0, err
	}
	if !slices.Contains(seqs, res.LastSeq) {
		return 0, &CallError{Entry: k, Class: ClassBadResponse}
	}
	return res.LastSeq, nil
}

// DeliverApproval sends one approval.deliver call (deliver/1) for one agent:
// event is the notice, a CloudEvent in its JSON form, sent as it is.
func (h *Host) DeliverApproval(ctx context.Context, k EntryKey, agent string, event json.RawMessage) error {
	var obj map[string]json.RawMessage
	if json.Unmarshal(event, &obj) != nil || obj == nil {
		return fmt.Errorf("plugin %s: a notice must be one JSON object", k)
	}
	return h.Call(ctx, k, []string{agent}, protocol.MethodApprovalDeliver,
		protocol.ApprovalDeliverRequest{Agent: agent, Event: event}, &protocol.ApprovalDeliverResponse{})
}

// batchSeqs reads data.seq of every event of a batch.
func batchSeqs(events json.RawMessage) ([]int64, error) {
	var batch []struct {
		Data struct {
			Seq *int64 `json:"seq"`
		} `json:"data"`
	}
	if json.Unmarshal(events, &batch) != nil || len(batch) == 0 || len(batch) > protocol.MaxFeedEvents {
		return nil, errBadBatch
	}
	seqs := make([]int64, len(batch))
	for i, e := range batch {
		if e.Data.Seq == nil {
			return nil, errBadBatch
		}
		seqs[i] = *e.Data.Seq
	}
	return seqs, nil
}
