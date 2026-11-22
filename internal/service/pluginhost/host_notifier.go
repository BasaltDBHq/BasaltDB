package pluginhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginproto"
)

// errBadBatch: the engine built a feed batch the contract does not allow. It
// is the engine's fault, so nothing is sent and the plugin is not blamed.
var errBadBatch = errors.New("plugin: a feed batch must be a JSON array of 1 to 100 events, each with a data.seq of at least 1")

// ObserveFeed sends one feed.observe call (feed/1) for one agent and returns
// the seq the plugin handled. events is the CloudEvents JSON batch; the
// transports send it compacted, with no character escaped, so build it with
// protocol.Marshal to keep its bytes the same on every transport. The answer
// must be the data.seq of one event of the batch; any other answer fails
// BAD_RESPONSE, so a caller moves its cursor only on a nil error. The call
// runs under Call's rules: a listed agent, the entry's slots and deadline.
// The caller sends it only to an entry whose manifest declares feed.observe.
func (h *Host) ObserveFeed(ctx context.Context, k EntryKey, agent string, events json.RawMessage) (int64, error) {
	return h.ObserveFeedOn(ctx, k, 0, agent, events)
}

// ObserveFeedOn is ObserveFeed made only on registration reg of the entry
// (CallOn): a batch read while one registration served the agent never
// reaches a later one, which may serve it from a later record.
func (h *Host) ObserveFeedOn(ctx context.Context, k EntryKey, reg Registration, agent string, events json.RawMessage) (int64, error) {
	seqs, err := batchSeqs(events)
	if err != nil {
		return 0, fmt.Errorf("plugin %s: %w", k, err)
	}
	var res pluginproto.FeedObserveResponse
	if err := h.CallOn(ctx, k, reg, []string{agent}, pluginproto.MethodFeedObserve,
		pluginproto.FeedObserveRequest{Agent: agent, Events: events}, &res); err != nil {
		return 0, err
	}
	if !slices.Contains(seqs, res.LastSeq) {
		return 0, &CallError{Entry: k, Class: ClassBadResponse}
	}
	return res.LastSeq, nil
}

// DeliverApproval sends one approval.deliver call (deliver/1) for one agent:
// event is the notice, a CloudEvent in its JSON form, sent compacted as a
// feed batch is. The caller sends it only to an entry whose manifest declares
// approval.deliver.
func (h *Host) DeliverApproval(ctx context.Context, k EntryKey, agent string, event json.RawMessage) error {
	var obj map[string]json.RawMessage
	if json.Unmarshal(event, &obj) != nil || obj == nil {
		return fmt.Errorf("plugin %s: a notice must be one JSON object", k)
	}
	return h.Call(ctx, k, []string{agent}, pluginproto.MethodApprovalDeliver,
		pluginproto.ApprovalDeliverRequest{Agent: agent, Event: event}, &pluginproto.ApprovalDeliverResponse{})
}

// batchSeqs reads data.seq of every event of a batch.
func batchSeqs(events json.RawMessage) ([]int64, error) {
	var batch []struct {
		Data struct {
			Seq *int64 `json:"seq"`
		} `json:"data"`
	}
	if json.Unmarshal(events, &batch) != nil || len(batch) == 0 || len(batch) > pluginproto.MaxFeedEvents {
		return nil, errBadBatch
	}
	seqs := make([]int64, len(batch))
	for i, e := range batch {
		// A seq is at least 1, so an answer with no lastSeq (0) is never
		// one of the batch's.
		if e.Data.Seq == nil || *e.Data.Seq < 1 {
			return nil, errBadBatch
		}
		seqs[i] = *e.Data.Seq
	}
	return seqs, nil
}
