package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// searchTerm is the search for a resource not found: its table name.
func (ds *Service) searchTerm(resource string) string {
	term := resource
	if _, name, err := ds.store.Language.ParseName(resource); err == nil {
		term = name
	}
	term = firstRunes(strings.TrimSpace(term), describeQueryMax)
	if term == "" {
		return resource
	}
	return term
}

// DescribeSearch returns one page of the resources matching p.Query, never
// matching or naming a SECRET field.
func (ds *Service) DescribeSearch(ctx context.Context, p DescribeSearchParams) (pagination.Page[SearchItem], error) {
	var after *agentstore.Cursor
	if p.Cursor != "" {
		c, err := decodeSearchCursor(p.Cursor)
		if err != nil {
			return pagination.Page[SearchItem]{}, err
		}
		after = &c
	}
	secrets, err := ds.store.Classes.Secrets(ctx)
	if err != nil {
		return pagination.Page[SearchItem]{}, err
	}
	matches, err := ds.store.Catalog.Search(ctx, p.Query, secrets, after, p.Limit+1)
	if err != nil {
		return pagination.Page[SearchItem]{}, err
	}
	var page pagination.Page[SearchItem]
	if len(matches) > p.Limit {
		matches = matches[:p.Limit]
		last := matches[len(matches)-1]
		page.NextCursor = encodeSearchCursor(agentstore.Cursor{Rank: last.Rank, Namespace: last.Namespace, Name: last.Name})
	}
	page.Items = make([]SearchItem, 0, len(matches))
	for _, m := range matches {
		page.Items = append(page.Items, ds.searchItem(m.Resource, m.Matched))
	}
	return page, nil
}

func (ds *Service) searchItem(r agentstore.Resource, matched string) SearchItem {
	access := r.Actions
	if access == nil {
		access = []action.Op{}
	}
	return SearchItem{
		Resource: ds.store.Language.PrintName(r.Namespace, r.Name), Kind: r.Kind, EstimatedRows: r.Estimate,
		Matched: matched, Access: access, Comment: trimComment(r.Comment, searchCommentMax),
	}
}

// searchCursorKey is a search page's cursor: the last match's rank and name.
type searchCursorKey struct {
	Rank      int    `json:"r"`
	Namespace string `json:"s"`
	Name      string `json:"n"`
}

// searchRanks is how many ranks Search has (exact table name to comment).
const searchRanks = 6

func encodeSearchCursor(c agentstore.Cursor) string {
	raw, err := json.Marshal(searchCursorKey(c))
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// decodeSearchCursor reads a cursor describe returned for a search.
func decodeSearchCursor(cursor string) (agentstore.Cursor, error) {
	stale := &guidance.ArgumentError{Message: "invalid arguments: the cursor is not one describe returned for a search", Reason: guidance.ReasonStaleCursor}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return agentstore.Cursor{}, stale
	}
	var k searchCursorKey
	if json.Unmarshal(raw, &k) != nil || k.Rank < 0 || k.Rank >= searchRanks || k.Namespace == "" || k.Name == "" {
		return agentstore.Cursor{}, stale
	}
	return agentstore.Cursor(k), nil
}
