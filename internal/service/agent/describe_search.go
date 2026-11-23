package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// searchTerm is the search for a resource not found: its table name.
func searchTerm(resource string) string {
	term := resource
	if _, name, err := parseResource(resource); err == nil {
		term = name
	}
	term = firstRunes(strings.TrimSpace(term), describeQueryMax)
	if term == "" {
		return resource
	}
	return term
}

// DescribeSearch returns one page of the relations matching p.Query, never
// matching or naming a SECRET column.
func (s *Service) DescribeSearch(ctx context.Context, p DescribeSearchParams) (pagination.Page[SearchItem], error) {
	var after *CatalogSearchCursor
	if p.Cursor != "" {
		c, err := decodeSearchCursor(p.Cursor)
		if err != nil {
			return pagination.Page[SearchItem]{}, err
		}
		after = &c
	}
	secrets, err := s.deps.Describe.Classes.Secrets(ctx)
	if err != nil {
		return pagination.Page[SearchItem]{}, err
	}
	exclude := make([]CatalogColumnKey, 0, len(secrets))
	for _, r := range secrets {
		exclude = append(exclude, CatalogColumnKey{OID: r.TableOID, Attnum: r.Attnum})
	}
	matches, err := s.deps.Describe.Catalog.Search(ctx, p.Query, exclude, after, p.Limit+1)
	if err != nil {
		return pagination.Page[SearchItem]{}, err
	}
	var page pagination.Page[SearchItem]
	if len(matches) > p.Limit {
		matches = matches[:p.Limit]
		last := matches[len(matches)-1]
		page.NextCursor = encodeSearchCursor(CatalogSearchCursor{Rank: last.Rank, Schema: last.Schema, Name: last.Name})
	}
	page.Items = make([]SearchItem, 0, len(matches))
	for _, m := range matches {
		page.Items = append(page.Items, searchItem(m.CatalogRelation, m.Matched))
	}
	return page, nil
}

func searchItem(r CatalogRelation, matched string) SearchItem {
	access := r.Privileges
	if access == nil {
		access = []string{}
	}
	return SearchItem{
		Resource: printedName(r.Schema, r.Name), Kind: r.Kind, EstimatedRows: r.EstimatedRows,
		Matched: matched, Access: access, Comment: trimComment(r.Comment, searchCommentMax),
	}
}

// searchCursorKey is a search page's cursor: the last match's rank and name.
type searchCursorKey struct {
	Rank   int    `json:"r"`
	Schema string `json:"s"`
	Name   string `json:"n"`
}

// searchRanks is how many ranks Search has (exact table name to comment).
const searchRanks = 6

func encodeSearchCursor(c CatalogSearchCursor) string {
	raw, err := json.Marshal(searchCursorKey(c))
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// decodeSearchCursor reads a cursor describe returned for a search.
func decodeSearchCursor(cursor string) (CatalogSearchCursor, error) {
	stale := &ArgumentError{Message: "invalid arguments: the cursor is not one describe returned for a search", Reason: ReasonStaleCursor}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return CatalogSearchCursor{}, stale
	}
	var k searchCursorKey
	if json.Unmarshal(raw, &k) != nil || k.Rank < 0 || k.Rank >= searchRanks || k.Schema == "" || k.Name == "" {
		return CatalogSearchCursor{}, stale
	}
	return CatalogSearchCursor(k), nil
}
