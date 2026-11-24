package agent

import (
	"context"
	"sync"
)

// BlindCache answers Visibility from the database's catalog, once per table
// until Refresh: a statement that returns no rows asks, and a busy agent
// does not ask again for the same table. The upkeep cycle calls Refresh, so
// a policy added or dropped by the person shows within one cycle.
type BlindCache struct {
	// ask returns which of tables (as written in a statement) the role is
	// blind to, named as the database writes them.
	ask func(ctx context.Context, tables []string) ([]string, error)

	mu    sync.Mutex
	known map[string]string
	// generation counts refreshes: an answer asked before a refresh is not stored.
	generation int
}

// NewBlindCache returns a cache that asks through ask. It panics without one.
func NewBlindCache(ask func(ctx context.Context, tables []string) ([]string, error)) *BlindCache {
	if ask == nil {
		panic("agent: blind cache needs a query")
	}
	return &BlindCache{ask: ask, known: map[string]string{}}
}

// Hides returns the database's name for table when it is hidden from the
// agent role, else "".
func (c *BlindCache) Hides(ctx context.Context, table string) (string, error) {
	c.mu.Lock()
	name, ok := c.known[table]
	asked := c.generation
	c.mu.Unlock()
	if ok {
		return name, nil
	}
	blind, err := c.ask(ctx, []string{table})
	if err != nil {
		return "", err
	}
	name = ""
	if len(blind) > 0 {
		name = blind[0]
	}
	c.mu.Lock()
	if c.generation == asked {
		c.known[table] = name
	}
	c.mu.Unlock()
	return name, nil
}

// Refresh forgets every answer, so the next statement asks again.
func (c *BlindCache) Refresh() {
	c.mu.Lock()
	clear(c.known)
	c.generation++
	c.mu.Unlock()
}
