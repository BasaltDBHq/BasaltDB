package binwatch

import "time"

// WithInterval sets how often the path is looked at (tests).
func (w *Watcher) WithInterval(d time.Duration) *Watcher {
	w.interval = d
	return w
}
