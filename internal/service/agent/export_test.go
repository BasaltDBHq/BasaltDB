package agent

import (
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
)

// The external tests reach into a built service through these.

// SetDeliverer replaces s's link deliverer.
func SetDeliverer(s *Service, d linksvc.LinkDeliverer) { s.deps.Delivery.Deliverer = d }

// LinkSecrets is s's short links' secrets.
func LinkSecrets(s *Service) *links.Secrets { return s.deps.Delivery.Links }
