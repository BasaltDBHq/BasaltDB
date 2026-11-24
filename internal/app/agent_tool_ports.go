package app

// DevLocalPages reports whether engine.json sets devLocalPages: every
// personMessage then starts with the DEV_LOCAL_PAGES warning.
func (s *Service) DevLocalPages() bool { return s.deps.Status.DevLocalPages }
