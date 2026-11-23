package app

import (
	"context"
	"log/slog"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/localsetup"
	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/pages"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/vault"
	"github.com/basaltdbhq/basaltdb/internal/app/setupbackend"
)

// sessionDispatcher gives the pages to the Vault channel: it turns the
// channel's link, request and response into the pages' own types and back.
// newPages is the pages for origin with every page's handlers mounted: the
// approval, revert and plugin approval routes.
func newPages(origin string, log *slog.Logger) *pages.Server {
	srv := pages.New(origin, log)
	srv.MountApprovals(pages.NewApprovalHandlers(srv))
	srv.MountReverts(pages.NewRevertHandlers(srv))
	srv.MountPlugins(pages.NewPluginHandlers(srv))
	return srv
}

type sessionDispatcher struct{ pages *pages.Server }

func (d sessionDispatcher) Dispatch(ctx context.Context, link vault.SessionLink, req vault.Request) vault.Response {
	out := d.pages.Dispatch(ctx,
		pages.SessionLink{Token: link.Token, Item: link.Item},
		pages.SessionRequest{Method: req.Method, Path: req.Path, Headers: req.Headers, Body: req.Body})
	return vault.Response{Status: out.Status, ContentType: out.ContentType, Body: out.Body}
}

var _ localsetup.Backend = setupbackend.Backend{}

// newLocalSetup builds the setup page's jobs on the engine's adapters.
func newLocalSetup(o localsetup.Options) (*localsetup.Service, error) {
	o.Backend = setupbackend.Backend{}
	return localsetup.New(o)
}
