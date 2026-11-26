package plugin

// Service is the plugin use case: request_plugin and the plugin approval
// pages. It holds its own copy of the core settings and a reference to its
// own Deps. What it needs from the delivery and status use cases it names as
// small ports of its own.
type Service struct {
	core     Core
	deps     *Deps
	delivery Delivery
	status   StatusView
	admit    Admitter
}

// New builds the plugin use case over core and deps.
func New(core Core, deps *Deps, delivery Delivery, status StatusView, admit Admitter) *Service {
	return &Service{core: core, deps: deps, delivery: delivery, status: status, admit: admit}
}
