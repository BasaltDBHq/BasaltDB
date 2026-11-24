package engine

// AbandonedMessage is the text of the answer to a request the engine took
// and never answered (it closed the connection: it stopped, or it refused
// the peer).
const AbandonedMessage = "the basalt engine closed the connection before answering, so the call may or may not have run; call status, and read before you write again"
