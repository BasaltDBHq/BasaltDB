// Package agentkit is the shared vocabulary of the agent's tools: the next
// steps builder, the commands a step names, the error codes and reasons, the
// mapping of an error to the contract's tool error, the person's message
// builder and the status problems list. It sits below every use case of the
// agent and imports none of them, so a use case package can import it
// without a cycle.
package agentkit
