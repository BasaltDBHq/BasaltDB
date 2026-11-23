package guidance

// Failure is the call an error answers: the tool and its arguments.
type Failure struct {
	Tool string
	Args map[string]any
	Err  error
}

// Arg is the string argument name of the call, "" when it has none.
func (f Failure) Arg(name string) string {
	s, _ := f.Args[name].(string)
	return s
}
