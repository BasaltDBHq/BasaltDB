package setup

// Target is what a connection string names, as the driver parses it: the
// first host, its port, the database and the user, and the driver's
// fallbacks after the first.
type Target struct {
	Host      string
	Port      int
	Database  string
	User      string
	Fallbacks []HostPort
}

// HostPort is one host of a connection string and its port.
type HostPort struct {
	Host string
	Port int
}
