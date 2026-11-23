package pluginhost

// publisherKeys are the Basalt publisher keys built into the binary, each a
// PEM PUBLIC KEY. Each key's id is computed from the key when the trust
// store is made. The publisher key is generated offline; until it is
// added here the trust store holds only the keys the person trusted.
var publisherKeys = []string{}
