package pgcatalog

// MaxIdentNameLen is Postgres NAMEDATALEN-1, the longest identifier Postgres
// keeps without truncating (for example a role name basalt_agent_<name>).
const MaxIdentNameLen = 63
