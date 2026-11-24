package setup

import "time"

// LoginTimeout bounds the agent's login that decides the code's kind.
const LoginTimeout = 15 * time.Second

// SQLStateClassAuth is the SQLSTATE class of a refused login:
// invalid_password (28P01) and invalid_authorization_specification (28000:
// no such role, a pg_hba refusal).
const SQLStateClassAuth = "28"

// SQLStateInternal is internal_error, which Supabase's pooler raises for a
// user it does not know (SupavisorNoTenant).
const SQLStateInternal = "XX000"

// SupavisorNoTenant is what Supabase's pooler answers (SQLSTATE XX000) for a
// user it does not know, such as an agent role not created yet.
const SupavisorNoTenant = "Tenant or user not found"
