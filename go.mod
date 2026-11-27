module github.com/basaltdbhq/basaltdb

go 1.26.0

toolchain go1.26.11

require (
	connectrpc.com/connect v1.21.1
	github.com/FastFilter/xorfilter v0.5.1
	github.com/Masterminds/squirrel v1.5.4
	github.com/basaltdbhq/basalt-plugin-go v0.1.0-alpha.2
	github.com/coder/websocket v1.8.15
	github.com/go-playground/validator/v10 v10.30.6
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.13.0
	github.com/nyaruka/phonenumbers v1.8.1
	github.com/pganalyze/pg_query_go/v6 v6.2.5
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3
	github.com/stretchr/testify v1.12.1
	github.com/wasilibs/go-pgquery v0.0.0-20261106060434-4301e51f8dbf
	go.uber.org/goleak v1.3.0
	golang.org/x/crypto/x509roots/fallback v0.0.0-20261123192653-4dc4fb521066
	golang.org/x/mod v0.43.0
	golang.org/x/net v0.63.0
	golang.org/x/sys v0.50.0
	golang.org/x/term v0.48.0
	golang.org/x/text v0.44.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/gabriel-vasile/mimetype v1.4.16 // indirect
	github.com/go-playground/locales v0.14.2 // indirect
	github.com/go-playground/universal-translator v0.18.2 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	github.com/lann/builder v0.0.0-20180802200727-47ae307949d0 // indirect
	github.com/lann/ps v0.0.0-20150810152359-62de8c46ede0 // indirect
	github.com/leodido/go-urn v1.5.0 // indirect
	github.com/tetratelabs/wazero v1.12.0 // indirect
	github.com/wasilibs/wazero-helpers v0.0.0-20250123031827-cd30c44769bb // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
)

// Release candidates of v0.1.0-alpha sort above it in Go module order, so
// go install ...@latest would pick one. They are test builds: retract them.
retract [v0.1.0-alpha-rc.1, v0.1.0-alpha-rc.99]
