module github.com/ruddro-roy/sindook/interop

go 1.26.5

replace github.com/ruddro-roy/sindook => ../

require (
	filippo.io/mlkem768 v0.0.0-20260214141301-2e7bebc7d88d
	github.com/cloudflare/circl v1.6.4
	github.com/ruddro-roy/sindook v0.2.0
)

require (
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)
