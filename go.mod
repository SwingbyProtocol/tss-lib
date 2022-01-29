module github.com/binance-chain/tss-lib

go 1.17

require (
	github.com/agl/ed25519 v0.0.0-20200305024217-f36fc4b53d43
	github.com/btcsuite/btcd v0.22.0-beta.0.20220111032746-97732e52810c
	github.com/btcsuite/btcd/btcec/v2 v2.0.0
	github.com/btcsuite/btcutil v1.0.3-0.20211129182920-9c4bbabe7acd
	github.com/decred/dcrd/dcrec/edwards/v2 v2.0.2
	github.com/hashicorp/go-multierror v1.1.1
	github.com/ipfs/go-log v1.0.5
	github.com/olekukonko/tablewriter v0.0.5
	github.com/otiai10/primes v0.0.0-20210501021515-f1b2be525a11
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
	golang.org/x/crypto v0.0.0-20220128200615-198e4374d7ed
	golang.org/x/text v0.3.7
	google.golang.org/protobuf v1.27.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/ipfs/go-log/v2 v2.5.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.7.0 // indirect
	go.uber.org/zap v1.20.0 // indirect
	golang.org/x/sys v0.0.0-20220128215802-99c3d69c2c27 // indirect
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)

replace github.com/agl/ed25519 => github.com/SwingbyProtocol/edwards25519 v0.0.0-20200305024217-f36fc4b53d43

replace github.com/btcsuite/btcd => github.com/Roasbeef/btcd v0.0.0-20220128222530-5a59e7c0ddfb

replace github.com/btcsuite/btcd/btcec/v2 => github.com/Roasbeef/btcd/btcec/v2 v2.0.0-20220128222530-5a59e7c0ddfb
