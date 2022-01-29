module github.com/binance-chain/tss-lib/cmd

go 1.17

require (
	github.com/binance-chain/tss-lib v1.3.3
	github.com/btcsuite/btcd/btcec/v2 v2.0.0
	github.com/ipfs/go-log v1.0.5
	github.com/olekukonko/tablewriter v0.0.5
	github.com/pkg/errors v0.9.1
	golang.org/x/text v0.3.7
)

require (
	github.com/agl/ed25519 v0.0.0-20200305024217-f36fc4b53d43 // indirect
	github.com/btcsuite/btcd v0.22.0-beta.0.20220111032746-97732e52810c // indirect
	github.com/btcsuite/btcutil v1.0.3-0.20211129182920-9c4bbabe7acd // indirect
	github.com/decred/dcrd/dcrec/edwards/v2 v2.0.2 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/ipfs/go-log/v2 v2.5.0 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/otiai10/primes v0.0.0-20210501021515-f1b2be525a11 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.7.0 // indirect
	go.uber.org/zap v1.20.0 // indirect
	golang.org/x/crypto v0.0.0-20220128200615-198e4374d7ed // indirect
	golang.org/x/sys v0.0.0-20220128215802-99c3d69c2c27 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
)

replace github.com/binance-chain/tss-lib => github.com/SwingbyProtocol/tss-lib v1.5.1-0.20220129135114-1e9891f47740

replace github.com/agl/ed25519 => github.com/SwingbyProtocol/edwards25519 v0.0.0-20200305024217-f36fc4b53d43

replace github.com/btcsuite/btcd => github.com/Roasbeef/btcd v0.0.0-20220128222530-5a59e7c0ddfb

replace github.com/btcsuite/btcd/btcec/v2 => github.com/Roasbeef/btcd/btcec/v2 v2.0.0-20220128222530-5a59e7c0ddfb
