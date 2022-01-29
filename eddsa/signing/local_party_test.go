// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/agl/ed25519/edwards25519"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v2/schnorr"
	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/eddsa/keygen"
	"github.com/binance-chain/tss-lib/test"
	"github.com/binance-chain/tss-lib/tss"
)

const (
	testParticipants     = test.TestParticipants
	testThreshold        = test.TestThreshold
	testSetIdS256Schnorr = "S256"
	testSetIdEdwards     = "Edwards"
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}

	// only for test
	tss.SetCurve(tss.Edwards())
}

func TestE2EConcurrentEdwards(t *testing.T) {
	setUp("info")

	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants, testSetIdEdwards)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	msg := big.NewInt(200)
	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(edwards.Edwards(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		P := NewLocalParty(msg, params, keys[i], outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
signing:
	for {
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break signing

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants", ended)
				R := parties[0].temp.r

				// BEGIN check s correctness
				sumS := bigIntToEncodedBytes(&parties[0].temp.si)
				for i, p := range parties {
					if i == 0 {
						continue
					}

					var tmpSumS [32]byte
					edwards25519.ScMulAdd(&tmpSumS, sumS, bigIntToEncodedBytes(big.NewInt(1)), bigIntToEncodedBytes(&p.temp.si))
					sumS = &tmpSumS
				}
				// END check s correctness

				// BEGIN EDDSA verify
				pkX, pkY := keys[0].EDDSAPub.X(), keys[0].EDDSAPub.Y()
				pk := edwards.PublicKey{
					Curve: tss.Edwards(),
					X:     pkX,
					Y:     pkY,
				}

				sBytes := copyBytes(parties[0].data.Signature[32:64])
				sEncodedBigInt := encodedBytesToBigInt(sBytes)

				newSig, err := edwards.ParseSignature(parties[0].data.Signature)
				if err != nil {
					t.Errorf("new sig error %v", err.Error())
					t.FailNow()
				}
				t.Logf("R: %s\n", common.FormatBigInt(newSig.R))
				t.Logf("S: %s\n", common.FormatBigInt(newSig.S))

				ok := edwards.Verify(&pk, msg.Bytes(), R, sEncodedBigInt)
				if !assert.True(t, ok, "eddsa verify must pass") {
					t.Error("eddsa verify must pass")
					t.FailNow()
				}
				t.Log("EDDSA signing test done.")
				// END EDDSA verify

				break signing
			}
		}
	}
}

func TestE2EConcurrentS256Schnorr(t *testing.T) {
	setUp("info")

	threshold := testThreshold

	// PHASE: load keygen fixtures

	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants, testSetIdS256Schnorr)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	msg, _ := hex.DecodeString("304502210088BE0644191B935DB1CD786B43FF27798006578D8C908906B49E89") // big.NewInt(200).Bytes()
	msgI := big.NewInt(0).SetBytes(msg)

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		P := NewLocalParty(msgI, params, keys[i], outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
signing:
	for {
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break signing

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)
				R := parties[0].temp.r

				modN := common.ModInt(tss.S256().Params().N)

				// BEGIN check s correctness
				sumS := big.NewInt(0)
				for _, p := range parties {
					sumS = modN.Add(sumS, &p.temp.si)
				}
				fmt.Printf("S: %s\n", common.FormatBigInt(sumS))
				fmt.Printf("R: %s\n", R.String())
				// END check s correctness

				// BEGIN EdDSA verify

				r := new(big.Int).SetBytes(parties[0].data.GetR())
				s := new(big.Int).SetBytes(parties[0].data.GetS())

				pk1 := keys[0].EDDSAPub.ToSecp256k1PubKey().ToECDSA()
				pk2 := secp256k1.PublicKey(*pk1)
				if ok := schnorr.Verify(&pk2, msg, r, s); !assert.True(t, ok, "eddsa verify must pass") {
					return
				}
				t.Log("EdDSA signing test done.")
				// END EdDSA verify

				break signing
			}
		}
	}
}
