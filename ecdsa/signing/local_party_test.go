// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/zkp"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/test"
	"github.com/binance-chain/tss-lib/tss"
)

const (
	testParticipants = test.TestParticipants
	testThreshold    = test.TestThreshold
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
}

func initTheParties(signPIDs tss.SortedPartyIDs, p2pCtx *tss.PeerContext, threshold int, keys []keygen.LocalPartySaveData, outCh chan tss.Message, endCh chan *SignatureData, parties []*LocalParty, errCh chan *tss.Error) (*big.Int, []*LocalParty, chan *tss.Error) {
	// init the parties
	msg := common.GetRandomPrimeInt(256)
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(p2pCtx, signPIDs[i], len(signPIDs), threshold)

		P := NewLocalParty(msg, params, keys[i], outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}
	return msg, parties, errCh
}

func TestE2EConcurrent(t *testing.T) {
	setUp("info")
	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// PHASE: signing
	// use a shuffled selection of the list of parties for this test
	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	msg, parties, errCh := initTheParties(signPIDs, p2pCtx, threshold, keys, outCh, endCh, parties, errCh)

	var ended int32
signing:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
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

		case data := <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants %+v", ended, data)

				// bigR is stored as bytes for the OneRoundData protobuf struct
				bigRX, bigRY := new(big.Int).SetBytes(parties[0].temp.BigR.GetX()), new(big.Int).SetBytes(parties[0].temp.BigR.GetY())
				bigR := crypto.NewECPointNoCurveCheck(tss.EC(), bigRX, bigRY)

				r := parties[0].temp.rI.X()
				fmt.Printf("sign result: R(%s, %s), r=%s\n", bigR.X().String(), bigR.Y().String(), r.String())

				modN := common.ModInt(tss.EC().Params().N)

				// BEGIN check s correctness
				sumS := big.NewInt(0)
				for _, p := range parties {
					sumS = modN.Add(sumS, p.temp.sI)
				}
				fmt.Printf("S: %s\n", sumS.String())
				// END check s correctness

				// BEGIN ECDSA verify
				pkX, pkY := keys[0].ECDSAPub.X(), keys[0].ECDSAPub.Y()
				pk := ecdsa.PublicKey{
					Curve: tss.EC(),
					X:     pkX,
					Y:     pkY,
				}
				ok := ecdsa.Verify(&pk, msg.Bytes(), bigR.X(), sumS)
				assert.True(t, ok, "ecdsa verify must pass")

				btcecSig := &btcec.Signature{R: r, S: sumS}
				btcecSig.Verify(msg.Bytes(), (*btcec.PublicKey)(&pk))
				assert.True(t, ok, "ecdsa verify 2 must pass")

				t.Log("ECDSA signing test done.")
				// END ECDSA verify

				break signing
			}
		}
	}
}

const (
	type7failureFromParty = 0
	type7failureToParty   = 1
)

// Test a type 7 abort. Change the zk-proof in SignRound6Message to force a consistency check failure
// in round 7 with y != bigSJ products.
func type7IdentifiedAbortUpdater(party tss.Party, msg tss.Message, errCh chan<- *tss.Error,
	test *testing.T) {
	// do not send a message from this party back to itself
	if party.PartyID() == msg.GetFrom() {
		return
	}
	bz, _, err := msg.WireBytes()
	if err != nil {
		errCh <- party.WrapError(err)
		return
	}
	pMsg, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
	if err != nil {
		errCh <- party.WrapError(err)
		return
	}

	// Intercepting a round 6 broadcast message to inject a bad zk-proof and trigger a type 7 abort
	if msg.Type() == "SignRound6Message" && msg.IsBroadcast() && msg.GetFrom().Index == type7failureFromParty &&
		party.PartyID().Index == type7failureToParty {
		common.Logger.Debugf("intercepting and changing message %s from %s", msg.Type(), msg.GetFrom())
		r6msg, meta, ok := sabotageRound6Message(party, msg, errCh, pMsg)
		if !ok {
			return
		}
		// repackaging the round 6 message
		pMsg = tss.NewMessage(meta, r6msg, tss.NewMessageWrapper(meta, r6msg))
	}

	if _, errUpdate := party.Update(pMsg); errUpdate != nil {
		if errUpdate.Culprits() != nil && len(errUpdate.Culprits()) > 0 {
			errCh <- errUpdate
		}
	}
}

// Create a fake zk-proof and change the round 6 message
func sabotageRound6Message(party tss.Party, msg tss.Message, errCh chan<- *tss.Error, pMsg tss.ParsedMessage) (*SignRound6Message, tss.MessageRouting, bool) {
	r6msg := pMsg.Content().(*SignRound6Message)
	fakeh, _ := crypto.ECBasePoint2(tss.EC())
	fakesigmaI := new(big.Int).SetInt64(1)
	fakelI := new(big.Int).SetInt64(1)
	fakeTI, err1 := crypto.ScalarBaseMult(tss.EC(), fakesigmaI).Add(fakeh.ScalarMult(fakesigmaI))
	if err1 != nil {
		common.Logger.Error("internal test error assembling fake TI for round 6 message")
		errCh <- party.WrapError(err1)
		return nil, tss.MessageRouting{}, false
	}
	round5_ := party.FirstRound().NextRound().NextRound().NextRound().NextRound()
	round5 := (round5_).(*round5)
	r3msg := round5.temp.signRound3Messages[msg.GetFrom().Index].Content().(*SignRound3Message)
	r3msg.TI = fakeTI.ToProtobufPoint()
	bigR, _ := crypto.NewECPointFromProtobuf(round5.temp.BigR)
	fakebigSI := bigR.ScalarMult(fakesigmaI)
	stPf, err2 := zkp.NewSTProof(fakeTI, bigR, fakeh, fakesigmaI, fakelI)
	if err2 != nil {
		common.Logger.Error("internal test error creating a new fake proof")
		errCh <- party.WrapError(err2)
		return nil, tss.MessageRouting{}, false
	}

	if ok := stPf.Verify(fakebigSI, fakeTI, bigR, fakeh); !ok {
		common.Logger.Error("some error") // TODO
		errCh <- party.WrapError(errors.New("some error"))
		return nil, tss.MessageRouting{}, false
	}
	sabotageRound6Message := NewSignRound6MessageSuccess(party.PartyID(), fakebigSI, stPf)
	round5.temp.signRound6Messages[int(party.PartyID().Index)] = sabotageRound6Message

	r6msg = sabotageRound6Message.Content().(*SignRound6Message)
	meta := tss.MessageRouting{
		From:        msg.GetFrom(),
		To:          msg.GetTo(),
		IsBroadcast: true,
	}
	return r6msg, meta, true
}

// Test a type 7 abort. Use a custom updater to change one round 6 message.
func TestType7Abort(t *testing.T) {
	setUp("debug")
	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// PHASE: signing
	// use a shuffled selection of the list of parties for this test
	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *SignatureData, len(signPIDs))

	updater := type7IdentifiedAbortUpdater

	_, parties, errCh = initTheParties(signPIDs, p2pCtx, threshold, keys, outCh, endCh, parties, errCh)

signing:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			assert.NotNil(t, err, "an error should have been produced")
			assert.NotNil(t, err.Culprits(), "culprits should have been identified")
			assert.EqualValues(t, len(err.Culprits()), 2, "there should have been 2 culprits")
			for _, c := range err.Culprits() {
				assert.True(t, c.Index == type7failureFromParty || c.Index == type7failureToParty,
					"the culprit should have been one of the test parties")
			}
			break signing

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh, t)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh, t)
			}

		case data := <-endCh:
			assert.FailNow(t, "the end channel should not have returned data %v", data)
		}
	}
}
