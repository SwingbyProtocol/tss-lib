// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"runtime"
	"strconv"
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

func initTheParties(signPIDs tss.SortedPartyIDs, p2pCtx *tss.PeerContext, threshold int,
	keys []keygen.LocalPartySaveData, keyDerivationDelta *big.Int, outCh chan tss.Message,
	endCh chan *SignatureData, parties []*LocalParty,
	errCh chan *tss.Error) (*big.Int, []*LocalParty, chan *tss.Error) {
	// init the parties
	msg := common.GetRandomPrimeInt(256)
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(p2pCtx, signPIDs[i], len(signPIDs), threshold)

		P := NewLocalParty(msg, params, keys[i], keyDerivationDelta, outCh, endCh).(*LocalParty)
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

	updater := test.SharedPartyUpdaterWithQueues

	msg, parties, errCh := initTheParties(signPIDs, p2pCtx, threshold, keys, big.NewInt(0), outCh, endCh, parties, errCh)

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

// Test a type 7 abort. Change the zk-proof in SignRound6Message to force a consistency check failure
// in round 7 with y != bigSJ products.
func type7IdentifiedAbortUpdater(party tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
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
	if msg.Type() == "SignRound6Message" && msg.IsBroadcast() {
		r6msg, meta, ok := sabotageRound6Message(party, &msg, errCh)
		if !ok {
			return
		}
		// repackaging the round 6 message
		pMsg = tss.NewMessage(meta, r6msg, tss.NewMessageWrapper(meta, r6msg))
	}
	qParty := party.(tss.QueuingParty)
	if _, errUpdate := qParty.ValidateAndStoreInQueues(pMsg); errUpdate != nil {
		if errUpdate.Culprits() != nil && len(errUpdate.Culprits()) > 0 {
			errCh <- errUpdate
		}
	}
}

// Create a fake zk-proof and change the round 6 message
func sabotageRound6Message(toParty tss.Party, msg *tss.Message, errCh chan<- *tss.Error) (*SignRound6Message, tss.MessageRouting, bool) {
	fakeh, _ := crypto.ECBasePoint2(tss.EC())
	fakesigmaI := new(big.Int).SetInt64(1)
	fakelI := new(big.Int).SetInt64(1)
	fakeTI, err1 := crypto.ScalarBaseMult(tss.EC(), fakesigmaI).Add(fakeh.ScalarMult(fakesigmaI))
	if err1 != nil {
		common.Logger.Error("internal test error assembling fake TI for round 6 message")
		errCh <- toParty.WrapError(err1)
		return nil, tss.MessageRouting{}, false
	}
	round5 := (toParty.FirstRound().NextRound().NextRound().NextRound().NextRound()).(*round5)
	toParty.Lock()
	r3msg := round5.temp.signRound3Messages[(*msg).GetFrom().Index].Content().(*SignRound3Message)
	r3msg.TI = fakeTI.ToProtobufPoint()
	bigR, _ := crypto.NewECPointFromProtobuf(round5.temp.BigR)
	fakebigSI := bigR.ScalarMult(fakesigmaI)
	stPf, err2 := zkp.NewSTProof(fakeTI, bigR, fakeh, fakesigmaI, fakelI)
	if err2 != nil {
		common.Logger.Error("internal test error creating a new fake proof")
		errCh <- toParty.WrapError(err2)
		return nil, tss.MessageRouting{}, false
	}

	parsedR6msg := NewSignRound6MessageSuccess((*msg).GetFrom(), fakebigSI, stPf)
	round5.temp.signRound6Messages[(*msg).GetFrom().Index] = parsedR6msg
	toParty.Unlock()
	r6msg := parsedR6msg.Content().(*SignRound6Message)
	meta := tss.MessageRouting{
		From:        (*msg).GetFrom(),
		To:          (*msg).GetTo(),
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

	_, parties, errCh = initTheParties(signPIDs, p2pCtx, threshold, keys, big.NewInt(0), outCh, endCh, parties, errCh)

signing:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			assert.NotNil(t, err, "an error should have been produced")
			assert.NotNil(t, err.Culprits(), "culprits should have been identified")
			assert.Greater(t, len(err.Culprits()), 0, "there should have been at least one culprit")
			assert.Regexp(t, ".*round 7 consistency check failed: y != bigSJ products, Type 7 identified abort.*", err.Error(),
				"the error should have had a Type 7 identified abort message")
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
			assert.FailNow(t, "the end channel should not have returned data %v", data)
		}
	}
}

const (
	type4failureFromParty = 0
)

// Test a type 4 abort
func type4IdentifiedAbortUpdater(party tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
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

	// Intercepting a round 5 broadcast message to inject a bad k_i and trigger a type 4 abort
	if msg.Type() == "SignRound5Message" && msg.IsBroadcast() && msg.GetFrom().Index == type4failureFromParty {
		common.Logger.Debugf("intercepting and changing message %s from %s", msg.Type(), msg.GetFrom())
		r5msg, meta, ok := taintRound5Message(party, msg, pMsg)
		if !ok {
			return
		}
		// repackaging the round 5 message
		pMsg = tss.NewMessage(meta, r5msg, tss.NewMessageWrapper(meta, r5msg))
	}
	qParty := party.(tss.QueuingParty)
	if _, errUpdate := qParty.ValidateAndStoreInQueues(pMsg); errUpdate != nil {
		errCh <- errUpdate
	}
}

// taint a round 5 message setting a bad k_i
func taintRound5Message(party tss.Party, msg tss.Message, pMsg tss.ParsedMessage) (*SignRound5Message, tss.MessageRouting, bool) {
	r5msg := pMsg.Content().(*SignRound5Message)
	round5 := (party.FirstRound().NextRound().NextRound().NextRound().NextRound()).(*round5)

	party.Lock()
	bigR, _ := crypto.NewECPointFromProtobuf(round5.temp.BigR)
	fakekI := new(big.Int).SetInt64(1)
	fakeBigRBarI := bigR.ScalarMult(fakekI)

	proof, _ := r5msg.UnmarshalPDLwSlackProof()
	round5Message := NewSignRound5Message(msg.GetFrom(), fakeBigRBarI, proof)
	round5.temp.signRound6Messages[msg.GetFrom().Index] = round5Message
	party.Unlock()
	r5msg = round5Message.Content().(*SignRound5Message)
	meta := tss.MessageRouting{
		From:        msg.GetFrom(),
		To:          msg.GetTo(),
		IsBroadcast: true,
	}
	return r5msg, meta, true
}

// Test a type 4 abort. Use a custom updater to change one round 5 message.
func TestType4IdentifiedAbort(t *testing.T) {
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

	updater := type4IdentifiedAbortUpdater

	_, parties, errCh = initTheParties(signPIDs, p2pCtx, threshold, keys, big.NewInt(0), outCh, endCh, parties, errCh)

signing:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			assert.NotNil(t, err, "an error should have been triggered")
			assert.NotNil(t, err.Culprits(), "culprits should have been identified")
			assert.EqualValues(t, len(err.Culprits()), 1, "there should have been 1 culprit")
			assert.True(t, err.Culprits()[0].Index == type4failureFromParty,
				"the culprit should have been player "+strconv.Itoa(type4failureFromParty))
			assert.Regexp(t, ".*failed to verify ZK proof of consistency between R_i and E_i\\(k_i\\) for P 0", err.Error(),
				"the error should have contained a proof of consistency failure message")

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
			assert.FailNow(t, "the end channel should not have returned data %v", data)
		}
	}
}

//

const (
	type5failureFromParty = 0
)

// Test a type 5 abort
func type5IdentifiedAbortUpdater(party tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
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

	// Intercepting a round 5 broadcast message to inject a bad k_i and trigger a type 5 abort
	if msg.Type() == "SignRound5Message" && msg.IsBroadcast() && msg.GetFrom().Index == type4failureFromParty {
		common.Logger.Debugf("intercepting and changing message %s from %s", msg.Type(), msg.GetFrom())
		party.Lock()
		r5msg, meta, ok := taintRound5MessageWithZKP(party, msg, pMsg)
		if !ok {
			return
		}
		// repackaging the round 5 message
		pMsg = tss.NewMessage(meta, r5msg, tss.NewMessageWrapper(meta, r5msg))
		party.Unlock()
	}
	qParty := party.(tss.QueuingParty)
	if _, errUpdate := qParty.ValidateAndStoreInQueues(pMsg); errUpdate != nil {
		errCh <- errUpdate
	}
}

// taint a round 5 message setting bad k_i and ZK proof
func taintRound5MessageWithZKP(party tss.Party, msg tss.Message, pMsg tss.ParsedMessage) (*SignRound5Message, tss.MessageRouting, bool) {
	r5msg := pMsg.Content().(*SignRound5Message)
	round5 := (party.FirstRound().NextRound().NextRound().NextRound().NextRound()).(*round5)

	bigR, _ := crypto.NewECPointFromProtobuf(round5.temp.BigR)
	fakekI := new(big.Int).SetInt64(1)
	fakeBigRBarI := bigR.ScalarMult(fakekI)

	paiPK := round5.key.PaillierPKs[type5failureFromParty]
	cA, rA, err := paiPK.EncryptAndReturnRandomness(fakekI)
	if err != nil {
		common.Logger.Error("internal test error")
	}

	r1msg1 := round5.temp.signRound1Message1s[type5failureFromParty].Content().(*SignRound1Message1)
	r1msg1.C = cA.Bytes()

	// compute ZK proof of consistency between R_i and E_i(k_i)
	// ported from: https://git.io/Jf69a
	pdlWSlackStatement := zkp.PDLwSlackStatement{
		PK:         paiPK,
		CipherText: cA,
		Q:          fakeBigRBarI,
		G:          bigR,
		H1:         round5.key.H1j[type5failureFromParty],
		H2:         round5.key.H2j[type5failureFromParty],
		NTilde:     round5.key.NTildej[type5failureFromParty],
	}
	pdlWSlackWitness := zkp.PDLwSlackWitness{
		SK: round5.key.PaillierSK,
		X:  fakekI,
		R:  rA,
	}
	pdlWSlackPf := zkp.NewPDLwSlackProof(pdlWSlackWitness, pdlWSlackStatement)

	round5Message := NewSignRound5Message(msg.GetFrom(), fakeBigRBarI, &pdlWSlackPf)
	round5.temp.signRound6Messages[msg.GetFrom().Index] = round5Message

	r5msg = round5Message.Content().(*SignRound5Message)
	meta := tss.MessageRouting{
		From:        msg.GetFrom(),
		To:          msg.GetTo(),
		IsBroadcast: true,
	}
	return r5msg, meta, true
}

// Test a type 5 abort. Use a custom updater to change one round 5 message.
func TestType5IdentifiedAbort(t *testing.T) {
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

	updater := type5IdentifiedAbortUpdater

	_, parties, errCh = initTheParties(signPIDs, p2pCtx, threshold, keys, big.NewInt(0), outCh, endCh, parties, errCh)

signing:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			if err.Victim() != nil && err.Victim().Index == type4failureFromParty {
				// let us not credit our own malicious party
				continue
			}
			assert.NotNil(t, err, "an error should have been triggered")
			assert.Regexp(t, ".*round 7 consistency check failed: g != R products, Type 5 identified abort.*", err.Error(),
				"the error should have had a type 5 identified abort failure message")

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
			assert.FailNow(t, "the end channel should not have returned data %v", data)
		}
	}
}
