// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/dlnp"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/vss"
	ecdsautils "github.com/binance-chain/tss-lib/ecdsa"
	"github.com/binance-chain/tss-lib/test"
	"github.com/binance-chain/tss-lib/tss"
)

const (
	testParticipants = TestParticipants
	testThreshold    = TestThreshold
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
}

func handleMessage(t *testing.T, msg tss.Message, parties []*LocalParty, updater func(party tss.Party, msg tss.Message, errCh chan<- *tss.Error), errCh chan *tss.Error) bool {
	dest := msg.GetTo()
	if dest == nil { // broadcast!
		for _, P := range parties {
			if P.PartyID().Index == msg.GetFrom().Index {
				continue
			}
			go updater(P, msg, errCh)
		}
	} else { // point-to-point!
		if dest[0].Index == msg.GetFrom().Index {
			t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
			return true
		}
		go updater(parties[dest[0].Index], msg, errCh)
	}
	return false
}

func initTheParties(pIDs tss.SortedPartyIDs, p2pCtx *tss.PeerContext, threshold int, fixtures []LocalPartySaveData, outCh chan tss.Message, endCh chan LocalPartySaveData, parties []*LocalParty, errCh chan *tss.Error) ([]*LocalParty, chan *tss.Error) {
	// init the parties
	for i := 0; i < len(pIDs); i++ {
		var P *LocalParty
		params := tss.NewParameters(p2pCtx, pIDs[i], len(pIDs), threshold)
		if i < len(fixtures) {
			P = NewLocalParty(params, outCh, endCh, fixtures[i].LocalPreParams).(*LocalParty)
		} else {
			P = NewLocalParty(params, outCh, endCh).(*LocalParty)
		}
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}
	return parties, errCh
}

func tryWriteTestFixtureFile(t *testing.T, index int, data LocalPartySaveData) {
	fixtureFileName := makeTestFixtureFilePath(index)

	// fixture file does not already exist?
	// if it does, we won't re-create it here
	fi, err := os.Stat(fixtureFileName)
	if !(err == nil && fi != nil && !fi.IsDir()) {
		fd, err := os.OpenFile(fixtureFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			assert.NoErrorf(t, err, "unable to open fixture file %s for writing", fixtureFileName)
		}
		bz, err := json.Marshal(&data)
		if err != nil {
			t.Fatalf("unable to marshal save data for fixture file %s", fixtureFileName)
		}
		_, err = fd.Write(bz)
		if err != nil {
			t.Fatalf("unable to write to fixture file %s", fixtureFileName)
		}
		t.Logf("Saved a test fixture file for party %d: %s", index, fixtureFileName)
	} else {
		t.Logf("Fixture file already exists for party %d; not re-creating: %s", index, fixtureFileName)
	}
	//
}

func TestStartRound1Paillier(t *testing.T) {
	setUp("info")

	pIDs := tss.GenerateTestPartyIDs(2)
	p2pCtx := tss.NewPeerContext(pIDs)
	threshold := 1
	params := tss.NewParameters(p2pCtx, pIDs[0], len(pIDs), threshold)

	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	var lp *LocalParty
	out := make(chan tss.Message, len(pIDs))
	if 0 < len(fixtures) {
		lp = NewLocalParty(params, out, nil, fixtures[0].LocalPreParams).(*LocalParty)
	} else {
		lp = NewLocalParty(params, out, nil).(*LocalParty)
	}
	if err := lp.Start(); err != nil {
		assert.FailNow(t, err.Error())
	}
	<-out

	// Paillier modulus 2048 (two 1024-bit primes)
	// round up to 256, it was used to be flaky, sometimes comes back with 1 byte less
	len1 := len(lp.data.PaillierSK.LambdaN.Bytes())
	len2 := len(lp.data.PaillierSK.PublicKey.N.Bytes())
	if len1%2 != 0 {
		len1 = len1 + (256 - (len1 % 256))
	}
	if len2%2 != 0 {
		len2 = len2 + (256 - (len2 % 256))
	}
	assert.Equal(t, 2048/8, len1)
	assert.Equal(t, 2048/8, len2)
}

func TestFinishAndSaveH1H2(t *testing.T) {
	setUp("info")

	pIDs := tss.GenerateTestPartyIDs(2)
	p2pCtx := tss.NewPeerContext(pIDs)
	threshold := 1
	params := tss.NewParameters(p2pCtx, pIDs[0], len(pIDs), threshold)

	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	var lp *LocalParty
	out := make(chan tss.Message, len(pIDs))
	if 0 < len(fixtures) {
		lp = NewLocalParty(params, out, nil, fixtures[0].LocalPreParams).(*LocalParty)
	} else {
		lp = NewLocalParty(params, out, nil).(*LocalParty)
	}
	if err := lp.Start(); err != nil {
		assert.FailNow(t, err.Error())
	}

	// RSA modulus 2048 (two 1024-bit primes)
	// round up to 256
	len1 := len(lp.data.H1j[0].Bytes())
	len2 := len(lp.data.H2j[0].Bytes())
	len3 := len(lp.data.NTildej[0].Bytes())
	if len1%2 != 0 {
		len1 = len1 + (256 - (len1 % 256))
	}
	if len2%2 != 0 {
		len2 = len2 + (256 - (len2 % 256))
	}
	if len3%2 != 0 {
		len3 = len3 + (256 - (len3 % 256))
	}
	// 256 bytes = 2048 bits
	assert.Equal(t, 256, len1, "h1 should be correct len")
	assert.Equal(t, 256, len2, "h2 should be correct len")
	assert.Equal(t, 256, len3, "n-tilde should be correct len")
	assert.NotZero(t, lp.data.H1i, "h1 should be non-zero")
	assert.NotZero(t, lp.data.H2i, "h2 should be non-zero")
	assert.NotZero(t, lp.data.NTildei, "n-tilde should be non-zero")
}

func TestBadMessageCulprits(t *testing.T) {
	setUp("info")

	pIDs := tss.GenerateTestPartyIDs(2)
	p2pCtx := tss.NewPeerContext(pIDs)
	params := tss.NewParameters(p2pCtx, pIDs[0], len(pIDs), 1)

	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	var lp *LocalParty
	out := make(chan tss.Message, len(pIDs))
	if 0 < len(fixtures) {
		lp = NewLocalParty(params, out, nil, fixtures[0].LocalPreParams).(*LocalParty)
	} else {
		lp = NewLocalParty(params, out, nil).(*LocalParty)
	}
	if err := lp.Start(); err != nil {
		assert.FailNow(t, err.Error())
	}

	badMsg, _ := NewKGRound1Message(pIDs[1], zero, &paillier.PublicKey{N: zero},
		&ecdsa.PublicKey{Curve: tss.EC(), X: zero, Y: zero}, ecdsautils.NewECDSASignature(zero, zero),
		zero, zero, zero, zero, zero, new(dlnp.Proof), new(dlnp.Proof))
	ok, err2 := lp.Update(badMsg)
	t.Log(err2)
	assert.False(t, ok)
	if !assert.Error(t, err2) {
		return
	}
	assert.Equal(t, 1, len(err2.Culprits()))
	assert.Equal(t, pIDs[1], err2.Culprits()[0])
	assert.Contains(t, err2.Error(),
		"task ecdsa-keygen, party {0,P[1]}, round 1, culprits [{1,")
	assert.Contains(t, err2.Error(),
		": message failed ValidateBasic: Type: KGRound1Message, From: {1,")
	assert.Regexp(t, ".+culprits \\[\\{1,.*?2.*?\\}\\].+", err2.Error())
}

// The function will change the Feldman shares at the end of round 1
// making party 1 send a bad share to party 0
func sharedPartyUpdaterInjectingFeldmanError(party tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
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

	// Intercepting a round 1 broadcast message and changing a share
	// Making party 1 send bad share to party 0 in round 2
	if "KGRound1Message" == msg.Type() && party.PartyID().Index == 1 {
		if msg.GetFrom().Index != 1 && msg.IsBroadcast() {
			common.Logger.Debugf("current party: %v", party.PartyID())
			round := party.FirstRound().(*round1)
			retries := 0
			party.Lock()
			for (round.temp.shares == nil || len(round.temp.shares) < 1) && retries < 10 {
				common.Logger.Debug("waiting for parties to start...")
				time.Sleep(2 * time.Second)
				retries++
			}
			// injecting a (probably) incorrect share
			share := *round.temp.shares[0].Share
			round.temp.shares[0].Share = new(big.Int).Add(&share, big.NewInt(1))
			party.Unlock()
		}
	}

	if _, err := party.Update(pMsg); err != nil {
		errCh <- err
	}
}

// Testing abort identification in keygen.
// The test will change a Feldman share. When the bad share is identified,
// the player must be accused and finally blamed as culprit.
func TestIdentifiableAbortFeldmanShareFail(t *testing.T) {
	setUp("info")

	threshold := testThreshold
	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...",
			err)
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan LocalPartySaveData, len(pIDs))

	updater := sharedPartyUpdaterInjectingFeldmanError

	parties, errCh = initTheParties(pIDs, p2pCtx, threshold, fixtures, outCh, endCh, parties, errCh)

	// PHASE: keygen
keygen:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			// We expect an error
			assert.Error(t, err, "should have thrown an abort identification error")
			msg := err.Cause().Error()
			assert.Truef(t, strings.Contains(msg, "abort identification - error in the Feldman share verification"),
				"the error detected should have been for abort identification")
			mError := err.Cause().(*multierror.Error)
			assert.Greaterf(t, len(mError.Errors), 0, "too few errors returned", len(mError.Errors))
			vc := (mError.Errors[0]).(*tss.VictimAndCulprit)
			assert.Truef(t, vc.Victim != nil && vc.Victim.Index == 0,
				"the Victim should have been 0 but it was %v instead", vc.Victim.Index)
			assert.Truef(t, vc.Culprit != nil && vc.Culprit.Index == 1,
				"the culprit should have been 1 but it was %v instead", vc.Culprit.Index)
			break keygen

		case msg := <-outCh:
			if handleMessage(t, msg, parties, updater, errCh) {
				return
			}
		case <-endCh:
			assert.FailNow(t, "the end channel should not have returned")
			break keygen
		}
	}
}

// When a round 2 broadcast is detected, set an abort flag to trigger
// a false Feldman check failure.
func sharedPartyUpdaterFalseFeldmanFramingError(party tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
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

	// Intercepting a round 2 broadcast message
	if msg.Type() == "KGRound2Message2" && msg.IsBroadcast() && msg.GetFrom().Index == 0 && party.PartyID().Index == 1 {
		common.Logger.Debugf("party %s at round 2 - msg %s from %s", party.PartyID(), msg.Type(), msg.GetFrom())
		tlp := party.(*LocalParty)
		tlp.temp.abortTriggers = []ecdsautils.AbortTrigger{ecdsautils.FeldmanCheckFailure}
	}

	if _, err := party.Update(pMsg); err != nil {
		errCh <- err
	}

}

// Testing abort identification in keygen.
// The test will trigger a false Feldman check failure.
// The abort identification will label the case as the plaintiff trying to frame the accused player.
func TestIdentifiableAbortFalseFeldmanFraming(t *testing.T) {
	setUp("info")

	threshold := testThreshold
	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...",
			err)
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan LocalPartySaveData, len(pIDs))

	updater := sharedPartyUpdaterFalseFeldmanFramingError

	parties, errCh = initTheParties(pIDs, p2pCtx, threshold, fixtures, outCh, endCh, parties, errCh)

	// PHASE: keygen
keygen:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			// We expect an error
			assert.Error(t, err, "should have thrown an abort identification error")
			msg := err.Cause().Error()
			assert.Truef(t, strings.Contains(msg, "abort identification - the plaintiff party tried to frame the accused one"),
				"the error detected should have been a framing case in abort identification")
			mError := err.Cause().(*multierror.Error)
			assert.Greaterf(t, len(mError.Errors), 0, "too few errors returned", len(mError.Errors))
			vc := (mError.Errors[0]).(*tss.VictimAndCulprit)
			assert.EqualValues(t, vc.Culprit.Index, 1,
				"the 1st culprit should have been 1 but it was %d instead", vc.Culprit.Index)
			break keygen

		case msg := <-outCh:
			if handleMessage(t, msg, parties, updater, errCh) {
				return
			}
		case <-endCh:
			assert.FailNow(t, "the end channel should not have returned")
			break keygen
		}
	}
}

// When a round 2 broadcast is detected, set an abort flag to trigger
// a false Feldman check failure. Then taint the evidence by changing the share.
// It should blame the plaintiff during the abort identification.
func sharedPartyUpdaterTaintFeldmanShareFramingError(party tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
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

	// Intercepting a round 2 broadcast message and triggering a Feldman check failure
	if msg.Type() == "KGRound2Message2" && msg.IsBroadcast() && msg.GetFrom().Index == 0 && party.PartyID().Index == 1 {
		common.Logger.Debugf("intercepting message %s from %s", msg.Type(), msg.GetFrom())
		tlp := party.(*LocalParty)
		tlp.temp.abortTriggers = []ecdsautils.AbortTrigger{ecdsautils.FeldmanCheckFailure}
	} else if msg.Type() == "KGRound3MessageAbortMode" && msg.IsBroadcast() && party.PartyID().Index == 0 {
		common.Logger.Debugf("intercepting and changing message %s from %s", msg.Type(), msg.GetFrom())
		r3msg := pMsg.Content().(*KGRound3MessageAbortMode)

		// Tainting the signature
		r3msg.SuspiciousVsss[0].AuthSigPk.X[0] = 1 + r3msg.SuspiciousVsss[0].AuthSigPk.X[0]
		r3msg.SuspiciousVsss[0].AuthSigPk.X[1] = 1 + r3msg.SuspiciousVsss[0].AuthSigPk.X[1]
		r3msg.SuspiciousVsss[0].AuthSigPk.Y[0] = 1 + r3msg.SuspiciousVsss[0].AuthSigPk.Y[0]
		r3msg.SuspiciousVsss[0].AuthSigPk.Y[1] = 1 + r3msg.SuspiciousVsss[0].AuthSigPk.Y[1]
		meta := tss.MessageRouting{
			From:        msg.GetFrom(),
			To:          msg.GetTo(),
			IsBroadcast: true,
		}
		// repackaging the message
		pMsg = tss.NewMessage(meta, r3msg, tss.NewMessageWrapper(meta, r3msg))
	}

	if _, err := party.Update(pMsg); err != nil {
		errCh <- err
	}
}

// Testing abort identification in keygen.
// The test will taint the Feldman signature after triggering a false Feldman check failure.
// The abort identification will label the case as the plaintiff trying to frame the accused player.
func TestIdentifiableAbortTaintFeldmanShareFraming(t *testing.T) {
	setUp("info")

	threshold := testThreshold
	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...",
			err)
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan LocalPartySaveData, len(pIDs))

	updater := sharedPartyUpdaterTaintFeldmanShareFramingError

	parties, errCh = initTheParties(pIDs, p2pCtx, threshold, fixtures, outCh, endCh, parties, errCh)

	// PHASE: keygen
keygen:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			// We expect an error
			assert.Error(t, err, "should have thrown an abort identification error")
			msg := err.Cause().Error()
			assert.Truef(t, strings.Contains(msg, "abort identification - the plaintiff party tried to frame the accused one"),
				"the error detected should have been a framing case in abort identification")
			mError := err.Cause().(*multierror.Error)
			assert.Greaterf(t, len(mError.Errors), 0, "too few errors returned", len(mError.Errors))
			vc := (mError.Errors[0]).(*tss.VictimAndCulprit)
			assert.EqualValues(t, vc.Culprit.Index, 1,
				"the 1st culprit should have been 1 but it was %d instead", vc.Culprit.Index)
			break keygen

		case msg := <-outCh:
			if handleMessage(t, msg, parties, updater, errCh) {
				return
			}
		case <-endCh:
			assert.FailNow(t, "the end channel should not have returned")
			break keygen
		}
	}
}

func TestE2EConcurrentAndSaveFixtures(t *testing.T) {
	setUp("info")

	// tss.SetCurve(elliptic.P256())

	threshold := testThreshold
	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...",
			err)
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan LocalPartySaveData, len(pIDs))

	updater := test.SharedPartyUpdater

	startGR := runtime.NumGoroutine()

	parties, errCh = initTheParties(pIDs, p2pCtx, threshold, fixtures, outCh, endCh, parties, errCh)

	// PHASE: keygen
	var ended int32
keygen:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break keygen

		case msg := <-outCh:
			if handleMessage(t, msg, parties, updater, errCh) {
				return
			}

		case save := <-endCh:
			// SAVE a test fixture file for this P (if it doesn't already exist)
			// .. here comes a workaround to recover this party's index (it was removed from save data)
			index, err := save.OriginalIndex()
			assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
			tryWriteTestFixtureFile(t, index, save)

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)

				// combine shares for each Pj to get u
				u := new(big.Int)
				for j, Pj := range parties {
					pShares := make(vss.Shares, 0)
					for j2, P := range parties {
						if j2 == j {
							continue
						}
						vssMsgs := P.temp.kgRound2Message1s
						share := vssMsgs[j].Content().(*KGRound2Message1).Share
						shareStruct := &vss.Share{
							Threshold: threshold,
							ID:        P.PartyID().KeyInt(),
							Share:     new(big.Int).SetBytes(share),
						}
						pShares = append(pShares, shareStruct)
					}
					uj, err := pShares[:threshold+1].ReConstruct()
					assert.NoError(t, err, "vss.ReConstruct should not throw error")

					// uG test: u*G[j] == V[0]
					assert.Equal(t, uj, Pj.temp.ui)
					uG := crypto.ScalarBaseMult(tss.EC(), uj)
					assert.True(t, uG.Equals(Pj.temp.vs[0]), "ensure u*G[j] == V_0")

					// xj tests: BigXj == xj*G
					xj := Pj.data.Xi
					gXj := crypto.ScalarBaseMult(tss.EC(), xj)
					BigXj := Pj.data.BigXj[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")

					// fails if threshold cannot be satisfied (bad share)
					{
						badShares := pShares[:threshold]
						badShares[len(badShares)-1].Share.Set(big.NewInt(0))
						uj, err := pShares[:threshold].ReConstruct()
						assert.NoError(t, err)
						assert.NotEqual(t, parties[j].temp.ui, uj)
						BigXjX, BigXjY := tss.EC().ScalarBaseMult(uj.Bytes())
						assert.NotEqual(t, BigXjX, Pj.temp.vs[0].X())
						assert.NotEqual(t, BigXjY, Pj.temp.vs[0].Y())
					}
					u = new(big.Int).Add(u, uj)
				}

				// build ecdsa key pair
				pkX, pkY := save.ECDSAPub.X(), save.ECDSAPub.Y()
				pk := ecdsa.PublicKey{
					Curve: tss.EC(),
					X:     pkX,
					Y:     pkY,
				}
				sk := ecdsa.PrivateKey{
					PublicKey: pk,
					D:         u,
				}
				// test pub key, should be on curve and match pkX, pkY
				assert.True(t, sk.IsOnCurve(pkX, pkY), "public key must be on curve")

				// public key tests
				assert.NotZero(t, u, "u should not be zero")
				ourPkX, ourPkY := tss.EC().ScalarBaseMult(u.Bytes())
				assert.Equal(t, pkX, ourPkX, "pkX should match expected pk derived from u")
				assert.Equal(t, pkY, ourPkY, "pkY should match expected pk derived from u")
				t.Log("Public key tests done.")

				// make sure everyone has the same ECDSA public key
				for _, Pj := range parties {
					assert.Equal(t, pkX, Pj.data.ECDSAPub.X())
					assert.Equal(t, pkY, Pj.data.ECDSAPub.Y())
				}
				t.Log("Public key distribution test done.")

				// test sign/verify
				data := make([]byte, 32)
				for i := range data {
					data[i] = byte(i)
				}
				r, s, err := ecdsa.Sign(rand.Reader, &sk, data)
				assert.NoError(t, err, "sign should not throw an error")
				ok := ecdsa.Verify(&pk, data, r, s)
				assert.True(t, ok, "signature should be ok")
				t.Log("ECDSA signing test done.")

				t.Logf("Start goroutines: %d, End goroutines: %d", startGR, runtime.NumGoroutine())

				break keygen
			}
		}
	}
}

func sharedPartyUpdaterCheckPaillierPKSize(party tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
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

	// Intercepting a round 1 message
	if msg.Type() == "KGRound1Message" && msg.IsBroadcast() {
		common.Logger.Debugf("intercepting and changing message %s from %s", msg.Type(), msg.GetFrom())
		r1msg := pMsg.Content().(*KGRound1Message)
		pk := r1msg.UnmarshalPaillierPK()
		pk.N = big.NewInt(0).Rsh(pk.N, 13)
		// Tainting the message
		r1msg.PaillierN = pk.N.Bytes()
		meta := tss.MessageRouting{
			From:        msg.GetFrom(),
			To:          msg.GetTo(),
			IsBroadcast: true,
		}
		// repackaging the message
		pMsg = tss.NewMessage(meta, r1msg, tss.NewMessageWrapper(meta, r1msg))
	}

	if _, err := party.Update(pMsg); err != nil {
		errCh <- err
	}
}

// Test when a malicious player set the Paillier modulus (PK) too small.
func TestMaliciousPaillierPK(t *testing.T) {
	setUp("info")

	threshold := testThreshold
	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...",
			err)
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan LocalPartySaveData, len(pIDs))

	updater := sharedPartyUpdaterCheckPaillierPKSize

	parties, errCh = initTheParties(pIDs, p2pCtx, threshold, fixtures, outCh, endCh, parties, errCh)

	// PHASE: keygen
keygen:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			// We expect an error
			assert.Error(t, err, "should have thrown an error")
			msg := err.Cause().Error()
			assert.Truef(t, strings.Contains(msg, "the Paillier PK bit length is too small"),
				"the error detected should have contained a message related to the Paillier PK bit length")
			break keygen

		case msg := <-outCh:
			if handleMessage(t, msg, parties, updater, errCh) {
				return
			}
		case <-endCh:
			assert.FailNow(t, "the end channel should not have returned")
			break keygen
		}
	}
}
