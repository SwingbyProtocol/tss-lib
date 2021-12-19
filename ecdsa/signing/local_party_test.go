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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	zkpdec "github.com/binance-chain/tss-lib/crypto/zkp/dec"
	zkplogstar "github.com/binance-chain/tss-lib/crypto/zkp/logstar"
	"github.com/btcsuite/btcd/btcec"
	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/test"
	"github.com/binance-chain/tss-lib/tss"
)

const (
	testParticipants            = test.TestParticipants
	testThreshold               = test.TestThreshold
	culpritPartySimulatingAbort = 2
	victimPartySimulatingAbort  = 1
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
}

func initTheParties(signPIDs tss.SortedPartyIDs, p2pCtx *tss.PeerContext, threshold int,
	keys []keygen.LocalPartySaveData, keyDerivationDelta *big.Int, outCh chan tss.Message,
	endCh chan common.SignatureData, parties []*LocalParty,
	errCh chan *tss.Error) (*big.Int, []*LocalParty, chan *tss.Error) {
	// init the parties
	msg := common.GetRandomPrimeInt(256)
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.EC(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

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
	endCh := make(chan common.SignatureData, len(signPIDs))
	dumpCh := make(chan tss.Message, len(signPIDs))

	updater := test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		keyDerivationDelta := big.NewInt(0)
		P := NewLocalParty(big.NewInt(42), params, keys[i], keyDerivationDelta, outCh, endCh).(*LocalParty)
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

		case dtemp := <-dumpCh:
			fmt.Println("got from dump")
			fmt.Println(dtemp)
			// P = ...... with dtemp
			// P.start

		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants", ended)
				R := parties[0].temp.BigR
				r := parties[0].temp.Rx
				fmt.Printf("sign result: R(%s, %s), r=%s\n", R.X().String(), R.Y().String(), r.String())

				modN := common.ModInt(tss.S256().Params().N)

				// BEGIN check s correctness
				sumS := big.NewInt(0)
				for _, p := range parties {
					sumS = modN.Add(sumS, p.temp.SigmaShare)
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
				ok := ecdsa.Verify(&pk, big.NewInt(42).Bytes(), R.X(), sumS)
				assert.True(t, ok, "ecdsa verify must pass")
				t.Log("ECDSA signing test done.")
				// END ECDSA verify

				break signing
			}
		}
	}
}

func TestE2EWithHDKeyDerivation(t *testing.T) {
	setUp("info")
	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	chainCode := make([]byte, 32)
	max32b := new(big.Int).Lsh(new(big.Int).SetUint64(1), 256)
	max32b = new(big.Int).Sub(max32b, new(big.Int).SetUint64(1))
	common.GetRandomPositiveInt(max32b).FillBytes(chainCode)

	il, extendedChildPk, errorDerivation := derivingPubkeyFromPath(keys[0].ECDSAPub, chainCode, []uint32{12, 209, 3}, btcec.S256())
	assert.NoErrorf(t, errorDerivation, "there should not be an error deriving the child public key")

	keyDerivationDelta := il

	err = UpdatePublicKeyAndAdjustBigXj(keyDerivationDelta, keys, &extendedChildPk.PublicKey, btcec.S256())
	assert.NoErrorf(t, err, "there should not be an error setting the derived keys")

	// PHASE: signing
	// use a shuffled selection of the list of parties for this test
	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))
	// dumpCh := make(chan tss.Message, len(signPIDs))

	updater := test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		P := NewLocalParty(big.NewInt(42), params, keys[i], keyDerivationDelta, outCh, endCh).(*LocalParty)
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
				R := parties[0].temp.BigR
				r := parties[0].temp.Rx
				fmt.Printf("sign result: R(%s, %s), r=%s\n", R.X().String(), R.Y().String(), r.String())

				modN := common.ModInt(tss.S256().Params().N)

				// BEGIN check s correctness
				sumS := big.NewInt(0)
				for _, p := range parties {
					sumS = modN.Add(sumS, p.temp.SigmaShare)
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
				ok := ecdsa.Verify(&pk, big.NewInt(42).Bytes(), R.X(), sumS)
				assert.True(t, ok, "ecdsa verify must pass")
				t.Log("ECDSA signing test done.")
				// END ECDSA verify

				break signing
			}
		}
	}
}

//
func identifiedAbortUpdater(party tss.Party, msg tss.Message, parties []*LocalParty, errCh chan<- *tss.Error,
	partyMutex *sync.RWMutex) {
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

	// Intercepting a round 3 message to inject a bad zk-proof and trigger an abort
	if strings.HasSuffix(msg.Type(), "PreSignRound3Message") && !msg.IsBroadcast() &&
		msg.GetFrom().Index == culpritPartySimulatingAbort &&
		len(msg.GetTo()) > 0 && msg.GetTo()[0].Index == victimPartySimulatingAbort {
		meta := tss.MessageRouting{
			From:        msg.GetFrom(),
			To:          msg.GetTo(),
			IsBroadcast: false,
		}
		i := msg.GetFrom().Index  // culprit
		j := msg.GetTo()[0].Index // victim

		victimParty := party
		common.Logger.Debugf("intercepting and changing message %s from %s (culprit) to party: %v (victim)",
			msg.Type(), msg.GetFrom(), victimParty)
		ok := false
		var roundVictim *presign3
		for {
			partyMutex.RLock()
			if roundVictim, ok = victimParty.Round().(*presign3); !ok {
				partyMutex.RUnlock()
				time.Sleep(5 * time.Second)
			} else {
				partyMutex.RUnlock()
				break
			}
		}

		var otherRoundCulprit *presign3
		ok = false
		partyMutex.RLock()
		if otherRoundCulprit, ok = parties[i].Round().(*presign3); !ok {
			r4 := parties[i].Round().(*sign4)
			otherRoundCulprit = r4.presign3
		}
		partyMutex.RUnlock()
		ec := tss.EC()
		q := ec.Params().N
		sk, pk := otherRoundCulprit.key.PaillierSK, &otherRoundCulprit.key.PaillierSK.PublicKey

		fakeki := common.GetRandomPositiveInt(q)
		fakeKi, fake𝜌i, _ := sk.EncryptAndReturnRandomness(fakeki)
		fakeΔi := roundVictim.temp.Γ.ScalarMult(fakeki)
		modN := common.ModInt(roundVictim.EC().Params().N)
		fake𝛿i := modN.Mul(fakeki, roundVictim.temp.𝛾i)

		common.Logger.Debugf(" test - fake proof - i:%v, j: %v, PK: %v, K(C): %v, Γ(g): %v, NTildej(NCap): %v, "+
			"H1j(s): %v, H2j(t): %v, ki(x): %v, 𝜌i: %v -- fakeΔi:%v",
			parties[i], parties[j], common.FormatBigInt(pk.N),
			common.FormatBigInt(fakeKi),
			crypto.FormatECPoint(roundVictim.temp.Γ),
			common.FormatBigInt(roundVictim.key.NTildej[j]), common.FormatBigInt(roundVictim.key.H1j[j]), common.FormatBigInt(roundVictim.key.H2j[j]),
			common.FormatBigInt(fakeki), common.FormatBigInt(fake𝜌i), crypto.FormatECPoint(fakeΔi))
		proof, errP := zkplogstar.NewProof(ec, pk, fakeKi, fakeΔi, roundVictim.temp.Γ, roundVictim.key.NTildej[j],
			roundVictim.key.H1j[j], roundVictim.key.H2j[j], fakeki, fake𝜌i)
		if errP != nil {
			common.Logger.Errorf("error changing message %s from %s", msg.Type(), msg.GetFrom())
		}

		verified := proof.Verify(ec, pk, fakeKi, fakeΔi, roundVictim.temp.Γ, roundVictim.key.NTildej[j], roundVictim.key.H1j[j], roundVictim.key.H2j[j])
		common.Logger.Debugf(" i: %v, j: %v, verified? %v", parties[i], parties[j], verified)
		r3msg := NewPreSignRound3Message(msg.GetTo()[0], msg.GetFrom(), fake𝛿i, fakeΔi, proof)
		// repackaging the malicious message
		pMsg = tss.NewMessage(meta, r3msg.Content(), tss.NewMessageWrapper(meta, r3msg.Content()))
	}

	common.Logger.Debugf("updater party:%v, pMsg: %v", party, pMsg)
	isVictim := partyMutex != nil // && len(msg.GetTo()) > 0 && msg.GetTo()[0] != nil && msg.GetTo()[0].Index == victimPartySimulatingAbort
	if isVictim {
		partyMutex.Lock()
	}
	if _, errUpdate := party.Update(pMsg); errUpdate != nil {
		errCh <- errUpdate
	}
	if isVictim {
		partyMutex.Unlock()
	}
}

func TestAbortIdentification(t *testing.T) {
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
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := identifiedAbortUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		keyDerivationDelta := big.NewInt(0)
		P := NewLocalParty(big.NewInt(42), params, keys[i], keyDerivationDelta, outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}
	var partyMutex sync.RWMutex

signing:
	for {
		select {
		case errS := <-errCh:
			ok := true
			if ok = assert.NotNil(t, errS, "there should have been an error"); !ok {
				t.FailNow()
			}
			if ok = assert.NotNil(t, errS.Culprits(), "here should have been one culprit"); !ok {
				t.FailNow()
			}
			if ok = assert.EqualValues(t, 1, len(errS.Culprits()), "there should have been one culprit"); !ok {
				t.FailNow()
			}
			if ok = assert.NotNil(t, errS.Culprits()[0], "there should have been one culprit"); !ok {
				t.FailNow()
			}
			if ok = assert.EqualValues(t, culpritPartySimulatingAbort, errS.Culprits()[0].Index, "error in test in identification of the malicious party"); !ok {
				t.FailNow()
			}
			break signing

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, parties, errCh, &partyMutex)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, parties, errCh, &partyMutex)
			}

		case sigData := <-endCh:
			common.Logger.Debugf("sigData: %v", sigData)
			assert.FailNow(t, "signing should not succeed in this test")
			break signing
		}
	}
}

func TestIdAbortSimulateRound7(test *testing.T) {
	setUp("debug")
	var err error
	ec := tss.S256()
	q := ec.Params().N

	modN := common.ModInt(ec.Params().N)
	var modMul = func(N, a, b *big.Int) *big.Int {
		_N := common.ModInt(big.NewInt(0).Set(N))
		return _N.Mul(a, b)
	}
	var modQ3Mul = func(a, b *big.Int) *big.Int {
		q3 := common.ModInt(new(big.Int).Mul(q, new(big.Int).Mul(q, q)))
		return q3.Mul(a, b)
	}
	var q3Add = func(a, b *big.Int) *big.Int {
		q3 := new(big.Int).Mul(q, new(big.Int).Mul(q, q))
		return q3.Add(a, b)
	}
	var i, j int

	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	n := len(signPIDs)

	K := make([]*big.Int, n)
	k := make([]*big.Int, n)
	𝜌 := make([]*big.Int, n)
	𝛾 := make([]*big.Int, n)
	Γ := make([]*crypto.ECPoint, n)
	sk := make([]*paillier.PrivateKey, n)
	pk := make([]*paillier.PublicKey, n)
	NCap := make([]*big.Int, n)
	s := make([]*big.Int, n)
	t := make([]*big.Int, n)
	D := make([][]*MtAOut, n)
	𝛽 := make([][]*big.Int, n)
	𝛽ʹ := make([][]*big.Int, n)

	if err != nil {
		test.Errorf("error %v", err)
		test.FailNow()
	}

	for i = 0; i < len(signPIDs); i++ {
		sk[i], pk[i] = keys[i].PaillierSK, &keys[i].PaillierSK.PublicKey

		NCap[i], s[i], t[i] = keys[i].NTildei, keys[i].H1i, keys[i].H2i
		k[i] = common.GetRandomPositiveInt(ec.Params().N)
		K[i], 𝜌[i], err = sk[i].EncryptAndReturnRandomness(k[i])
		𝛾[i] = common.GetRandomPositiveInt(q)
		Γ[i] = crypto.ScalarBaseMult(ec, 𝛾[i])

		D[i] = make([]*MtAOut, n)
		𝛽[i] = make([]*big.Int, n)
		𝛽ʹ[i] = make([]*big.Int, n)
		if err != nil {
			test.Errorf("error %v", err)
			test.FailNow()
		}
	}
	for i = 0; i < len(signPIDs); i++ {
		for j = 0; j < len(signPIDs); j++ {
			if j == i {
				continue
			}

			DeltaMtAij, errMta := NewMtA(ec, K[j], 𝛾[i], Γ[i], pk[j], pk[i], NCap[j], s[j], t[j])
			if errMta != nil {
				test.Errorf("error %v", errMta)
				test.FailNow()
			}
			D[j][i] = DeltaMtAij
			𝛽ʹ[i][j] = DeltaMtAij.BetaNeg
			𝛽[i][j] = DeltaMtAij.Beta
		}
	}

	for i = 0; i < len(signPIDs); i++ {
		Gi, 𝜈i, _ := sk[i].EncryptAndReturnRandomness(𝛾[i])

		// Fig 7. Output.2
		Hi, err := pk[i].HomoMult(k[i], Gi)
		if err != nil {
			test.Errorf("error %v", err)
			test.FailNow()
		}

		DeltaShareEnc := Hi
		secretProduct := big.NewInt(1).Exp(𝜈i, k[i], pk[i].NSquare())
		encryptedValueSum := modQ3Mul(k[i], 𝛾[i])

		{
			proof, _ := zkpdec.NewProof(ec, pk[i], Hi, modN.Add(zero, encryptedValueSum), NCap[i], s[i], t[i], encryptedValueSum, secretProduct)
			ok := proof.Verify(ec, pk[i], Hi, modN.Add(zero, encryptedValueSum), NCap[i], s[i], t[i])
			assert.True(test, ok, "zkpdec proof must verify")
		}

		for j = 0; j < len(signPIDs); j++ {
			if j == i {
				continue
			}

			𝜌𝛾s := modMul(pk[i].NSquare(), big.NewInt(1).Exp(𝜌[i], 𝛾[j], pk[i].NSquare()), D[i][j].Sij)
			𝛾k𝛽ʹ := q3Add(𝛽ʹ[j][i], modQ3Mul(𝛾[j], k[i]))

			common.Logger.Debugf("ut NewMtAHardcoded D(i%v,j:%v): %v, 𝛽ji: %v, 𝛽ʹji: %v, sij:%v, 𝛾k𝛽ʹ:%v, 𝜌𝛾s: %v, 𝛾j:%v", i, j, common.FormatBigInt(D[i][j].Dji),
				common.FormatBigInt(𝛽[j][i]), common.FormatBigInt(𝛽ʹ[j][i]), common.FormatBigInt(D[i][j].Sij), common.FormatBigInt(𝛾k𝛽ʹ),
				common.FormatBigInt(𝜌𝛾s), common.FormatBigInt(𝛾[j]))
			{
				proofD, err1 := zkpdec.NewProof(ec, pk[i], D[i][j].Dji, modN.Add(zero, 𝛾k𝛽ʹ), NCap[i], s[i], t[i], 𝛾k𝛽ʹ, 𝜌𝛾s)
				assert.NoError(test, err1)
				okD := proofD.Verify(ec, pk[i], D[i][j].Dji, modN.Add(zero, 𝛾k𝛽ʹ), NCap[i], s[i], t[i])
				assert.True(test, okD, "proof must verify")
			}

			// F
			var Fji *big.Int
			Fji, D[i][j].Rij, err = pk[i].EncryptAndReturnRandomness(𝛽[i][j])
			if err != nil {
				test.Errorf("error %v", err)
				test.FailNow()
			}

			common.Logger.Debugf("ut F(j:%v,i:%v): %v, 𝛽ij: %v, rij:%v", j, i, common.FormatBigInt(Fji),
				common.FormatBigInt(𝛽[i][j]), common.FormatBigInt(D[i][j].Rij))

			// DF
			𝜌𝛾sr := modMul(pk[i].NSquare(), 𝜌𝛾s, D[i][j].Rij)
			𝛾k𝛽ʹ𝛽 := q3Add(𝛾k𝛽ʹ, 𝛽[i][j])
			DF, err3 := pk[i].HomoAdd(D[i][j].Dji, Fji)
			if err3 != nil {
				test.Errorf("error %v", err3)
				test.FailNow()
			}

			{
				common.Logger.Debugf("ut zkpdecNewProof DF(i:%v,j:%v): %v, rij: %v, 𝛾k𝛽ʹ𝛽:%v, 𝛾k𝛽ʹ:%v, 𝛽ij:%v, 𝜌𝛾sr:%v", i, j, common.FormatBigInt(DF),
					common.FormatBigInt(D[i][j].Rij), common.FormatBigInt(𝛾k𝛽ʹ𝛽),
					common.FormatBigInt(𝛾k𝛽ʹ), common.FormatBigInt(𝛽[i][j]),
					common.FormatBigInt(𝜌𝛾sr))

				proof2, err4 := zkpdec.NewProof(ec, pk[i], DF, modN.Add(zero, 𝛾k𝛽ʹ𝛽), NCap[i], s[i], t[i], 𝛾k𝛽ʹ𝛽, 𝜌𝛾sr)
				if err4 != nil {
					test.Errorf("error %v", err4)
					test.FailNow()
				}
				ok2 := proof2.Verify(ec, pk[i], DF, modN.Add(zero, 𝛾k𝛽ʹ𝛽), NCap[i], s[i], t[i])
				if okA := assert.True(test, ok2, "proof must verify"); !okA {
					test.FailNow()
				}
			}

			secretProduct = modMul(pk[i].NSquare(), 𝜌𝛾sr, secretProduct)
			encryptedValueSum = q3Add(𝛾k𝛽ʹ𝛽, encryptedValueSum)

			DeltaShareEnc, err = pk[i].HomoAdd(DF, DeltaShareEnc)
			if err != nil {
				test.Errorf("error %v", err)
				test.FailNow()
			}

		}
		{
			common.Logger.Debugf("ut zkpdecNewProof i:%v, j:%v, r6msgDeltaShareEnc[i:%v]: %v, encryptedValueSum: %v, secretProduct: %v", i, j, i,
				common.FormatBigInt(DeltaShareEnc),
				common.FormatBigInt(encryptedValueSum), common.FormatBigInt(secretProduct))

			proofDeltaShare, err6 := zkpdec.NewProof(ec, pk[i], DeltaShareEnc, modN.Add(zero, encryptedValueSum), NCap[i], s[i], t[i], encryptedValueSum, secretProduct)
			if err6 != nil {
				test.Errorf("error %v", err6)
				test.FailNow()
			}
			ok6 := proofDeltaShare.Verify(ec, pk[i], DeltaShareEnc, modN.Add(zero, encryptedValueSum), NCap[i], s[i], t[i])
			assert.True(test, ok6, "proof must verify")
		}
	}
}

func TestFillTo32BytesInPlace(t *testing.T) {
	s := big.NewInt(123456789)
	normalizedS := padToLengthBytesInPlace(s.Bytes(), 32)
	assert.True(t, big.NewInt(0).SetBytes(normalizedS).Cmp(s) == 0)
	assert.Equal(t, 32, len(normalizedS))
	assert.NotEqual(t, 32, len(s.Bytes()))
}
