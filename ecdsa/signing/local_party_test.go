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
	"sync/atomic"
	"testing"
	"time"

	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	zkpdec "github.com/binance-chain/tss-lib/crypto/zkp/dec"
	"github.com/btcsuite/btcd/btcec"
	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/test"
	"github.com/binance-chain/tss-lib/tss"
)

const (
	testParticipants = test.TestParticipants
	testThreshold    = test.TestThreshold
	maliciousPartySimulatingAbort = 3
	innocentPartySimulatingAbort = 1
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
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

/* TODO
//
func identifiedAbortUpdater(party tss.Party, msg tss.Message, parties []*LocalParty, errCh chan<- *tss.Error) {
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
	if strings.HasSuffix(msg.Type(),"PreSignRound3Message") && !msg.IsBroadcast() &&
		msg.GetFrom().Index == maliciousPartySimulatingAbort &&
		len(msg.GetTo()) > 0 && msg.GetTo()[0].Index==innocentPartySimulatingAbort {
		meta := tss.MessageRouting{
			From:        msg.GetFrom(),
			To:          msg.GetTo(),
			IsBroadcast: false,
		}
		i := msg.GetFrom().Index
		j := msg.GetTo()[0].Index

		common.Logger.Debugf("intercepting and changing message %s from %s", msg.Type(), msg.GetFrom())
		round := party.Round().(*presign3)
		otherRound := parties[i].Round().(*presign3)
		ec := tss.EC()
		q := ec.Params().N
		sk, pk := otherRound.key.PaillierSK, &otherRound.key.PaillierSK.PublicKey

		fakeki := common.GetRandomPositiveInt(q)
		// g := crypto.ScalarBaseMult(ec, big.NewInt(1))
		fakeKi, fake𝜌i, _ := sk.EncryptAndReturnRandomness(fakeki)
		// X := crypto.ScalarBaseMult(ec, fakeki)
		fakeΔi := round.temp.Γ.ScalarMult(fakeki)
		modN := common.ModInt(round.EC().Params().N)
		fake𝛿i := modN.Mul(fakeki, round.temp.𝛾i)

		common.Logger.Debugf(" test - fake proof - i:%v, j: %v, PK: %v, K(C): %v, Γ(g): %v, NTildej(NCap): %v, " +
			"H1j(s): %v, H2j(t): %v, ki(x): %v, 𝜌i: %v -- fakeΔi:%v",
			parties[i],parties[j], common.FormatBigInt(pk.N),
			common.FormatBigInt(fakeKi),
			crypto.FormatECPoint(round.temp.Γ),
			common.FormatBigInt(round.key.NTildej[j]), common.FormatBigInt(round.key.H1j[j]), common.FormatBigInt(round.key.H2j[j]),
			common.FormatBigInt(fakeki), common.FormatBigInt(fake𝜌i), crypto.FormatECPoint(fakeΔi))
		proof, errP := zkplogstar.NewProof(ec, pk, fakeKi, fakeΔi, round.temp.Γ, round.key.NTildej[j],
			round.key.H1j[j], round.key.H2j[j], fakeki, fake𝜌i)
		if errP!=nil {
			common.Logger.Errorf("error changing message %s from %s", msg.Type(), msg.GetFrom())
		}

		verified := proof.Verify(ec, pk, fakeKi, fakeΔi, round.temp.Γ, round.key.NTildej[j],round.key.H1j[j],round.key.H2j[j])
		common.Logger.Debugf(" i: %v, j: %v, verified? %v", parties[i], parties[j], verified)
		round.temp.Δi = fakeΔi
		round.temp.r1msgK[i] = fakeKi
		r3msg := NewPreSignRound3Message(msg.GetTo()[0], msg.GetFrom(), fake𝛿i, fakeΔi, proof)
		// repackaging the malicious message
		pMsg = tss.NewMessage(meta, r3msg.Content(), tss.NewMessageWrapper(meta, r3msg.Content()))
	}

	common.Logger.Debugf("updater party:%v, pMsg: %v", party, pMsg)
	if _, errUpdate := party.Update(pMsg); errUpdate != nil {
			errCh <- errUpdate
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

signing:
	for {
		select {
		case errS := <-errCh:
			assert.NotNil(t, errS, "there should have been an error")
			assert.NotNil(t, errS.Culprits(), "here should have been one culprit")
			assert.EqualValues(t, len(errS.Culprits()), 1, "there should have been one culprit")
			assert.NotNil(t, errS.Culprits()[0], "there should have been one culprit")
			assert.EqualValues(t, errS.Culprits()[0].Index, maliciousPartySimulatingAbort, "error in test in identification of the malicious party")
			break signing

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, parties, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, parties, errCh)
			}

		case sigData := <-endCh:
			common.Logger.Debugf("sigData: %v", sigData)
			assert.FailNow(t, "signing should not succeed in this test")
			break signing
		}
	}
}
*/

func TestIdAbortSimulateRound7(test *testing.T) {
    var err error
	ec := tss.S256()
	q := ec.Params().N

	modN := common.ModInt(ec.Params().N)
	var modMul = func(N, a, b *big.Int) * big.Int {
		_N := common.ModInt(big.NewInt(0).Set(N))
		return _N.Mul(a, b)
	}
	var modQ3Mul = func(a, b *big.Int) * big.Int {
		 q3 := common.ModInt(new(big.Int).Mul(q, new(big.Int).Mul(q, q)))
		 return q3.Mul(a, b)
	}
	var q3Add = func(a, b *big.Int) * big.Int {
		q3 := new(big.Int).Mul(q, new(big.Int).Mul(q, q))
		return q3.Add(a, b)
	}
	var i,j int
	n := 4

	K := make([]*big.Int, n)
	k := make([]*big.Int, n)
	𝜌 := make([]*big.Int, n)
	𝛾 := make([]*big.Int, n)
	// x := make([]*big.Int, n)
	Γ := make([]*crypto.ECPoint, n)
	sk := make([]*paillier.PrivateKey, n)
	pk := make([]*paillier.PublicKey, n)
	NCap := make([]*big.Int, n)
	s := make([]*big.Int, n)
	t := make([]*big.Int, n)

	for i=0; i<n; i++ {
		sk[i], pk[i], err = paillier.GenerateKeyPair(1024*2, time.Minute*10)
		if err!= nil {
			test.Errorf("error %v", err)
			test.FailNow()
		}
		primes := [2]*big.Int{common.GetRandomPrimeInt(1024), common.GetRandomPrimeInt(1024)}
		NCap[i], s[i], t[i], err = crypto.GenerateNTildei(primes)
		if err!= nil {
			test.Errorf("error %v", err)
			test.FailNow()
		}
		k[i] = common.GetRandomPositiveInt(ec.Params().N)
		K[i], 𝜌[i], err = sk[i].EncryptAndReturnRandomness(k[i])
		𝛾[i] = common.GetRandomPositiveInt(q)
		Γ[i] = crypto.ScalarBaseMult(ec, 𝛾[i])
		if err!= nil {
			test.Errorf("error %v", err)
			test.FailNow()
		}
	}
	for i=0; i<n/2; i++ {
		Gi, 𝜈i, _ := sk[i].EncryptAndReturnRandomness(𝛾[i])

		// Fig 7. Output.2
		Hi, err := pk[i].HomoMult(k[i], Gi)
		if err!= nil {
			test.Errorf("error %v", err)
			test.FailNow()
		}

		DeltaShareEnc := Hi
		secretProduct := big.NewInt(1).Exp(𝜈i, k[i], pk[i].NSquare())
		encryptedValueSum := modQ3Mul(k[i],𝛾[i])

		proof1, err := zkpdec.NewProof(ec, pk[i], Hi, modN.Add(zero, encryptedValueSum), NCap[i], s[i], t[i], encryptedValueSum, secretProduct)
		ok1 := proof1.Verify(ec, pk[i], Hi, modN.Add(zero, encryptedValueSum), NCap[i], s[i], t[i]) // TODO
		assert.True(test, ok1, "proof must verify")

		for j=0; j<n; j++ {
			if j == i {
				continue
			}

			DeltaMtAij, errMta := NewMtA(ec, K[i], 𝛾[j], Γ[j], pk[i], pk[j], NCap[i], s[i], t[i])
			if errMta!= nil {
				test.Errorf("error %v", errMta)
				test.FailNow()
			}

			𝜌𝛾s := modMul(pk[i].NSquare(), big.NewInt(1).Exp(𝜌[i], 𝛾[j], pk[i].NSquare()), DeltaMtAij.Sij)
			𝛾k𝛽ʹ := q3Add(DeltaMtAij.BetaNeg, modQ3Mul(𝛾[j],k[i]))

			proofD, err1 := zkpdec.NewProof(ec, pk[i], DeltaMtAij.Dji, modN.Add(zero,𝛾k𝛽ʹ), NCap[i], s[i], t[i], 𝛾k𝛽ʹ, 𝜌𝛾s)
			assert.NoError(test, err1)
			okD := proofD.Verify(ec, pk[i], DeltaMtAij.Dji, modN.Add(zero,𝛾k𝛽ʹ), NCap[i], s[i], t[i])
			assert.True(test, okD, "proof must verify")

			// F
			Fji, rij, err2 := pk[i].EncryptAndReturnRandomness(DeltaMtAij.BetaNeg)
			if err2!= nil {
				test.Errorf("error %v", err2)
				test.FailNow()
			}

			// DF
			𝜌𝛾sr := modMul(pk[i].NSquare(), 𝜌𝛾s, rij)
			𝛾k2𝛽ʹ := q3Add(𝛾k𝛽ʹ, DeltaMtAij.BetaNeg)
			DF, err3 := pk[i].HomoAdd(DeltaMtAij.Dji, Fji)
			if err3!= nil {
				test.Errorf("error %v", err3)
				test.FailNow()
			}

			proof2, err4 := zkpdec.NewProof(ec, pk[i], DF, modN.Add(zero, 𝛾k2𝛽ʹ), NCap[i], s[i], t[i], 𝛾k2𝛽ʹ, 𝜌𝛾sr)
			if err4!= nil {
				test.Errorf("error %v", err4)
				test.FailNow()
			}
			ok2 := proof2.Verify(ec, pk[i], DF, modN.Add(zero, 𝛾k2𝛽ʹ), NCap[i], s[i], t[i])
			assert.True(test, ok2, "proof must verify")

			secretProduct = modMul(pk[i].NSquare(), 𝜌𝛾sr, secretProduct)
			encryptedValueSum = q3Add(𝛾k2𝛽ʹ, encryptedValueSum)

			DeltaShareEnc, err = pk[i].HomoAdd(DF, DeltaShareEnc)
			if err!= nil {
				test.Errorf("error %v", err)
				test.FailNow()
			}

		}
		proofDeltaShare, err6 := zkpdec.NewProof(ec, pk[i], DeltaShareEnc, modN.Add(zero, encryptedValueSum), NCap[i], s[i], t[i], encryptedValueSum, secretProduct)
		if err6!= nil {
			test.Errorf("error %v", err6)
			test.FailNow()
		}
		ok6 := proofDeltaShare.Verify(ec, pk[i], DeltaShareEnc, modN.Add(zero, encryptedValueSum), NCap[i], s[i], t[i])
		assert.True(test, ok6, "proof must verify")
	}
}


func TestFillTo32BytesInPlace(t *testing.T) {
	s := big.NewInt(123456789)
	normalizedS := padToLengthBytesInPlace(s.Bytes(), 32)
	assert.True(t, big.NewInt(0).SetBytes(normalizedS).Cmp(s) == 0)
	assert.Equal(t, 32, len(normalizedS))
	assert.NotEqual(t, 32, len(s.Bytes()))
}
