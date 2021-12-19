// Copyright © 2021 Swingby

package signing

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/ckd"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/test"
	"github.com/binance-chain/tss-lib/tss"
)

// For more information about child key derivation see https://github.com/binance-chain/tss-lib/issues/104
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki .
// As mentioned in the Jira ticket above, we only use non-hardened derived keys.
// Differently from the Jira ticket, our code only updates xi and bigXj
// in signing. Our code does not require updates u_i or the VSS commitment to the polynomial either,
// as these are not used during the signing phase.
func TestHDKeyDerivation(t *testing.T) {
	setUp("debug")
	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))
	assert.NotNil(t, keys[0].ECDSAPub, "the first ECDSA public key must not be null")

	// build ecdsa key pair
	parentPkX, parentPkY := keys[0].ECDSAPub.X(), keys[0].ECDSAPub.Y()
	pk := ecdsa.PublicKey{
		Curve: tss.EC(),
		X:     parentPkX,
		Y:     parentPkY,
	}

	// setting the chain code to a random positive number smaller than the maximum allowed of 32 bytes
	chainCode := make([]byte, 32)
	max32b := new(big.Int).Lsh(new(big.Int).SetUint64(1), 256)
	max32b = new(big.Int).Sub(max32b, new(big.Int).SetUint64(1))
	common.GetRandomPositiveInt(max32b).FillBytes(chainCode)

	extendedParentPk := &ckd.ExtendedKey{
		PublicKey:  pk,
		Depth:      0,
		ChildIndex: 0,
		ChainCode:  chainCode,
	}

	// Using an arbitrary path of indices. In the common notation, this would be "m/13/209/3".
	il, extendedChildPk, errorDerivation := ckd.DeriveChildKeyFromHierarchy([]uint32{13, 209, 3}, extendedParentPk,
		tss.EC().Params().N, tss.EC())
	assert.NoErrorf(t, errorDerivation, "there should not be an error deriving the child public key")

	keyDerivationDelta := il

	err = UpdatePublicKeyAndAdjustBigXj(keyDerivationDelta, keys, &extendedChildPk.PublicKey, tss.EC())
	assert.NoErrorf(t, err, "there should not be an error setting the derived keys")

	// PHASE: signing
	// use a shuffled selection of the list of parties for this test
	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	msg, parties, errCh := initTheParties(signPIDs, p2pCtx, threshold, keys, keyDerivationDelta, outCh, endCh, parties, errCh)

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
				bigRX, bigRY := parties[0].temp.BigR.X(), parties[0].temp.BigR.Y()
				bigR := crypto.NewECPointNoCurveCheck(tss.EC(), bigRX, bigRY)

				r := parties[0].temp.Rx
				fmt.Printf("sign result: R(%s, %s), r=%s\n", bigR.X().String(), bigR.Y().String(), r.String())

				modN := common.ModInt(tss.EC().Params().N)

				// BEGIN check s correctness
				sumS := big.NewInt(0)
				for _, p := range parties {
					sumS = modN.Add(sumS, p.temp.SigmaShare)
				}
				fmt.Printf("S: %s\n", sumS.String())
				// END check s correctness

				ok := ecdsa.Verify(&extendedChildPk.PublicKey, msg.Bytes(), bigR.X(), sumS)
				assert.True(t, ok, "ecdsa verify must pass")

				btcecSig := &btcec.Signature{R: r, S: sumS}
				btcecSig.Verify(msg.Bytes(), (*btcec.PublicKey)(&extendedChildPk.PublicKey))
				assert.True(t, ok, "ecdsa verify 2 must pass")

				t.Log("ECDSA signing test done.")
				// END ECDSA verify

				break signing
			}
		}
	}
}
