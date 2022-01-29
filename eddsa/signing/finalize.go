// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/agl/ed25519/edwards25519"
	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v2/schnorr"
)

func (round *finalization) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	ok := false
	var s *big.Int
	var sumS *[32]byte

	_, isTwistedEdwardsCurve := round.Params().EC().(*edwards.TwistedEdwardsCurve)
	isSecp256k1Curve := strings.Compare("secp256k1", round.Params().EC().Params().Name) == 0

	if isTwistedEdwardsCurve {
		sumS = bigIntToEncodedBytes(&round.temp.si)
		for j := range round.Parties().IDs() {
			round.ok[j] = true
			if j == round.PartyID().Index {
				continue
			}
			r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)
			sjBytes := bigIntToEncodedBytes(r3msg.UnmarshalS())
			var tmpSumS [32]byte
			edwards25519.ScMulAdd(&tmpSumS, sumS, bigIntToEncodedBytes(big.NewInt(1)), sjBytes)

			sumS = &tmpSumS
		}
		s = encodedBytesToBigInt(sumS)
	} else if isSecp256k1Curve {
		sumSInt := &round.temp.si
		modN := common.ModInt(tss.S256().Params().N)
		for j := range round.Parties().IDs() {
			round.ok[j] = true
			if j == round.PartyID().Index {
				continue
			}
			r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)
			sumSInt = modN.Add(sumSInt, r3msg.UnmarshalS())
		}
		// if we adjusted R by adding aG to find R with an even Y coordinate, add a to s also.
		s = modN.Add(sumSInt, big.NewInt(int64(round.temp.a)))
	}

	// save the signature for final output
	signature := new(common.ECSignature)
	if isTwistedEdwardsCurve {
		signature.Signature = append(bigIntToEncodedBytes(round.temp.r)[:], sumS[:]...)
		signature.R = bigIntToEncodedBytes(round.temp.r)[:]
		signature.S = bigIntToEncodedBytes(s)[:]
	} else if isSecp256k1Curve {
		var r32b, s32b [32]byte
		encode32bytes(round.temp.r, &r32b)
		encode32bytes(s, &s32b)
		signature.Signature = append(r32b[:], s32b[:]...)
		signature.R = r32b[:]
		signature.S = s32b[:]
	}
	signature.M = round.temp.m.Bytes()

	round.data.R = signature.R
	round.data.S = signature.S
	round.data.Signature = append(round.data.R, round.data.S...)

	if isTwistedEdwardsCurve {
		pk := edwards.PublicKey{
			Curve: round.Params().EC(),
			X:     round.key.EDDSAPub.X(),
			Y:     round.key.EDDSAPub.Y(),
		}
		common.Logger.Debugf("finalize - r: %v, s:%v", hex.EncodeToString(round.temp.r.Bytes()),
			hex.EncodeToString(s.Bytes()))
		ok = edwards.Verify(&pk, round.temp.m.Bytes(), round.temp.r, s)
		if !ok {
			return round.WrapError(fmt.Errorf("edwards signature verification failed"))
		}
	} else if isSecp256k1Curve {
		pk1 := round.key.EDDSAPub.ToSecp256k1PubKey().ToECDSA()
		pk2 := secp256k1.PublicKey(*pk1)
		if ok = schnorr.Verify(&pk2, round.temp.m.Bytes(), round.temp.r, s); !ok {
			return round.WrapError(fmt.Errorf("schnorr signature verification failed"))
		}
	}
	round.end <- *round.data
	return nil
}

func (round *finalization) CanAccept(_ tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *finalization) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *finalization) NextRound() tss.Round {
	return nil // finished!
}

func encode32bytes(i *big.Int, buff *[32]byte) {
	i.FillBytes(buff[:])
}
