// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/agl/ed25519/edwards25519"
	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v2"
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
	common.Logger.Debugf("curve name: %v", round.Params().EC().Params().Name)
	if _, ok = round.Params().EC().(*edwards.TwistedEdwardsCurve); ok {
		sumS = round.temp.si
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
	} else if strings.Compare("secp256k1", round.Params().EC().Params().Name) == 0 {
		sumSInt := encodedBytesToBigInt(round.temp.si)
		modN := common.ModInt(tss.S256().Params().N)
		for j := range round.Parties().IDs() {
			round.ok[j] = true
			if j == round.PartyID().Index {
				continue
			}
			r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)
			sumSInt = modN.Add(sumSInt, r3msg.UnmarshalS())
		}
		s = sumSInt
		sumS = bigIntToEncodedBytes(sumSInt)
	}

	// save the signature for final output
	signature := new(common.ECSignature)
	signature.Signature = append(bigIntToEncodedBytes(round.temp.r)[:], sumS[:]...)
	signature.R = bigIntToEncodedBytes(round.temp.r)[:]
	signature.S = bigIntToEncodedBytes(s)[:]
	signature.M = round.temp.m.Bytes()

	round.data.R = signature.R
	round.data.S = signature.S
	round.data.Signature = append(round.data.R, round.data.S...)

	if _, ok = round.Params().EC().(*edwards.TwistedEdwardsCurve); ok {
		pk := edwards.PublicKey{
			Curve: round.Params().EC(),
			X:     round.key.EDDSAPub.X(),
			Y:     round.key.EDDSAPub.Y(),
		}
		common.Logger.Debugf("pk.X: %v, r: %v, s: %s", pk.X, round.temp.r, s)
		ok = edwards.Verify(&pk, round.temp.m.Bytes(), round.temp.r, s)
		if !ok {
			return round.WrapError(fmt.Errorf("edwards signature verification failed"))
		}
	} else if strings.Compare("secp256k1", round.Params().EC().Params().Name) == 0 {
		pk := secp256k1.PublicKey{
			Curve: round.Params().EC(),
			X:     round.key.EDDSAPub.X(),
			Y:     round.key.EDDSAPub.Y(),
		}
		common.Logger.Debugf("pk.X: %v, r: %v, s: %s, #m: %v", common.FormatBigInt(pk.X),
			common.FormatBigInt(round.temp.r),
			common.FormatBigInt(s), len(round.temp.m.Bytes()))
		ok = Verify(&pk, round.temp.m.Bytes(), round.temp.r, s)
		common.Logger.Debugf("pk.X: %v, r: %v, s: %s, #m: %v, verify ok? %v", common.FormatBigInt(pk.X),
			common.FormatBigInt(round.temp.r),
			common.FormatBigInt(s), len(round.temp.m.Bytes()), ok)
		if !ok {
			return round.WrapError(fmt.Errorf("schnorr signature verification failed"))
		}
	}

	round.end <- *round.data

	return nil
}

func (round *finalization) CanAccept(msg tss.ParsedMessage) bool {
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

func Verify(p *secp256k1.PublicKey, m []byte, r_ *big.Int, s_ *big.Int) bool {
	var r btcec.FieldVal
	var s btcec.ModNScalar
	r.SetByteSlice(r_.Bytes())
	s.SetByteSlice(s_.Bytes())
	signature := schnorr.NewSignature(&r, &s)
	var x, y btcec.FieldVal
	x.SetByteSlice(p.X.Bytes())
	y.SetByteSlice(p.Y.Bytes())
	pk := btcec.NewPublicKey(&x, &y)
	//
	// TODO pubKey, err := ParsePubKey(pk.SerializeCompressed()[1:])
	//
	return signature.Verify(m, pk)
}

// ParsePubKey TODO DELETE
func ParsePubKey(pubKeyStr []byte) (*btcec.PublicKey, error) {
	if pubKeyStr == nil {
		err := fmt.Errorf("nil pubkey byte string")
		return nil, err
	}
	if len(pubKeyStr) != 32 {
		err := fmt.Errorf("bad pubkey byte string size (want %v, have %v)",
			32, len(pubKeyStr))
		return nil, err
	}

	// We'll manually prepend the compressed byte so we can re-use the
	// existing pubkey parsing routine of the main btcec package.
	var keyCompressed [btcec.PubKeyBytesLenCompressed]byte
	keyCompressed[0] = btcec.PubKeyFormatCompressedEven
	copy(keyCompressed[1:], pubKeyStr)

	return btcec.ParsePubKey(keyCompressed[:])
}
