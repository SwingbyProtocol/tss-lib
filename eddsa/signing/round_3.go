// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/sha512"
	"math/big"
	"strings"

	"github.com/agl/ed25519/edwards25519"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 3
	round.started = true
	round.resetOK()

	// 1. init R
	var Redwards edwards25519.ExtendedGroupElement
	var Rsecp256k1 *crypto.ECPoint

	var riBytes *[32]byte
	_, isTwistedEdwardsCurve := round.Params().EC().(*edwards.TwistedEdwardsCurve)
	isSecp256k1Curve := strings.Compare("secp256k1", round.Params().EC().Params().Name) == 0
	if isTwistedEdwardsCurve {
		riBytes = bigIntToEncodedBytes(round.temp.ri)
		edwards25519.GeScalarMultBase(&Redwards, riBytes)
	} else if isSecp256k1Curve {
		Rsecp256k1 = crypto.ScalarBaseMult(round.Params().EC(), round.temp.ri)
	}

	// 2-6. compute R
	i := round.PartyID().Index
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		msg := round.temp.signRound2Messages[j]
		r2msg := msg.Content().(*SignRound2Message)
		cmtDeCmt := commitments.HashCommitDecommit{C: round.temp.cjs[j], D: r2msg.UnmarshalDeCommitment()}
		ok, coordinates := cmtDeCmt.DeCommit()
		if !ok {
			return round.WrapError(errors.New("de-commitment verify failed"))
		}
		if len(coordinates) != 2 {
			return round.WrapError(errors.New("length of de-commitment should be 2"))
		}

		Rj, err := crypto.NewECPoint(round.Params().EC(), coordinates[0], coordinates[1])
		if err != nil {
			return round.WrapError(errors.Wrapf(err, "NewECPoint(Rj)"), Pj)
		}
		proof, err := r2msg.UnmarshalZKProof(round.Params().EC())
		if err != nil {
			return round.WrapError(errors.New("failed to unmarshal Rj proof"), Pj)
		}
		ok = proof.Verify(Rj)
		if !ok {
			return round.WrapError(errors.New("failed to prove Rj"), Pj)
		}

		if isTwistedEdwardsCurve {
			extendedRj := ecPointToExtendedElement(round.Params().EC(), Rj.X(), Rj.Y())
			Redwards = addExtendedElements(Redwards, extendedRj)
		} else if isSecp256k1Curve {
			Rsecp256k1, err = Rsecp256k1.Add(Rj)
			if err != nil {
				return round.WrapError(errors.Wrapf(err, "error with addition"), Pj)
			}
		}
	}

	var encodedR [32]byte
	var encodedPubKey *[32]byte

	if isTwistedEdwardsCurve {
		Redwards.ToBytes(&encodedR)
		encodedPubKey = ecPointToEncodedBytes(round.key.EDDSAPub.X(), round.key.EDDSAPub.Y())
	} else if isSecp256k1Curve {
		s := new([32]byte)
		round.key.EDDSAPub.X().FillBytes(s[:])
		encodedPubKey = s
	}

	// 7. compute lambda
	// h = hash512(k || A || M)
	var lambda [64]byte
	var 𝜆 *chainhash.Hash
	var lambdaReduced [32]byte
	if isTwistedEdwardsCurve {
		h := sha512.New()
		h.Reset()
		h.Write(encodedR[:])
		h.Write(encodedPubKey[:])
		h.Write(round.temp.m.Bytes())
		h.Sum(lambda[:0])

		edwards25519.ScReduce(&lambdaReduced, &lambda)
	} else if isSecp256k1Curve {
		// if R has an odd Y coordinate, we'll add to it until we find an R with even Y.
		a := 0
		G := crypto.ScalarBaseMult(round.Params().EC(), big.NewInt(1))
		for ; OddY(Rsecp256k1); a++ { // Y cannot be odd in BIP340
			Rsecp256k1, _ = Rsecp256k1.Add(G)
		}
		round.temp.a = a

		//
		encode32bytes(Rsecp256k1.X(), &encodedR)
		𝜆 = chainhash.TaggedHash(
			[]byte("BIP0340/challenge"), encodedR[:], encodedPubKey[:], round.temp.m.Bytes(),
		) // commitment
		var e btcec.ModNScalar
		if overflow := e.SetBytes((*[32]byte)(𝜆)); overflow != 0 {
			str := "hash of (r || P || m) too big"
			return round.WrapError(errors.New(str))
		}
	}

	// 8. compute si
	var localS [32]byte
	var si *big.Int
	if isTwistedEdwardsCurve {
		edwards25519.ScMulAdd(&localS, &lambdaReduced, bigIntToEncodedBytes(round.temp.wi), riBytes)
		si = encodedBytesToBigInt(&localS)
	} else if isSecp256k1Curve {
		𝜆wi := big.NewInt(0).Mul(big.NewInt(0).SetBytes(𝜆.CloneBytes()), round.temp.wi)
		si = big.NewInt(0).Add(round.temp.ri, 𝜆wi)
	}

	// 9. store r3 message pieces
	round.temp.si = *si
	if isTwistedEdwardsCurve {
		round.temp.r = encodedBytesToBigInt(&encodedR)
	} else if isSecp256k1Curve {
		round.temp.r = Rsecp256k1.X()
	}

	// 10. broadcast si to other parties
	r3msg := NewSignRound3Message(round.PartyID(), si)
	round.temp.signRound3Messages[round.PartyID().Index] = r3msg
	round.out <- r3msg

	return nil
}

func (round *round3) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound3Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
}
