// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/sha512"
	"fmt"
	"math/big"
	"strings"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
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
	Redwards := new(edwards25519.Point) // extended group element
	var Rsecp256k1 *crypto.ECPoint

	var riBytes []byte
	_, isTwistedEdwardsCurve := round.EC().(*edwards.TwistedEdwardsCurve)
	isSecp256k1Curve := strings.Compare("secp256k1", round.EC().Params().Name) == 0
	if isTwistedEdwardsCurve {
		riBytes = bigIntToEncodedBytes32(round.temp.ri)
		sc, err := new(edwards25519.Scalar).SetBytesWithClamping(riBytes)
		if err != nil {
			return round.WrapError(err)
		}
		Redwards = Redwards.ScalarBaseMult(sc)
	} else if isSecp256k1Curve {
		Rsecp256k1 = crypto.ScalarBaseMult(round.EC(), round.temp.ri)
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
		ok, _ := cmtDeCmt.DeCommit()
		if !ok {
			return round.WrapError(errors.New("de-commitment verify failed"))
		}
		// the first element is the randomness param; discard it
		coordinates := r2msg.GetDeCommitment()
		if len(coordinates) != 5 {
			return round.WrapError(fmt.Errorf("length of de-commitment should be 4 but was %d", len(coordinates) - 1))
		}
		coordinates = coordinates[1:]

		Rj, err := crypto.NewECPoint(round.EC(), encoded32BytesToBigInt(coordinates[0]), encoded32BytesToBigInt(coordinates[1]))
		if err != nil {
			return round.WrapError(errors.Wrapf(err, "NewECPoint(Rj)"), Pj)
		}
		proof, err := r2msg.UnmarshalZKProof(round.EC())
		if err != nil {
			return round.WrapError(errors.New("failed to unmarshal Rj proof"), Pj)
		}
		ok = proof.Verify(Rj)
		if !ok {
			return round.WrapError(errors.New("failed to prove Rj"), Pj)
		}

		if isTwistedEdwardsCurve {
			var err2 error
			var x, y, z, t *field.Element
			if x, err2 = new(field.Element).SetBytes(coordinates[0]); err2 != nil {
				return round.WrapError(err2)
			}
			if y, err2 = new(field.Element).SetBytes(coordinates[1]); err2 != nil {
				return round.WrapError(err2)
			}
			if z, err2 = new(field.Element).SetBytes(coordinates[2]); err2 != nil {
				return round.WrapError(err2)
			}
			if t, err2 = new(field.Element).SetBytes(coordinates[3]); err2 != nil {
				return round.WrapError(err2)
			}
			extendedRj, err2 := new(edwards25519.Point).SetExtendedCoordinates(x, y, z, t)
			if err2 != nil {
				return round.WrapError(errors.Wrapf(err2, "1"), Pj)
			}
			Redwards = new(edwards25519.Point).Add(Redwards, extendedRj)
		} else if isSecp256k1Curve {
			Rsecp256k1, err = Rsecp256k1.Add(Rj)
			if err != nil {
				return round.WrapError(errors.Wrapf(err, "error with addition"), Pj)
			}
		}
	}

	encodedR := make([]byte, 32)
	var encodedPubKey []byte

	if isTwistedEdwardsCurve {
		var err error
		encodedR = Redwards.Bytes()
		if encodedPubKey, err = ecPointToEncodedBytes32(round.key.EDDSAPub.X()); err != nil {
			return round.WrapError(err)
		}
	} else if isSecp256k1Curve {
		s := make([]byte, 32)
		round.key.EDDSAPub.X().FillBytes(s[:])
		encodedPubKey = s
	}

	// 7. compute lambda
	// h = hash512(k || A || M)
	var 𝜆 *chainhash.Hash
	var lambdaSc *edwards25519.Scalar
	lambda := make([]byte, 0, 64)
	if isTwistedEdwardsCurve {
		h := sha512.New()
		h.Reset()
		h.Write(encodedR[:])
		h.Write(encodedPubKey[:])
		h.Write(round.temp.m.Bytes())
		lambda = h.Sum(nil)

		var err error
		if lambdaSc, err = new(edwards25519.Scalar).SetUniformBytes(lambda); err != nil {
			return round.WrapError(err)
		}
	} else if isSecp256k1Curve {
		// if R has an odd Y coordinate, we'll add to it until we find an R with even Y.
		a := 0
		G := crypto.ScalarBaseMult(round.EC(), big.NewInt(1))
		for ; OddY(Rsecp256k1); a++ { // Y cannot be odd in BIP340
			Rsecp256k1, _ = Rsecp256k1.Add(G)
		}
		round.temp.a = a

		Rsecp256k1.X().FillBytes(encodedR[:])
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
	var localS *edwards25519.Scalar
	var si *big.Int
	if isTwistedEdwardsCurve {
		var err error
		var wiSc, riSc *edwards25519.Scalar
		if wiSc, err = new(edwards25519.Scalar).SetCanonicalBytes(bigIntToEncodedBytes32(round.temp.wi)); err != nil {
			return round.WrapError(err)
		}
		if riSc, err = new(edwards25519.Scalar).SetCanonicalBytes(riBytes); err != nil {
			return round.WrapError(err)
		}
		localS = localS.MultiplyAdd(lambdaSc, wiSc, riSc)
		si = encoded32BytesToBigInt(localS.Bytes())
	} else if isSecp256k1Curve {
		𝜆wi := big.NewInt(0).Mul(big.NewInt(0).SetBytes(𝜆.CloneBytes()), round.temp.wi)
		si = big.NewInt(0).Add(round.temp.ri, 𝜆wi)
	}

	// 9. store r3 message pieces
	round.temp.si = *si
	if isTwistedEdwardsCurve {
		round.temp.r = encoded32BytesToBigInt(encodedR)
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
