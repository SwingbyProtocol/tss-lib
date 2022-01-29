// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"fmt"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/eddsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

// round 1 represents round 1 of the signing part of the EDDSA TSS spec
func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- common.SignatureData) tss.Round {
	return &round1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 1
	round.started = true
	round.resetOK()

	// 1. select ri
	ri := common.MustGetRandomInt(256)

	// 2. make commitment
	// pointRi := crypto.ScalarBaseMult(round.Params().EC(), ri)
	riSc, err := new(edwards25519.Scalar).SetBytesWithClamping(reverse(ri.Bytes()))
	if err != nil {
		return round.WrapError(err)
	}
	pointRi := new(edwards25519.Point).ScalarBaseMult(riSc)
	x, y, z, t := pointRi.ExtendedCoordinates()
	bzs := [][]byte{x.Bytes(), y.Bytes(), z.Bytes(), t.Bytes()}
	cmt := commitments.NewHashCommitment(common.ByteSlicesToBigInts(bzs)...)

	// 3. store r1 message pieces
	// round.temp.ri = new(big.Int).SetBytes(reverse(riSc.Bytes()))
	if round.temp.pointRi, err = crypto.NewECPoint(
		round.EC(),
		encoded32BytesToBigInt(new(field.Element).Multiply(x, z).Bytes()),
		encoded32BytesToBigInt(new(field.Element).Multiply(y, z).Bytes())); err != nil {
		return round.WrapError(err)
	}
	// round.temp.pointRi = crypto.ScalarBaseMult(round.EC(), round.temp.ri)
	round.temp.deCommit = cmt.D

	i := round.PartyID().Index
	round.ok[i] = true

	// 4. broadcast commitment
	r1msg2 := NewSignRound1Message(round.PartyID(), cmt.C)
	round.temp.signRound1Messages[i] = r1msg2
	round.out <- r1msg2

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound1Messages {
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

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}

// ----- //

// helper to call into PrepareForSigning()
func (round *round1) prepare() error {
	i := round.PartyID().Index

	xi := round.key.Xi
	ks := round.key.Ks

	if round.Threshold()+1 > len(ks) {
		// TODO: this should not panic
		return fmt.Errorf("t+1=%d is not consistent with the key count %d", round.Threshold()+1, len(ks))
	}
	wi := PrepareForSigning(round.Params().EC(), i, len(ks), xi, ks)

	round.temp.wi = wi
	return nil
}
