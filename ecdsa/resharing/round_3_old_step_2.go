// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"

	"github.com/hashicorp/go-multierror"

	ecdsautils "github.com/binance-chain/tss-lib/ecdsa"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK() // resets both round.oldOK and round.newOK
	round.allNewOK()

	if !round.ReSharingParams().IsOldCommittee() {
		return nil
	}
	round.allOldOK()

	Pi := round.PartyID()
	i := Pi.Index
	authSignaturesFailCulprits := make([]*tss.PartyID, len(round.NewParties().IDs()))

	for j, msg := range round.temp.dgRound2Message2s {
		r2msg2 := msg.Content().(*DGRound2Message2)
		authEcdsaPKj := r2msg2.UnmarshalAuthEcdsaPK()
		round.save.AuthenticationPKs[j] = (*ecdsautils.MarshallableEcdsaPublicKey)(authEcdsaPKj)
	}

	// 2. send share to Pj from the new committee
	for j, Pj := range round.NewParties().IDs() {
		r, s, err := ecdsa.Sign(rand.Reader, (*ecdsa.PrivateKey)(round.save.AuthEcdsaPrivateKey),
			ecdsautils.HashShare(round.temp.NewShares[j]))
		if err != nil {
			authSignaturesFailCulprits[j] = Pj
		}
		authSignature := ecdsautils.NewECDSASignature(r, s)

		share := round.temp.NewShares[j]
		r3msg1 := NewDGRound3Message1(Pj, round.PartyID(), share, authSignature, &round.save.AuthEcdsaPrivateKey.PublicKey)
		round.out <- r3msg1
	}
	var multiErr error
	culpritSet := make(map[*tss.PartyID]struct{})
	var culpritSetAndErrors = func(arrayCulprits []*tss.PartyID, errorMessage string) {
		for _, culprit := range arrayCulprits {
			if culprit != nil {
				multiErr = multierror.Append(multiErr,
					round.WrapError(errors.New(errorMessage), culprit))
				culpritSet[culprit] = struct{}{}
			}
		}
	}
	culpritSetAndErrors(authSignaturesFailCulprits,
		"ecdsa signature of shares for authentication failed")
	uniqueCulprits := make([]*tss.PartyID, 0, len(culpritSet))
	for aCulprit := range culpritSet {
		uniqueCulprits = append(uniqueCulprits, aCulprit)
	}
	if multiErr != nil {
		return round.WrapError(multiErr, uniqueCulprits...)
	}

	vDeCmt := round.temp.VD
	r3msg2 := NewDGRound3Message2(
		round.NewParties().IDs().Exclude(round.PartyID()), round.PartyID(),
		vDeCmt)
	round.temp.dgRound3Message2s[i] = r3msg2
	round.out <- r3msg2

	return nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*DGRound3Message1); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*DGRound3Message2); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) Update() (bool, *tss.Error) {
	// only the new committee receive in this round
	if !round.ReSharingParams().IsNewCommittee() {
		return true, nil
	}
	// accept messages from old -> new committee
	for j, msg1 := range round.temp.dgRound3Message1s {
		if round.oldOK[j] {
			continue
		}
		if msg1 == nil || !round.CanAccept(msg1) {
			return false, nil
		}
		msg2 := round.temp.dgRound3Message2s[j]
		if msg2 == nil || !round.CanAccept(msg2) {
			return false, nil
		}
		round.oldOK[j] = true
	}
	return true, nil
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
