// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"errors"
	"fmt"

	"github.com/binance-chain/tss-lib/common"
	ecdsautils "github.com/binance-chain/tss-lib/ecdsa"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round5) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 5
	round.started = true

	round.allOldOK()
	round.allNewOK()

	Pi := round.PartyID()
	i := Pi.Index

	abortMessages := false
	culprits := make([]ecdsautils.AttributionOfBlame, 0)
	culpritSet := make(map[*tss.PartyID]struct{})
	for _, m := range round.temp.dgRound4Messages {
		a, isAbort := m.Content().(*DGRound4Message).Content.(*DGRound4Message_Abort)
		common.Logger.Debugf("party %v %p, IsNewCommittee? %v, IsOldCommittee? %v, isAbort? %v", Pi, Pi,
			round.IsNewCommittee(), round.IsOldCommittee(), isAbort)
		abortMessages = abortMessages || isAbort
		if isAbort {
			if round.IsOldCommittee() {
				feldmanCheckFailureEvidences, plaintiffParty := a.Abort.UnmarshalFeldmanCheckFailureEvidence()
				if i == plaintiffParty {
					common.Logger.Debugf("party %v is the plaintiff and is excusing itself from the attribution of blame",
						Pi)
					continue
				}

				ecdsautils.FindFeldmanCulprits(Pi, feldmanCheckFailureEvidences, nil,
					round.Threshold(), round.NewParties().IDs(), round.OldParties().IDs(), plaintiffParty, &culprits, culpritSet)
			}
		}
	}
	if abortMessages {
		if round.IsNewCommittee() {
			return round.WrapError(fmt.Errorf("player %v (new committee) is aborting", Pi))
		} else {
			var feldmanErrorMap = ecdsautils.FeldmanErrorMap()
			return ecdsautils.HandleMultiErrorVictimAndCulprit(culpritSet, culprits, round.OldParties().IDs(),
				feldmanErrorMap, round.WrapMultiError)
		}
	}

	if round.IsNewCommittee() {
		// 21.
		// for this P: SAVE data
		round.save.BigXj = round.temp.newBigXjs
		round.save.ShareID = round.PartyID().KeyInt()
		round.save.Xi = round.temp.newXi
		round.save.Ks = round.temp.newKs

		// misc: build list of paillier public keys to save
		for j, msg := range round.temp.dgRound2Message1s {
			if j == i {
				continue
			}
			r2msg1 := msg.Content().(*DGRound2Message1)
			round.save.PaillierPKs[j] = r2msg1.UnmarshalPaillierPK()
		}
	} else if round.IsOldCommittee() {
		round.input.Xi.SetInt64(0)
	}

	round.end <- *round.save
	return nil
}

func (round *round5) CanAccept(msg tss.ParsedMessage) bool {
	return false
}

func (round *round5) Update() (bool, *tss.Error) {
	return false, nil
}

func (round *round5) NextRound() tss.Round {
	return nil // both committees are finished!
}
