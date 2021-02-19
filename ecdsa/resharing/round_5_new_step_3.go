// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"errors"

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

	abortMessages := make([]*DGRound4Message_AbortData, 0)
	culprits := make([]ecdsautils.AttributionOfBlame, 0)
	culpritSet := make(map[*tss.PartyID]struct{})
	for _, m := range round.temp.dgRound4Messages {
		if a, isAbort := m.Content().(*DGRound4Message).Content.(*DGRound4Message_Abort); isAbort {
			feldmanCheckFailureEvidences, plaintiffParty := a.Abort.UnmarshalFeldmanCheckFailureEvidence()
			if i == plaintiffParty {
				common.Logger.Debugf("party %v is the plaintiff and is excusing itself from the attribution of blame",
					Pi)
				continue
			}

			ecdsautils.FindFeldmanCulprits(i, round.Parties().IDs(), feldmanCheckFailureEvidences, round.save.AuthenticationPKs,
				round.Threshold(), round.Parties().IDs(), plaintiffParty, &culprits, culpritSet)
		}
	}
	if len(abortMessages) > 0 {

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
