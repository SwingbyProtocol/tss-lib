// Copyright © 2020 Swingby
//

package keygen

import (
	"github.com/binance-chain/tss-lib/common"
	ecdsautils "github.com/binance-chain/tss-lib/ecdsa"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round4) startInAbortMode(i int, Ps tss.SortedPartyIDs, abortr3msgs []tss.ParsedMessage) *tss.Error {

	var feldmanErrorMap = ecdsautils.FeldmanErrorMap()

	common.Logger.Debugf("party %v is starting the abort identification", Ps[i])
	culprits := make([]ecdsautils.AttributionOfBlame, 0)
	culpritSet := make(map[*tss.PartyID]struct{})
	for _, msg := range abortr3msgs {
		r3msg := msg.Content().(*KGRound3MessageAbortMode)
		feldmanCheckFailureEvidences, plaintiffParty := r3msg.UnmarshalFeldmanCheckFailureEvidence()
		if i == plaintiffParty {
			common.Logger.Debugf("party %v is the plaintiff and is excusing itself from the attribution of blame",
				Ps[i])
			continue
		}

		ecdsautils.FindFeldmanCulprits(Ps[i], feldmanCheckFailureEvidences, round.save.AuthenticationPKs,
			round.Threshold(), round.Parties().IDs(), round.Parties().IDs(), plaintiffParty, &culprits, culpritSet)
	}

	return ecdsautils.HandleMultiErrorVictimAndCulprit(culpritSet, culprits, Ps, feldmanErrorMap, round.WrapMultiError)
}
