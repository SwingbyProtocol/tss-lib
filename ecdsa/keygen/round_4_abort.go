// Copyright © 2020 Swingby
//

package keygen

import (
	"github.com/binance-chain/tss-lib/common"
	ecdsautils "github.com/binance-chain/tss-lib/ecdsa"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round4) startInAbortMode(i int, Ps tss.SortedPartyIDs, abortr3msgs []tss.ParsedMessage) *tss.Error {

	var errorMap = map[ecdsautils.FeldmanError]string{
		ecdsautils.DecommitError:                      "abort identification - error opening de-commitment",
		ecdsautils.UnFlattenError:                     "abort identification - error unflattening EC points from de-commitment",
		ecdsautils.ShareVerificationError:             "abort identification - error in the Feldman share verification",
		ecdsautils.PlaintiffTryingToFrameAccusedParty: "abort identification - the plaintiff party tried to frame the accused one"}

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

		ecdsautils.FindFeldmanCulprits(i, Ps, feldmanCheckFailureEvidences, round.save.AuthenticationPKs,
			round.Threshold(), round.Parties().IDs(), plaintiffParty, &culprits, culpritSet)
	}

	return ecdsautils.HandleMultiErrorVictimAndCulprit(culpritSet, culprits, Ps, errorMap, round.WrapMultiError)
}
