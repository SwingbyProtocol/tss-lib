// Copyright © 2020 Swingby
//

package keygen

import (
	"crypto/ecdsa"

	"github.com/hashicorp/go-multierror"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/tss"
)

type FeldmanError int

// Possible errors
const (
	NoError FeldmanError = iota
	DecommitError
	UnFlattenError
	ShareVerificationError
	PlaintiffTryingToFrameAccusedParty
)

func (round *round4) feldmanCheck(feldmanCheckFailureEvidence *FeldmanCheckFailureEvidence) (bool, FeldmanError) {
	KGCj := round.temp.KGCs[feldmanCheckFailureEvidence.accusedPartyj]

	cmtDeCmt := commitments.HashCommitDecommit{C: KGCj, D: feldmanCheckFailureEvidence.KGDj}
	ok, flatPolyGs := cmtDeCmt.DeCommit()
	if !ok || flatPolyGs == nil {
		return false, DecommitError
	}
	PjVs, err := crypto.UnFlattenECPoints(tss.EC(), flatPolyGs)
	if err != nil {
		return false, UnFlattenError
	}
	var PjShare = feldmanCheckFailureEvidence.sigmaji
	if ok = PjShare.Verify(round.Threshold(), PjVs); !ok {
		return false, ShareVerificationError
	}
	return true, NoError
}

func (round *round4) startInAbortMode(i int, Ps tss.SortedPartyIDs, abortr3msgs []tss.ParsedMessage) *tss.Error {

	var errorMap = map[FeldmanError]string{
		DecommitError:                      "abort identification - error opening de-commitment",
		UnFlattenError:                     "abort identification - error unflattening EC points from de-commitment",
		ShareVerificationError:             "abort identification - error in the Feldman share verification",
		PlaintiffTryingToFrameAccusedParty: "abort identification - the plaintiff party tried to frame the accused one"}

	type attributionOfBlame struct {
		partyToBlame *tss.PartyID
		victim       uint32
		feldmanError FeldmanError
	}
	common.Logger.Debugf("party %v is starting the abort identification", Ps[i])
	culprits := make([]attributionOfBlame, 0)
	culpritSet := make(map[*tss.PartyID]struct{})
	for _, msg := range abortr3msgs {
		r3msg := msg.Content().(*KGRound3MessageAbortMode)
		feldmanCheckFailureEvidences, plaintiffParty := r3msg.UnmarshalFeldmanCheckFailureEvidence()
		if i == plaintiffParty {
			common.Logger.Debugf("party %v is the plaintiff and is excusing itself from the attribution of blame",
				Ps[i])
			continue
		}

		for _, evidence := range feldmanCheckFailureEvidences {
			if i == int(evidence.accusedPartyj) {
				common.Logger.Debugf("the current party %v is being accused and is excusing itself from the attribution of blame",
					Ps[i])
				continue
			}

			common.Logger.Debugf("party %v round 4 plaintiff party: %v, accused party: %v", round.PartyID(),
				plaintiffParty, evidence.accusedPartyj)

			authSignaturesAreEqual := len(round.save.AuthenticationPKs) > int(evidence.accusedPartyj) &&
				round.save.AuthenticationPKs[int(evidence.accusedPartyj)] != nil &&
				evidence.authSignaturePkj.Equal((*ecdsa.PublicKey)(round.save.AuthenticationPKs[int(evidence.accusedPartyj)]))

			authEcdsaSignatureOk := ecdsa.Verify(&evidence.authSignaturePkj, HashShare(evidence.sigmaji),
				evidence.authEcdsaSignature.r, evidence.authEcdsaSignature.s)
			var partyToBlame *tss.PartyID
			if !authEcdsaSignatureOk || !authSignaturesAreEqual {
				partyToBlame = round.Parties().IDs()[plaintiffParty]
				culprits = append(culprits, attributionOfBlame{partyToBlame: partyToBlame, victim: evidence.accusedPartyj,
					feldmanError: PlaintiffTryingToFrameAccusedParty})
			} else {
				ok, feldmanError := round.feldmanCheck(evidence)
				if !ok {
					partyToBlame = round.Parties().IDs()[evidence.accusedPartyj]
					culprits = append(culprits, attributionOfBlame{partyToBlame: partyToBlame,
						victim:       uint32(plaintiffParty),
						feldmanError: feldmanError})
				} else {
					partyToBlame = round.Parties().IDs()[plaintiffParty]
					culprits = append(culprits, attributionOfBlame{partyToBlame: partyToBlame,
						feldmanError: PlaintiffTryingToFrameAccusedParty})
				}
			}
			common.Logger.Debugf("party %v, party to blame: %v", round.PartyID(), partyToBlame)
			culpritSet[partyToBlame] = struct{}{}
		}
	}

	uniqueCulprits := make([]*tss.PartyID, 0, len(culpritSet))
	for aCulprit := range culpritSet {
		uniqueCulprits = append(uniqueCulprits, aCulprit)
	}

	var multiErr error
	for _, culprit := range culprits {
		vc := &tss.VictimAndCulprit{Victim: Ps[culprit.victim], Culprit: culprit.partyToBlame,
			Message: errorMap[culprit.feldmanError]}
		multiErr = multierror.Append(multiErr, vc)
	}
	if len(culprits) > 0 {
		return round.WrapMultiError(multiErr, Ps[culprits[0].victim], uniqueCulprits...)
	} else {
		return nil
	}

}
