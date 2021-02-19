// Copyright © 2021 Swingby

package ecdsautils

import (
	"crypto/ecdsa"

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

type AttributionOfBlame struct {
	PartyToBlame    *tss.PartyID
	Victim          uint32
	TheFeldmanError FeldmanError
}

func FeldmanCheck(feldmanCheckFailureEvidence *FeldmanCheckFailureEvidence,
	roundThreshold int) (bool, FeldmanError) {

	cmtDeCmt := commitments.HashCommitDecommit{C: feldmanCheckFailureEvidence.TheHashCommitDecommit.C,
		D: feldmanCheckFailureEvidence.TheHashCommitDecommit.D}
	ok, flatPolyGs := cmtDeCmt.DeCommit()
	if !ok || flatPolyGs == nil {
		return false, DecommitError
	}
	PjVs, err := crypto.UnFlattenECPoints(tss.EC(), flatPolyGs)
	if err != nil {
		return false, UnFlattenError
	}
	var PjShare = feldmanCheckFailureEvidence.Sigmaji
	if ok = PjShare.Verify(roundThreshold, PjVs); !ok {
		return false, ShareVerificationError
	}
	return true, NoError
}

func FindFeldmanCulprits(i int, Ps tss.SortedPartyIDs, feldmanCheckFailureEvidences []*FeldmanCheckFailureEvidence,
	authenticationPKs []*MarshallableEcdsaPublicKey, roundThreshold int,
	sortedPartyIDs tss.SortedPartyIDs, plaintiffParty int,
	culprits *[]AttributionOfBlame, culpritSet map[*tss.PartyID]struct{}) {
	for _, evidence := range feldmanCheckFailureEvidences {
		if i == int(evidence.AccusedPartyj) {
			common.Logger.Debugf("the current party %v is being accused and is excusing itself from the attribution of blame",
				Ps[i])
			continue
		}

		common.Logger.Debugf("party %v round 4 plaintiff party: %v, accused party: %v", sortedPartyIDs[plaintiffParty],
			plaintiffParty, evidence.AccusedPartyj)

		authSignaturesAreEqual := len(authenticationPKs) > int(evidence.AccusedPartyj) &&
			authenticationPKs[int(evidence.AccusedPartyj)] != nil &&
			evidence.AuthSignaturePkj.Equal((*ecdsa.PublicKey)(authenticationPKs[int(evidence.AccusedPartyj)]))

		authEcdsaSignatureOk := ecdsa.Verify(&evidence.AuthSignaturePkj, HashShare(evidence.Sigmaji),
			evidence.AuthEcdsaSignature.R, evidence.AuthEcdsaSignature.S)
		var partyToBlame *tss.PartyID
		if !authEcdsaSignatureOk || !authSignaturesAreEqual {
			partyToBlame = sortedPartyIDs[plaintiffParty]
			*culprits = append(*culprits, AttributionOfBlame{PartyToBlame: partyToBlame, Victim: evidence.AccusedPartyj,
				TheFeldmanError: PlaintiffTryingToFrameAccusedParty})
		} else {
			ok, feldmanError := FeldmanCheck(evidence, roundThreshold)
			if !ok {
				partyToBlame = sortedPartyIDs[evidence.AccusedPartyj]
				*culprits = append(*culprits, AttributionOfBlame{PartyToBlame: partyToBlame,
					Victim:          uint32(plaintiffParty),
					TheFeldmanError: feldmanError})
			} else {
				partyToBlame = sortedPartyIDs[plaintiffParty]
				*culprits = append(*culprits, AttributionOfBlame{PartyToBlame: partyToBlame,
					TheFeldmanError: PlaintiffTryingToFrameAccusedParty})
			}
		}
		common.Logger.Warnf("party %v blames party %v ", sortedPartyIDs[i], partyToBlame)
		culpritSet[partyToBlame] = struct{}{}
	}
}
