// Copyright © 2021 Swingby

package ecdsautils

import (
	"crypto/ecdsa"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/vss"
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
	CulpritParty    *tss.PartyID
	Victim          uint32
	TheFeldmanError FeldmanError
}

// The evidence of an eventual Feldman check failure will be evaluated
// during the abort identification in round 4 of keygen and in resharing.
type FeldmanCheckFailureEvidence struct {
	Sigmaji               *vss.Share
	AuthSignaturePkj      ecdsa.PublicKey
	AccusedPartyj         uint32
	TheHashCommitDecommit commitments.HashCommitDecommit
	AuthEcdsaSignature    *ECDSASignature
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

func FindFeldmanCulprits(Pi *tss.PartyID, feldmanCheckFailureEvidences []*FeldmanCheckFailureEvidence,
	authenticationPKs []*MarshallableEcdsaPublicKey, roundThreshold int,
	plaintiffsPartyIDs tss.SortedPartyIDs, accusedPartyIDs tss.SortedPartyIDs, plaintiffParty int,
	culprits *[]AttributionOfBlame, culpritSet map[*tss.PartyID]struct{}) {
	for _, evidence := range feldmanCheckFailureEvidences {
		if Pi.Index == int(evidence.AccusedPartyj) {
			common.Logger.Debugf("the current party %v is being accused and is excusing itself from the attribution of blame",
				Pi)
			continue
		}

		authSignaturesAreEqual := len(authenticationPKs) > int(evidence.AccusedPartyj) &&
			authenticationPKs[int(evidence.AccusedPartyj)] != nil &&
			evidence.AuthSignaturePkj.Equal((*ecdsa.PublicKey)(authenticationPKs[int(evidence.AccusedPartyj)]))

		authEcdsaSignatureOk := ecdsa.Verify(&evidence.AuthSignaturePkj, HashShare(evidence.Sigmaji),
			evidence.AuthEcdsaSignature.R, evidence.AuthEcdsaSignature.S)
		var culpritParty *tss.PartyID
		if !authEcdsaSignatureOk || !authSignaturesAreEqual {
			culpritParty = plaintiffsPartyIDs[plaintiffParty]
			*culprits = append(*culprits, AttributionOfBlame{CulpritParty: culpritParty, Victim: evidence.AccusedPartyj,
				TheFeldmanError: PlaintiffTryingToFrameAccusedParty})
		} else {
			ok, feldmanError := FeldmanCheck(evidence, roundThreshold)
			if !ok {
				culpritParty = accusedPartyIDs[evidence.AccusedPartyj]
				*culprits = append(*culprits, AttributionOfBlame{CulpritParty: culpritParty,
					Victim:          uint32(plaintiffParty),
					TheFeldmanError: feldmanError})
			} else {
				culpritParty = plaintiffsPartyIDs[plaintiffParty]
				*culprits = append(*culprits, AttributionOfBlame{CulpritParty: culpritParty,
					TheFeldmanError: PlaintiffTryingToFrameAccusedParty})
			}
		}
		common.Logger.Warnf("party %v deliberated and blames party %v ", Pi, culpritParty)
		culpritSet[culpritParty] = struct{}{}
	}
}

func PrepareShareWithAuthSigMessages(feldmanCheckFailures []*FeldmanCheckFailureEvidence, plaintiffPartyID *tss.PartyID) []*common.VSSShareWithAuthSigMessage {
	vssShareWithAuthSigMessages := make([]*common.VSSShareWithAuthSigMessage, len(feldmanCheckFailures))
	for a, evidence := range feldmanCheckFailures {
		ecPoint := common.ECPoint{X: evidence.AuthSignaturePkj.X.Bytes(), Y: evidence.AuthSignaturePkj.Y.Bytes()}
		DjBytes := make([][]byte, len(evidence.TheHashCommitDecommit.D))
		for b, k := range evidence.TheHashCommitDecommit.D {
			DjBytes[b] = k.Bytes()
		}

		msg := common.VSSShareWithAuthSigMessage{
			VssThreshold:        uint32(evidence.Sigmaji.Threshold),
			VssId:               evidence.Sigmaji.ID.Bytes(),
			VssSigma:            evidence.Sigmaji.Share.Bytes(),
			AccusedParty:        evidence.AccusedPartyj,
			AuthSigPk:           &ecPoint,
			Dj:                  DjBytes,
			Cj:                  evidence.TheHashCommitDecommit.C.Bytes(),
			AuthEcdsaSignatureR: evidence.AuthEcdsaSignature.R.Bytes(),
			AuthEcdsaSignatureS: evidence.AuthEcdsaSignature.S.Bytes()}
		vssShareWithAuthSigMessages[a] = &msg
		common.Logger.Warnf("party %v is the plaintiff triggering an abort identification"+
			" accusing party %v",
			plaintiffPartyID, evidence.AccusedPartyj)
	}
	return vssShareWithAuthSigMessages
}

func FeldmanErrorMap() map[FeldmanError]string {
	return map[FeldmanError]string{
		DecommitError:                      "abort identification - error opening de-commitment",
		UnFlattenError:                     "abort identification - error unflattening EC points from de-commitment",
		ShareVerificationError:             "abort identification - error in the Feldman share verification",
		PlaintiffTryingToFrameAccusedParty: "abort identification - the plaintiff party tried to frame the accused one"}
}

const (
	FeldmanCheckFailure AbortTrigger = iota
)
