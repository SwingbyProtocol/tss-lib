// Copyright © 2021 Swingby

package ecdsautils

import (
	"crypto/ecdsa"
	"math/big"
	"strconv"

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

		var authSignaturesAreEqual bool
		if authenticationPKs != nil && authenticationPKs[int(evidence.AccusedPartyj)] != nil {
			authSignaturesAreEqual = len(authenticationPKs) > int(evidence.AccusedPartyj) &&
				authenticationPKs[int(evidence.AccusedPartyj)] != nil &&
				evidence.AuthSignaturePkj.Equal((*ecdsa.PublicKey)(authenticationPKs[int(evidence.AccusedPartyj)]))
		} else {
			authSignaturesAreEqual = true
		}
		common.Logger.Debugf("plaintiff party %v w/ index %v, accused party: %v w/ index %v, auth pk: %v, sigmaji: %v , r: %v, s: %v",
			plaintiffsPartyIDs[plaintiffParty],
			plaintiffParty, accusedPartyIDs[evidence.AccusedPartyj], evidence.AccusedPartyj,
			FormatEcdsaPublicKey(&evidence.AuthSignaturePkj),
			FormatShare(*evidence.Sigmaji),
			FormatBigInt(evidence.AuthEcdsaSignature.R), FormatBigInt(evidence.AuthEcdsaSignature.S))

		authEcdsaSignatureOk := ecdsa.Verify(&evidence.AuthSignaturePkj, HashShare(evidence.Sigmaji),
			evidence.AuthEcdsaSignature.R, evidence.AuthEcdsaSignature.S)
		var partyToBlame *tss.PartyID
		if !authEcdsaSignatureOk || !authSignaturesAreEqual {
			partyToBlame = plaintiffsPartyIDs[plaintiffParty]
			*culprits = append(*culprits, AttributionOfBlame{PartyToBlame: partyToBlame, Victim: evidence.AccusedPartyj,
				TheFeldmanError: PlaintiffTryingToFrameAccusedParty})
		} else {
			ok, feldmanError := FeldmanCheck(evidence, roundThreshold)
			if !ok {
				partyToBlame = accusedPartyIDs[evidence.AccusedPartyj]
				*culprits = append(*culprits, AttributionOfBlame{PartyToBlame: partyToBlame,
					Victim:          uint32(plaintiffParty),
					TheFeldmanError: feldmanError})
			} else {
				partyToBlame = plaintiffsPartyIDs[plaintiffParty]
				*culprits = append(*culprits, AttributionOfBlame{PartyToBlame: partyToBlame,
					TheFeldmanError: PlaintiffTryingToFrameAccusedParty})
			}
		}
		common.Logger.Warnf("party %v deliberated and blames party %v ", Pi, partyToBlame)
		culpritSet[partyToBlame] = struct{}{}
	}
}

func FeldmanErrorMap() map[FeldmanError]string {
	return map[FeldmanError]string{
		DecommitError:                      "abort identification - error opening de-commitment",
		UnFlattenError:                     "abort identification - error unflattening EC points from de-commitment",
		ShareVerificationError:             "abort identification - error in the Feldman share verification",
		PlaintiffTryingToFrameAccusedParty: "abort identification - the plaintiff party tried to frame the accused one"}
}

func FormatShare(s vss.Share) string {
	return "S:" + FormatBigInt(s.Share) + ", T:" + strconv.Itoa(s.Threshold) + ", ID:" + FormatBigInt(s.ID)
}

func FormatEcdsaPublicKey(pk *ecdsa.PublicKey) string {
	return "X:" + FormatBigInt(pk.X) + ", Y:" + FormatBigInt(pk.Y) + ", C:" + pk.Curve.Params().Name
}

func FormatBigInt(a *big.Int) string {
	var aux = new(big.Int).SetInt64(0xFFFFFFFF)
	return func(i *big.Int) string {
		return new(big.Int).And(i, aux).Text(16)
	}(a)
}

const (
	FeldmanCheckFailure AbortTrigger = iota
)
