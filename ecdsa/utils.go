// Copyright © 2021 Swingby

package ecdsautils

import (
	"crypto/ecdsa"
	"encoding/json"
	"math/big"

	"github.com/hashicorp/go-multierror"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
)

type ECDSASignature struct {
	R, S *big.Int
}

func HashShare(share *vss.Share) (hash []byte) {
	hash = append(share.ID.Bytes(), share.Share.Bytes()...)
	hash = append(hash, big.NewInt(int64(share.Threshold)).Bytes()...)
	hash = common.SHA512_256(hash)
	return
}

func NewECDSASignature(r, s *big.Int) *ECDSASignature {
	return &ECDSASignature{R: r, S: s}
}

func HashPaillierKey(pk *paillier.PublicKey) (hash []byte) {
	hash = common.SHA512_256i(append(pk.AsInts())...).Bytes()
	return
}

func (k MarshallableEcdsaPrivateKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		PublicKey MarshallableEcdsaPublicKey
		D         *big.Int
	}{
		PublicKey: (MarshallableEcdsaPublicKey)(k.PublicKey),
		D:         k.D,
	})
}

func (k *MarshallableEcdsaPrivateKey) UnmarshalJSON(b []byte) error {
	// PrivateKey represents an ECDSA private key.
	newKey := new(struct {
		PublicKey MarshallableEcdsaPublicKey
		D         *big.Int
	})
	if err := json.Unmarshal(b, &newKey); err != nil {
		return err
	}
	k.D = newKey.D
	k.PublicKey = (ecdsa.PublicKey)(newKey.PublicKey)

	return nil
}

func (k MarshallableEcdsaPublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		X, Y *big.Int
	}{
		X: k.X,
		Y: k.Y,
	})
}

func (k *MarshallableEcdsaPublicKey) UnmarshalJSON(b []byte) error {
	newKey := new(struct {
		X, Y *big.Int
	})
	if err := json.Unmarshal(b, &newKey); err != nil {
		return err
	}
	k.X = newKey.X
	k.Y = newKey.Y
	k.Curve = tss.EC()

	return nil
}

// We will customize the Json serialization of the public key
// used for party authentication.
// The serialization of the Koblitz curve showed problems,
// as the type does not expose a number of attributes.
type MarshallableEcdsaPublicKey ecdsa.PublicKey

type MarshallableEcdsaPrivateKey ecdsa.PrivateKey

// The evidence of an eventual Feldman check failure will be evaluated
// during the abort identification in round 4 of keygen and in resharing.
type FeldmanCheckFailureEvidence struct {
	Sigmaji               *vss.Share
	AuthSignaturePkj      ecdsa.PublicKey
	AccusedPartyj         uint32
	TheHashCommitDecommit commitments.HashCommitDecommit
	AuthEcdsaSignature    *ECDSASignature
}

func PrepareShareWithAuthSigMessages(feldmanCheckFailures []*FeldmanCheckFailureEvidence, partyID *tss.PartyID) []*common.VSSShareWithAuthSigMessage {
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
			partyID, evidence.AccusedPartyj)
	}
	return vssShareWithAuthSigMessages
}

func HandleMultiErrorVictimAndCulprit(culpritSet map[*tss.PartyID]struct{}, culprits []AttributionOfBlame,
	Ps tss.SortedPartyIDs, errorMap map[FeldmanError]string, wrapMultiErrorFunc func(err error, victim *tss.PartyID, culprits ...*tss.PartyID) *tss.Error) *tss.Error {
	uniqueCulprits := make([]*tss.PartyID, 0, len(culpritSet))
	for aCulprit := range culpritSet {
		uniqueCulprits = append(uniqueCulprits, aCulprit)
	}

	var multiErr error
	for _, culprit := range culprits {
		vc := &tss.VictimAndCulprit{Victim: Ps[culprit.Victim], Culprit: culprit.PartyToBlame,
			Message: errorMap[culprit.TheFeldmanError]}
		multiErr = multierror.Append(multiErr, vc)
	}
	if len(culprits) > 0 {
		return wrapMultiErrorFunc(multiErr, Ps[culprits[0].Victim], uniqueCulprits...)
	} else {
		return nil
	}
}
