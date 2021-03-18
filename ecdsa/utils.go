// Copyright © 2021 Swingby

package ecdsautils

import (
	"crypto/ecdsa"
	"encoding/json"
	"math/big"

	"github.com/hashicorp/go-multierror"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/vss"
	"github.com/binance-chain/tss-lib/tss"
)

type ECDSASignature struct {
	R, S *big.Int
}

type AbortTrigger int

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
	hash = common.SHA512_256i(pk.AsInts()...).Bytes()
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

func HandleMultiErrorVictimAndCulprit(culpritSet map[*tss.PartyID]struct{}, culprits []AttributionOfBlame,
	Ps tss.SortedPartyIDs, errorMap map[FeldmanError]string, wrapMultiErrorFunc func(err error, victim *tss.PartyID, culprits ...*tss.PartyID) *tss.Error) *tss.Error {
	uniqueCulprits := make([]*tss.PartyID, 0, len(culpritSet))
	for aCulprit := range culpritSet {
		uniqueCulprits = append(uniqueCulprits, aCulprit)
	}

	var multiErr error
	for _, culprit := range culprits {
		vc := &tss.VictimAndCulprit{Victim: Ps[culprit.Victim], Culprit: culprit.CulpritParty,
			Message: errorMap[culprit.TheFeldmanError]}
		multiErr = multierror.Append(multiErr, vc)
	}
	if len(culprits) > 0 {
		return wrapMultiErrorFunc(multiErr, Ps[culprits[0].Victim], uniqueCulprits...)
	} else {
		return nil
	}
}

func ProofNSquareFree(NTildei *big.Int, p *big.Int, q *big.Int) (*big.Int, *big.Int) {
	randIntProofNSquareFreei := common.GetRandomPositiveInt(NTildei)

	// Using Euler's totient function: phi(N)=phi(P)(Q)=(P-1)(Q-1)=2p2q
	phiNTildei := new(big.Int).Mul(new(big.Int).Mul(big.NewInt(4), p), q)
	bigM := new(big.Int).ModInverse(NTildei, phiNTildei)
	proofNSquareFree := common.ModInt(NTildei).Exp(randIntProofNSquareFreei, bigM)
	return randIntProofNSquareFreei, proofNSquareFree
}
