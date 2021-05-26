// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"encoding/hex"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/ecdsa"
	"github.com/binance-chain/tss-lib/tss"
)

type (
	LocalPreParams struct {
		PaillierSK          *paillier.PrivateKey // ski
		AuthEcdsaPrivateKey *ecdsautils.MarshallableEcdsaPrivateKey
		NTildei,
		H1i, H2i,
		Alpha, Beta,
		P, Q *big.Int
	}

	LocalSecrets struct {
		// secret fields (not shared, but stored locally)
		Xi, ShareID *big.Int // xi, kj
	}

	// Everything in LocalPartySaveData is saved locally to user's HD when done
	LocalPartySaveData struct {
		LocalPreParams
		LocalSecrets

		// original indexes (ki in signing preparation phase)
		Ks []*big.Int

		// n-tilde, h1, h2 for range proofs
		NTildej, H1j, H2j []*big.Int

		// public keys (Xj = uj*G for each Pj)
		BigXj             []*crypto.ECPoint                        // Xj
		PaillierPKs       []*paillier.PublicKey                    // pkj
		AuthenticationPKs []*ecdsautils.MarshallableEcdsaPublicKey // auth_yj

		// the ECDSA public key
		ECDSAPub *crypto.ECPoint // y

		// The ReshareKeyOffset is 0 before a reshare run and is set to an epoch each reshare run.
		ReshareKeyOffset uint64
	}
)

func NewLocalPartySaveData(partyCount int) (saveData LocalPartySaveData) {
	saveData.Ks = make([]*big.Int, partyCount)
	saveData.NTildej = make([]*big.Int, partyCount)
	saveData.H1j, saveData.H2j = make([]*big.Int, partyCount), make([]*big.Int, partyCount)
	saveData.BigXj = make([]*crypto.ECPoint, partyCount)
	saveData.PaillierPKs = make([]*paillier.PublicKey, partyCount)
	saveData.AuthenticationPKs = make([]*ecdsautils.MarshallableEcdsaPublicKey, partyCount)
	return
}

func (preParams LocalPreParams) Validate() bool {
	return preParams.PaillierSK != nil &&
		preParams.AuthEcdsaPrivateKey != nil &&
		preParams.NTildei != nil &&
		preParams.H1i != nil &&
		preParams.H2i != nil
}

func (preParams LocalPreParams) ValidateWithProof() bool {
	return preParams.Validate() &&
		preParams.Alpha != nil &&
		preParams.Beta != nil &&
		preParams.P != nil &&
		preParams.Q != nil
}

// BuildLocalSaveDataSubset re-creates the LocalPartySaveData to contain data for only the list of signing parties.
func BuildLocalSaveDataSubset(sourceData LocalPartySaveData, sortedIDs tss.SortedPartyIDs) LocalPartySaveData {
	keysToIndices := make(map[string]int, len(sourceData.Ks))
	for j, kj := range sourceData.Ks {
		keysToIndices[hex.EncodeToString(kj.Bytes())] = j
	}
	newData := NewLocalPartySaveData(sortedIDs.Len())
	newData.LocalPreParams = sourceData.LocalPreParams
	newData.LocalSecrets = sourceData.LocalSecrets
	newData.ECDSAPub = sourceData.ECDSAPub
	reshareKeyOffset := big.NewInt(int64(sourceData.ReshareKeyOffset))
	for j, id := range sortedIDs {
		idKey := new(big.Int).SetBytes(id.Key)
		keyAndShift := new(big.Int).Add(idKey, reshareKeyOffset)
		savedIdx, ok := keysToIndices[hex.EncodeToString(keyAndShift.Bytes())]
		if !ok {
			common.Logger.Warn("BuildLocalSaveDataSubset: unable to find a signer party in the local save data", id)
		}
		newData.Ks[j] = sourceData.Ks[savedIdx]
		newData.NTildej[j] = sourceData.NTildej[savedIdx]
		newData.H1j[j] = sourceData.H1j[savedIdx]
		newData.H2j[j] = sourceData.H2j[savedIdx]
		newData.BigXj[j] = sourceData.BigXj[savedIdx]
		newData.PaillierPKs[j] = sourceData.PaillierPKs[savedIdx]
		newData.AuthenticationPKs[j] = sourceData.AuthenticationPKs[savedIdx]
	}
	return newData
}
