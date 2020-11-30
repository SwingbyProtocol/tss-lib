// Copyright © 2020 Swingby
//

package keygen

import (
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/vss"
)

type ECDSASignature struct {
	r, s *big.Int
}

func NewECDSASignature(r, s *big.Int) *ECDSASignature {
	return &ECDSASignature{r: r, s: s}
}

func HashShare(share *vss.Share) (hash []byte) {
	hash = append(share.ID.Bytes(), share.Share.Bytes()...)
	hash = append(hash, big.NewInt(int64(share.Threshold)).Bytes()...)
	hash = common.SHA512_256(hash)
	return
}

func HashPaillierKey(pk *paillier.PublicKey) (hash []byte) {
	hash = common.SHA512_256i(append(pk.AsInts())...).Bytes()
	return
}
