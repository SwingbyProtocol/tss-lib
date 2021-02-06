// Copyright © 2021 Swingby

package signing

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/tss"
)

func UpdatePublicKeyAndAdjustBigXj(keyDerivationDelta *big.Int, keys []keygen.LocalPartySaveData,
	extendedChildPk *ecdsa.PublicKey) error {
	var err error
	gDelta := crypto.ScalarBaseMult(tss.EC(), keyDerivationDelta)
	for k := range keys {
		keys[k].ECDSAPub, err = crypto.NewECPoint(tss.EC(), extendedChildPk.X, extendedChildPk.Y)
		if err != nil {
			common.Logger.Errorf("error creating new extended child public key")
			return err
		}

		for j := range keys[k].BigXj {
			keys[k].BigXj[j], err = keys[k].BigXj[j].Add(gDelta)
			if err != nil {
				common.Logger.Errorf("error in delta operation")
				return err
			}
		}
	}
	return nil
}
