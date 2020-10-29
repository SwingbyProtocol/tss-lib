// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package schnorr

import (
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/assert"
)

func TestSchnorrKeyGenAndSign(t *testing.T) {
	msg := "hello"
	privKey, err := GenerateKey(btcec.S256(), rand.Reader)
	assert.Nil(t, err)
	signature, err := privKey.Sign([]byte(msg))
	assert.Nil(t, err)
	ret := privKey.PublicKey.Verify([]byte(msg), signature.R, signature.S)
	assert.True(t, ret)
}

func TestSignVerifyFail(t *testing.T) {
	msg := "hello"
	privKey, err := GenerateKey(btcec.S256(), rand.Reader)
	assert.Nil(t, err)
	signature, err := privKey.Sign([]byte(msg))
	assert.Nil(t, err)
	ret := privKey.PublicKey.Verify([]byte(msg+"2"), signature.R, signature.S)
	assert.False(t, ret)
	// now we apply verify with a wrong public key
	privKey2, err := GenerateKey(btcec.S256(), rand.Reader)
	assert.Nil(t, err)
	ret = privKey2.PublicKey.Verify([]byte(msg), signature.R, signature.S)
	assert.False(t, ret)
}
