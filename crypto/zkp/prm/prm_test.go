// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpprm

import (
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/ecdsa/keygen"
)

func TestPrm(test *testing.T) {
	preParams, err := keygen.GeneratePreParams(time.Minute*10, 8)
	assert.NoError(test, err)

	s, t, lambda, P, Q, N := preParams.H1i, preParams.H2i, preParams.Beta, preParams.P, preParams.Q, preParams.NTildei
	P2, Q2 := new(big.Int).Mul(P, big.NewInt(2)), new(big.Int).Mul(Q, big.NewInt(2))
	Phi := new(big.Int).Mul(P2, Q2)
	fmt.Println(Phi)
	fmt.Println(N)

    proof, err := NewProof(s, t, N, Phi, lambda)
    assert.NoError(test, err)

    ok := proof.Verify(s, t, N)
    assert.True(test, ok, "proof must verify")
}
