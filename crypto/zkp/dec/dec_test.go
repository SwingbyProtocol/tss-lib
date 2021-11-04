// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package zkpdec

import (
    "math/big"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"

    "github.com/binance-chain/tss-lib/common"
    "github.com/binance-chain/tss-lib/crypto"
    "github.com/binance-chain/tss-lib/crypto/paillier"
    "github.com/binance-chain/tss-lib/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
    testSafePrimeBits = 1024
)

func TestDec(test *testing.T) {
    ec := tss.EC()
    q := ec.Params().N

	primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
    NCap, s, t, err := crypto.GenerateNTildei(primes)
    assert.NoError(test, err)

    sk, pk, err := paillier.GenerateKeyPair(testSafePrimeBits*2, time.Minute*10)
    assert.NoError(test, err)

    x := common.GetRandomPositiveInt(q)
	y := new(big.Int).Add(x, q)
    C, rho, err := sk.EncryptAndReturnRandomness(y)
    assert.NoError(test, err)
	
    proof, err := NewProof(ec, pk, C, x, NCap, s, t, y, rho)
    assert.NoError(test, err)

    ok := proof.Verify(ec, pk, C, x, NCap, s, t)
    assert.True(test, ok, "proof must verify")
}

func TestDecWithCompositions(test *testing.T) {
    ec := tss.EC()
    q := ec.Params().N
    q3 := new(big.Int).Mul(q, q)
    q3 = new(big.Int).Mul(q, q3)
    modN := common.ModInt(q)
    zero := big.NewInt(0)

    primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
    NCap, s, t, err := crypto.GenerateNTildei(primes)
    assert.NoError(test, err)

    sk, pk, err := paillier.GenerateKeyPair(testSafePrimeBits*2, time.Minute*10)
    assert.NoError(test, err)
    N2 := pk.NSquare()

    // Ki
    𝛾i := common.GetRandomPositiveInt(q)
    ki := common.GetRandomPositiveInt(q)
    Ki, 𝜌i, err := sk.EncryptAndReturnRandomness(ki)

    proof1, err := NewProof(ec, pk, Ki, modN.Add(zero,ki), NCap, s, t, ki, 𝜌i)
    assert.NoError(test, err)
    ok1 := proof1.Verify(ec, pk, Ki, modN.Add(zero,ki), NCap, s, t)
    assert.True(test, ok1, "proof must verify")

    // 𝛾K
    𝛾K, err := pk.HomoMult(𝛾i, Ki)
    𝜌ʹ := big.NewInt(1).Exp(𝜌i, 𝛾i, N2)
    yʹ := q3.Mul(𝛾i, ki)
    proof2, err := NewProof(ec, pk, 𝛾K, modN.Add(zero,yʹ), NCap, s, t, yʹ, 𝜌ʹ)
    assert.NoError(test, err)
    ok2 := proof2.Verify(ec, pk, 𝛾K, modN.Add(zero,yʹ), NCap, s, t)
    assert.True(test, ok2, "proof must verify")

    // Dji
    x := common.GetRandomPositiveInt(q)
    y := new(big.Int).Add(x, q)
    Dji, sij, err := sk.EncryptAndReturnRandomness(y)
    assert.NoError(test, err)
    Dji, err = pk.HomoAdd(𝛾K, Dji)

    𝜌ʺ := N2.Mul(𝜌ʹ,sij)
    yʺ := q3.Add(y, yʹ)
    proof3, err := NewProof(ec, pk, Dji, modN.Add(zero, yʺ), NCap, s, t, yʺ, 𝜌ʺ)
    assert.NoError(test, err)

    ok3 := proof3.Verify(ec, pk, Dji, modN.Add(zero, yʺ), NCap, s, t)
    assert.True(test, ok3, "proof must verify")

}