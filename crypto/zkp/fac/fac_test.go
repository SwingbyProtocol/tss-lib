// Copyright © 2021 Swingby

package zkpfac

import (
	"math/big"
	"testing"
	"time"

	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/stretchr/testify/assert"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testSafePrimeBits = 1024
)

func TestFacPQNoSmallFactor(test *testing.T) {
	ec := tss.EC()
	Twol := ec.Params().N

	primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NCap, s, t, err := crypto.GenerateNTildei(primes)
	modNCap := common.ModInt(NCap)

	pqOk := false

	var p, q *big.Int
	var pk *paillier.PublicKey

	for !pqOk {
		var err2 error
		_, pk, p, q, err2 = paillier.GenerateKeyPairAndPQ(testSafePrimeBits*2, time.Minute*10)
		assert.NoError(test, err2)
		sqrtNo := new(big.Int).Sqrt(pk.N)
		sqrtNoTwol := modNCap.Mul(sqrtNo, Twol)
		pUpperBound := p.Cmp(sqrtNoTwol) == -1
		qUpperBound := q.Cmp(sqrtNoTwol) == -1
		pLowerBound := p.Cmp(Twol) == +1
		qLowerBound := q.Cmp(Twol) == +1
		pqOk = pUpperBound && qUpperBound && pLowerBound && qLowerBound
	}

	proof, err := NewProof(ec, pk, NCap, s, t, p, q)
	assert.NoError(test, err)

	ok := proof.Verify(ec, pk, NCap, s, t)
	assert.True(test, ok, "proof must verify")
}
