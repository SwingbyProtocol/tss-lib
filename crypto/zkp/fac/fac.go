// Copyright © 2021 Swingby

package zkpfac

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/paillier"
)

const (
	ProofFacBytesParts = 11
)

type (
	ProofFac struct {
		P, Q, A, B, T, Sigma, Z1, Z2, W1, W2, V *big.Int
	}
)

// NewProof implements prooffac
func NewProof(ec elliptic.Curve, pk *paillier.PublicKey, NCap, s, t, p, q *big.Int) (*ProofFac, error) {
	if ec == nil || pk == nil || NCap == nil || s == nil || t == nil || p == nil || q == nil {
		return nil, errors.New("ProveDec constructor received nil value(s)")
	}

	Twol := ec.Params().N                                                                 // "q" (N) == "2^l"
	N3 := new(big.Int).Mul(ec.Params().N, new(big.Int).Mul(ec.Params().N, ec.Params().N)) // "q3" == "2^(l+𝜀)
	TwolPlus𝜀 := N3
	sqrtNo := new(big.Int).Sqrt(pk.N) // pk.N == No
	TwolPlus𝜀SqrtNo := new(big.Int).Mul(TwolPlus𝜀, sqrtNo)
	TwolNCap := new(big.Int).Mul(Twol, NCap) // "qNCap"
	TwolNoNCap := new(big.Int).Mul(TwolNCap, pk.N)
	TwolPlus𝜀NCap := new(big.Int).Mul(TwolPlus𝜀, NCap)
	TwolPlus𝜀NoNCap := new(big.Int).Mul(TwolPlus𝜀NCap, pk.N)

	// Fig 28.1 sample
	𝛼, 𝛽 := common.GetRandomPositiveInt(TwolPlus𝜀SqrtNo), common.GetRandomPositiveInt(TwolPlus𝜀SqrtNo)
	𝜇, 𝜈 := common.GetRandomPositiveInt(TwolNCap), common.GetRandomPositiveInt(TwolNCap)
	𝜎 := common.GetRandomPositiveInt(TwolNoNCap)
	r := common.GetRandomPositiveInt(TwolPlus𝜀NoNCap)
	x, y := common.GetRandomPositiveInt(TwolPlus𝜀NCap), common.GetRandomPositiveInt(TwolPlus𝜀NCap)

	// Fig 28.1 compute
	modNCap := common.ModInt(NCap)
	P, Q := modNCap.Mul(modNCap.Exp(s, p), modNCap.Exp(t, 𝜇)), modNCap.Mul(modNCap.Exp(s, q), modNCap.Exp(t, 𝜈))
	A := modNCap.Mul(modNCap.Exp(s, 𝛼), modNCap.Exp(t, x))
	B := modNCap.Mul(modNCap.Exp(s, 𝛽), modNCap.Exp(t, y))
	T := modNCap.Mul(modNCap.Exp(Q, 𝛼), modNCap.Exp(t, r))

	// Fig 29.2 e
	var e *big.Int
	{
		eHash := common.SHA512_256i(append(pk.AsInts(), P, Q, A, B, T, 𝜎)...)
		e = common.RejectionSample(ec.Params().N, eHash) // Likely N and not secret input q
	}

	// Fig 29.3
	ŝ := new(big.Int).Sub(𝜎, new(big.Int).Mul(𝜈, p))

	z1 := new(big.Int).Add(𝛼, new(big.Int).Mul(e, p))
	z2 := new(big.Int).Add(𝛽, new(big.Int).Mul(e, q))
	w1 := new(big.Int).Add(x, new(big.Int).Mul(e, 𝜇))
	w2 := new(big.Int).Add(y, new(big.Int).Mul(e, 𝜈))
	v := new(big.Int).Add(r, new(big.Int).Mul(e, ŝ))

	return &ProofFac{P: P, Q: Q, A: A, B: B, T: T, Sigma: 𝜎, Z1: z1, Z2: z2, W1: w1, W2: w2, V: v}, nil
}

func NewProofFromBytes(bzs [][]byte) (*ProofFac, error) {
	if !common.NonEmptyMultiBytes(bzs) {
		return nil, fmt.Errorf("expected non-empty multy bytes to construct ProofFac")
	}
	return &ProofFac{
		P:     new(big.Int).SetBytes(bzs[0]),
		Q:     new(big.Int).SetBytes(bzs[1]),
		A:     new(big.Int).SetBytes(bzs[2]),
		B:     new(big.Int).SetBytes(bzs[3]),
		T:     new(big.Int).SetBytes(bzs[4]),
		Sigma: new(big.Int).SetBytes(bzs[5]),
		Z1:    new(big.Int).SetBytes(bzs[6]),
		Z2:    new(big.Int).SetBytes(bzs[7]),
		W1:    new(big.Int).SetBytes(bzs[8]),
		W2:    new(big.Int).SetBytes(bzs[9]),
		V:     new(big.Int).SetBytes(bzs[10]),
	}, nil
}

func (pf *ProofFac) ValidateBasic() bool {
	return pf.P != nil &&
		pf.Q != nil &&
		pf.A != nil &&
		pf.B != nil &&
		pf.T != nil &&
		pf.Sigma != nil &&
		pf.Z1 != nil &&
		pf.Z2 != nil &&
		pf.W1 != nil &&
		pf.W2 != nil
}

func (pf *ProofFac) Verify(ec elliptic.Curve, pk *paillier.PublicKey, NCap, s, t *big.Int) bool {
	if pf == nil || !pf.ValidateBasic() || ec == nil || NCap == nil || s == nil || t == nil {
		return false
	}

	No := pk.N
	modNCap := common.ModInt(NCap)

	var e *big.Int
	{
		eHash := common.SHA512_256i(append(pk.AsInts(), pf.P, pf.Q, pf.A, pf.B, pf.T, pf.Sigma)...)
		e = common.RejectionSample(ec.Params().N, eHash) // Likely N and not secret input q
	}

	R := new(big.Int).Mul(modNCap.Exp(s, No), modNCap.Exp(t, pf.Sigma))

	// Fig 28. Equality Checks
	{
		left := modNCap.Mul(modNCap.Exp(s, pf.Z1), modNCap.Exp(t, pf.W1))
		right := modNCap.Mul(pf.A, modNCap.Exp(pf.P, e))
		if left.Cmp(right) != 0 {
			return false
		}
	}

	{
		left := modNCap.Mul(modNCap.Exp(s, pf.Z2), modNCap.Exp(t, pf.W2))
		right := modNCap.Mul(pf.B, modNCap.Exp(pf.Q, e))
		if left.Cmp(right) != 0 {
			return false
		}
	}

	{
		left := modNCap.Mul(modNCap.Exp(pf.Q, pf.Z1), modNCap.Exp(t, pf.V))
		right := modNCap.Mul(pf.T, modNCap.Exp(R, e))
		if left.Cmp(right) != 0 {
			return false
		}
	}

	return true
}

func (pf *ProofFac) Bytes() [ProofFacBytesParts][]byte {
	return [...][]byte{
		pf.P.Bytes(),
		pf.Q.Bytes(),
		pf.A.Bytes(),
		pf.B.Bytes(),
		pf.T.Bytes(),
		pf.Sigma.Bytes(),
		pf.Z1.Bytes(),
		pf.Z2.Bytes(),
		pf.W1.Bytes(),
		pf.W2.Bytes(),
		pf.V.Bytes(),
	}
}
