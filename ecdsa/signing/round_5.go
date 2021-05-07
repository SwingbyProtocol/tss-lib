// Copyright © 2021 Swingby

package signing

import (
	"errors"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/crypto/zkp"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round5) InboundQueuesToConsume() []tss.QueueFunction {
	return nil
}

func (round *round5) Preprocess() (*tss.GenericParameters, *tss.Error) {
	if round.started {
		return nil, round.WrapError(errors.New("round already started"))
	}
	round.number = 5
	round.started = true
	round.ended = false
	return nil, nil

}

func (round *round5) Postprocess(parameters *tss.GenericParameters) *tss.Error {
	Pi := round.PartyID()
	i := Pi.Index
	modN := common.ModInt(tss.EC().Params().N)

	bigR, err := crypto.NewECPointFromProtobuf(round.temp.BigR)
	if err != nil {
		common.Logger.Error(err)
		return nil
	}
	r := bigR.X()

	// used in FinalizeGetOurSigShare
	round.temp.RSigmaI = modN.Mul(r, round.temp.sigmaI).Bytes()

	// all parties broadcast Rdash_i = k_i * R
	kI := new(big.Int).SetBytes(round.temp.KI)
	bigRBarI := bigR.ScalarMult(kI)

	// compute ZK proof of consistency between R_i and E_i(k_i)
	// ported from: https://git.io/Jf69a

	pdlWSlackWitness := zkp.PDLwSlackWitness{
		X: kI,
		R: round.temp.rAKI,
	}

	var pdlWSlackPfs []zkp.PDLwSlackProof
	for j, _ := range round.Parties().IDs() {
		if j == i {
			pdlWSlackPfs = append(pdlWSlackPfs, zkp.PDLwSlackProof{})
			continue
		}
		pdlWSlackStatement := zkp.PDLwSlackStatement{
			N:          round.key.PaillierSK.N,
			CipherText: round.temp.cAKI,
			Q:          bigRBarI,
			G:          bigR,
			H1:         round.key.H1j[j],
			H2:         round.key.H2j[j],
			NTilde:     round.key.NTildej[j],
		}

		pdlWSlackPf := zkp.NewPDLwSlackProof(pdlWSlackWitness, pdlWSlackStatement)
		pdlWSlackPfs = append(pdlWSlackPfs, pdlWSlackPf)
	}

	r5msg := NewSignRound5Message(Pi, bigRBarI, pdlWSlackPfs)
	round.out <- r5msg
	round.ended = true
	return nil
}

func (round *round5) CanProcess(msg tss.ParsedMessage) bool {
	return false
}

func (round *round5) CanProceed() bool {
	return round.started && round.ended
}

func (round *round5) NextRound() tss.Round {
	round.started = false
	return &round6{round, false}
}
