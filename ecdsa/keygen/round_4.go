// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"fmt"

	"github.com/hashicorp/go-multierror"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/zkp"
	"github.com/binance-chain/tss-lib/tss"
)

func (round *round4) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	Ps := round.Parties().IDs()
	PIDs := Ps.Keys()
	ecdsaPub := round.save.ECDSAPub

	// 1-3. (concurrent)
	// r3 messages are assumed to be available and != nil in this function
	r3msgs := round.temp.kgRound3Messages
	type channelOut struct {
		unWrappedErr error
		ok bool
	}
	chs := make([]chan channelOut, len(r3msgs))
	for i := range chs {
		chs[i] = make(chan channelOut)
	}
	for j, msg := range round.temp.kgRound3Messages {
		if j == i {
			continue
		}
		r3msg := msg.Content().(*KGRound3Message)
		go func(prf paillier.Proof, j int, ch chan<- channelOut) {
			ppk := round.save.PaillierPKs[j]
			ok, err := prf.Verify(ppk.N, PIDs[j], ecdsaPub)
			if err != nil {
				common.Logger.Error(round.WrapError(err, Ps[j]).Error())
				ch <- channelOut{err, false}
				return
			}
			ch <- channelOut{nil, ok}
		}(r3msg.UnmarshalProofInts(), j, chs[j])

		zkProofxi, err := r3msg.UnmarshalXiProof()
		if err != nil {
			common.Logger.Error("error unmarshalling the xj ZK proof for party %v", Ps[j])
			return round.WrapError(fmt.Errorf("error unmarshalling the xj ZK proof for party %v", Ps[j]))
		} else {
			go func(prf *zkp.DLogProof, j int, ch chan<- channelOut) {
				bigXj := round.save.BigXj[j]
				ok := prf.Verify(bigXj)
				if !ok {
					err := fmt.Errorf("error in the verification the xj ZK proof for party %v", Ps[j])
					common.Logger.Error(err)
					ch <- channelOut{err, false}
					return
				}
				ch <- channelOut{nil, ok}
			}(zkProofxi, j, chs[j])
		}
	}

	outResults := make([]channelOut, len(Ps))
	culprits := make([]*tss.PartyID, 0, len(Ps)) // who caused the error(s)
	// consume unbuffered channels (end the goroutines)
	for j, ch := range chs {
		if j == i {
			round.ok[j] = true
			continue
		}
		outResults[j] = <-ch
		if err := outResults[j].unWrappedErr; err != nil && j < len(Ps) {
			culprits = append(culprits, Ps[j])
		}
		round.ok[j] = outResults[j].ok
	}
	{
		var multiErr error
		if len(culprits) > 0 {
			for _, vssResult := range outResults {
				if vssResult.unWrappedErr == nil {
					continue
				}
				multiErr = multierror.Append(multiErr, vssResult.unWrappedErr)
			}
			return round.WrapError(multiErr, culprits...)
		}
	}

	round.end <- *round.save

	return nil
}

func (round *round4) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *round4) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *round4) NextRound() tss.Round {
	return nil // finished!
}
