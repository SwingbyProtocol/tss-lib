// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"math/big"
	sync "sync"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	zkpfac "github.com/binance-chain/tss-lib/crypto/zkp/fac"
	zkpsch "github.com/binance-chain/tss-lib/crypto/zkp/sch"
	"github.com/binance-chain/tss-lib/tss"

	zkpmod "github.com/binance-chain/tss-lib/crypto/zkp/mod"
)

const (
	paillierModulusLen = 2048
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	Pi := round.Parties().IDs()[i]
	round.ok[i] = true

	// Fig 5. Round 3.1 / Fig 6. Round 3.1
	toCmp := new(big.Int).Lsh(big.NewInt(1), 1024)
	errChs := make(chan *tss.Error, (len(round.Parties().IDs())-1)*3)
	rid := round.temp.ridi
	wg := sync.WaitGroup{}
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		rid = new(big.Int).Xor(rid, round.temp.r2msgRidj[j])
		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			if round.save.PaillierPKs[j].N.BitLen() < paillierModulusLen {
				errChs <- round.WrapError(errors.New("paillier modulus too small"), Pj)
				return
			}
			if round.save.NTildej[j].Cmp(toCmp) < 0 {
				errChs <- round.WrapError(errors.New("paillier-blum modulus too small"), Pj)
				return
			}
			𝜓j := round.temp.r2msg𝜓j[j]
			if verifyOk := 𝜓j.Verify(round.save.H1j[j], round.save.H2j[j], round.save.NTildej[j]); !verifyOk {
				errChs <- round.WrapError(errors.New("error in prm proof verification"), Pj)
				return
			}
			listToHash, err := crypto.FlattenECPoints(round.temp.r2msgVss[j])
			if err != nil {
				errChs <- round.WrapError(err, Pj)
				return
			}
			listToHash = append(listToHash, round.save.PaillierPKs[j].N, round.temp.r2msgRidj[j],
				round.temp.r2msgXj[j].X(), round.temp.r2msgXj[j].Y(),
				round.temp.r2msgAj[j].X(), round.temp.r2msgAj[j].Y(), round.save.NTildej[j], round.save.H1j[j],
				round.save.H2j[j])

			for _, a := range 𝜓j.A {
				listToHash = append(listToHash, a)
			}
			for _, z := range 𝜓j.Z {
				listToHash = append(listToHash, z)
			}
			VjHash := common.SHA512_256i(listToHash...)
			if VjHash.Cmp(round.temp.r1msgVHashs[j]) != 0 {
				errChs <- round.WrapError(errors.New("verify hash failed"), Pj)
				return
			}
		}(j, Pj)
	}
	round.temp.rid = rid
	wg.Wait()
	close(errChs)
	culprits := make([]*tss.PartyID, 0)
	for err := range errChs {
		culprits = append(culprits, err.Culprits()...)
	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("round3: failed stage 3.1"), culprits...)
	}

	// Fig 5. Round 3.2 / Fig 6. Round 3.2
	𝜓i, err := zkpmod.NewProof(round.save.NTildei, common.PrimeToSafePrime(round.save.P), common.PrimeToSafePrime(round.save.Q))
	if err != nil {
		return round.WrapError(errors.New("create proofmod failed"))
	}
	𝜙ji, err := zkpfac.NewProof(round.EC(), &round.save.PaillierSK.PublicKey, round.save.NTildei,
		round.save.H1i, round.save.H2i, common.PrimeToSafePrime(round.save.P), common.PrimeToSafePrime(round.save.Q))
	if err != nil {
		return round.WrapError(errors.New("create proofPrm failed"))
	}
	xi := new(big.Int).Set(round.temp.shares[i].Share)
	Xi := crypto.ScalarBaseMult(round.EC(), xi)
	𝜓ij, err := zkpsch.NewProofWithAlpha(Xi, xi, round.temp.τ, rid)
	if err != nil {
		return round.WrapError(errors.New("create proofSch failed"))
	}

	errChs = make(chan *tss.Error, len(round.Parties().IDs())-1)
	wg = sync.WaitGroup{}
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()

			Cij, err := round.save.PaillierPKs[j].Encrypt(round.temp.shares[j].Share)
			if err != nil {
				errChs <- round.WrapError(errors.New("encrypt error"), Pi)
				return
			}

			r3msg := NewKGRound3Message(Pj, round.PartyID(), Cij, 𝜓i, 𝜙ji, 𝜓ij)
			round.out <- r3msg
		}(j, Pj)
	}
	wg.Wait()
	close(errChs)
	for err := range errChs {
		return err
	}

	return nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound3Message); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round3) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.r3msgxij {
		if round.ok[j] {
			continue
		}
		if msg == nil {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
