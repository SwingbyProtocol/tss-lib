// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	cmt "github.com/binance-chain/tss-lib/crypto/commitments"
	"github.com/binance-chain/tss-lib/crypto/dlnp"
	"github.com/binance-chain/tss-lib/crypto/paillier"
	"github.com/binance-chain/tss-lib/crypto/vss"
	ecdsautils "github.com/binance-chain/tss-lib/ecdsa"
	"github.com/binance-chain/tss-lib/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-resharing.pb.go

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*DGRound1Message)(nil),
		(*DGRound2Message1)(nil),
		(*DGRound2Message2)(nil),
		(*DGRound3Message1)(nil),
		(*DGRound3Message2)(nil),
	}
)

// ----- //

func NewDGRound1Message(
	to []*tss.PartyID,
	from *tss.PartyID,
	ecdsaPub *crypto.ECPoint,
	vct cmt.HashCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	content := &DGRound1Message{
		EcdsaPub:    ecdsaPub.ToProtobufPoint(),
		VCommitment: vct.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound1Message) ValidateBasic() bool {
	return m != nil &&
		m.EcdsaPub != nil &&
		m.EcdsaPub.ValidateBasic() &&
		common.NonEmptyBytes(m.VCommitment)
}

func (m *DGRound1Message) UnmarshalECDSAPub() (*crypto.ECPoint, error) {
	return crypto.NewECPointFromProtobuf(m.GetEcdsaPub())
}

func (m *DGRound1Message) UnmarshalVCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetVCommitment())
}

// ----- //

func NewDGRound2Message1(
	to []*tss.PartyID,
	from *tss.PartyID,
	paillierPK *paillier.PublicKey,
	authEcdsaPK *ecdsa.PublicKey,
	authPaillierSignature *ecdsautils.ECDSASignature,
	paillierPf paillier.Proof,
	NTildei, H1i, H2i *big.Int,
	dlnProof1, dlnProof2 *dlnp.Proof,
) (tss.ParsedMessage, error) {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	paiPfBzs := common.BigIntsToBytes(paillierPf[:])
	dlnProof1Bz, err := dlnProof1.Marshal()
	if err != nil {
		return nil, err
	}
	dlnProof2Bz, err := dlnProof2.Marshal()
	if err != nil {
		return nil, err
	}
	content := &DGRound2Message1{
		PaillierN:                     paillierPK.N.Bytes(),
		PaillierProof:                 paiPfBzs,
		NTilde:                        NTildei.Bytes(),
		H1:                            H1i.Bytes(),
		H2:                            H2i.Bytes(),
		Dlnproof_1:                    dlnProof1Bz,
		Dlnproof_2:                    dlnProof2Bz,
		AuthenticationEcdsaPublicKeyX: authEcdsaPK.X.Bytes(),
		AuthenticationEcdsaPublicKeyY: authEcdsaPK.Y.Bytes(),
		AuthenticationPaillierSigR:    authPaillierSignature.R.Bytes(),
		AuthenticationPaillierSigS:    authPaillierSignature.S.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg), nil
}

func (m *DGRound2Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.PaillierProof) &&
		common.NonEmptyBytes(m.PaillierN) &&
		common.NonEmptyBytes(m.NTilde) &&
		common.NonEmptyBytes(m.H1) &&
		common.NonEmptyBytes(m.H2) &&
		// expected len of dln proof = sizeof(int64) + len(alpha) + len(t)
		common.NonEmptyMultiBytes(m.GetDlnproof_1(), 2+(dlnp.Iterations*2)) &&
		common.NonEmptyMultiBytes(m.GetDlnproof_2(), 2+(dlnp.Iterations*2))
}

func (m *DGRound2Message1) UnmarshalPaillierPK() *paillier.PublicKey {
	return &paillier.PublicKey{
		N: new(big.Int).SetBytes(m.PaillierN),
	}
}

func (m *DGRound2Message1) UnmarshalNTilde() *big.Int {
	return new(big.Int).SetBytes(m.GetNTilde())
}

func (m *DGRound2Message1) UnmarshalH1() *big.Int {
	return new(big.Int).SetBytes(m.GetH1())
}

func (m *DGRound2Message1) UnmarshalH2() *big.Int {
	return new(big.Int).SetBytes(m.GetH2())
}

func (m *DGRound2Message1) UnmarshalPaillierProof() paillier.Proof {
	var pf paillier.Proof
	ints := common.ByteSlicesToBigInts(m.PaillierProof)
	copy(pf[:], ints[:paillier.ProofIters])
	return pf
}

func (m *DGRound2Message1) UnmarshalDLNProof1() (*dlnp.Proof, error) {
	return dlnp.UnmarshalProof(m.GetDlnproof_1())
}

func (m *DGRound2Message1) UnmarshalDLNProof2() (*dlnp.Proof, error) {
	return dlnp.UnmarshalProof(m.GetDlnproof_2())
}

func (m *DGRound2Message1) UnmarshalAuthEcdsaPK() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{X: new(big.Int).SetBytes(m.GetAuthenticationEcdsaPublicKeyX()),
		Y:     new(big.Int).SetBytes(m.GetAuthenticationEcdsaPublicKeyY()),
		Curve: tss.EC(),
	}
}

func (m *DGRound2Message1) UnmarshalAuthPaillierSignature() *ecdsautils.ECDSASignature {
	return ecdsautils.NewECDSASignature(new(big.Int).SetBytes(m.GetAuthenticationPaillierSigR()),
		new(big.Int).SetBytes(m.GetAuthenticationPaillierSigS()))
}

// ----- //

func NewDGRound2Message2(
	to []*tss.PartyID,
	from *tss.PartyID,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: true,
	}
	content := &DGRound2Message2{}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound2Message2) ValidateBasic() bool {
	return true
}

// ----- //

func NewDGRound3Message1(
	to *tss.PartyID,
	from *tss.PartyID,
	share *vss.Share,
	authenticationEcdsaSig *ecdsautils.ECDSASignature,
	authEcdsaPK *ecdsa.PublicKey,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               []*tss.PartyID{to},
		IsBroadcast:      false,
		IsToOldCommittee: false,
	}
	content := &DGRound3Message1{
		Share:                         share.Share.Bytes(),
		AuthenticationEcdsaSigR:       authenticationEcdsaSig.R.Bytes(),
		AuthenticationEcdsaSigS:       authenticationEcdsaSig.S.Bytes(),
		AuthenticationEcdsaPublicKeyX: authEcdsaPK.X.Bytes(),
		AuthenticationEcdsaPublicKeyY: authEcdsaPK.Y.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound3Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.Share)
}

func (m *DGRound3Message1) UnmarshalAuthEcdsaSignature() *ecdsautils.ECDSASignature {
	return ecdsautils.NewECDSASignature(new(big.Int).SetBytes(m.AuthenticationEcdsaSigR),
		new(big.Int).SetBytes(m.AuthenticationEcdsaSigS))
}

func (m *DGRound3Message1) UnmarshalAuthEcdsaPK() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{X: new(big.Int).SetBytes(m.GetAuthenticationEcdsaPublicKeyX()),
		Y:     new(big.Int).SetBytes(m.GetAuthenticationEcdsaPublicKeyY()),
		Curve: tss.EC(),
	}
}

// ----- //

func NewDGRound3Message2(
	to []*tss.PartyID,
	from *tss.PartyID,
	vdct cmt.HashDeCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	vDctBzs := common.BigIntsToBytes(vdct)
	content := &DGRound3Message2{
		VDecommitment: vDctBzs,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound3Message2) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.VDecommitment)
}

func (m *DGRound3Message2) UnmarshalVDeCommitment() cmt.HashDeCommitment {
	deComBzs := m.GetVDecommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

// ----- //

func NewDGRound4MessageAck(
	to []*tss.PartyID,
	from *tss.PartyID,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:                    from,
		To:                      to,
		IsBroadcast:             true,
		IsToOldAndNewCommittees: true,
	}
	content := &DGRound4Message{
		Content: &DGRound4Message_Ack{},
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound4Message) ValidateBasic() bool {
	return true
}

// ----- //

func NewDGRound4MessageAbort(
	to []*tss.PartyID,
	from *tss.PartyID,
	suspiciousVssShareWithAuthSigMessages []*common.VSSShareWithAuthSigMessage,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:                    from,
		To:                      to,
		IsBroadcast:             true,
		IsToOldAndNewCommittees: true,
	}
	content := &DGRound4Message{
		Content: &DGRound4Message_Abort{
			Abort: &DGRound4Message_AbortData{
				SuspiciousVsss: suspiciousVssShareWithAuthSigMessages,
				PlaintiffParty: uint32(from.Index),
			},
		},
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *DGRound4Message_AbortData) UnmarshalFeldmanCheckFailureEvidence() ([]*ecdsautils.FeldmanCheckFailureEvidence, int) {
	suspiciousVsss := m.GetSuspiciousVsss()
	feldmanCheckFailures := make([]*ecdsautils.FeldmanCheckFailureEvidence, len(suspiciousVsss))
	for n, vsss := range suspiciousVsss {
		share := vss.Share{Share: new(big.Int).SetBytes(vsss.GetVssSigma()),
			ID:        new(big.Int).SetBytes(vsss.GetVssId()),
			Threshold: int(vsss.GetVssThreshold()),
		}
		pk := ecdsa.PublicKey{X: new(big.Int).SetBytes(vsss.GetAuthSigPk().GetX()),
			Y:     new(big.Int).SetBytes(vsss.GetAuthSigPk().GetY()),
			Curve: tss.EC()}
		authEcdsaSignature := ecdsautils.ECDSASignature{R: new(big.Int).SetBytes(vsss.GetAuthEcdsaSignatureR()),
			S: new(big.Int).SetBytes(vsss.GetAuthEcdsaSignatureS())}
		var Dj = make([]*big.Int, len(vsss.GetDj()))
		Cj := new(big.Int).SetBytes(vsss.GetCj())
		for a, k := range vsss.GetDj() {
			Dj[a] = new(big.Int).SetBytes(k)
		}

		e := ecdsautils.FeldmanCheckFailureEvidence{Sigmaji: &share, AuthSignaturePkj: pk,
			AccusedPartyj:         vsss.GetAccusedParty(),
			TheHashCommitDecommit: cmt.HashCommitDecommit{C: Cj, D: Dj},
			AuthEcdsaSignature:    &authEcdsaSignature}
		feldmanCheckFailures[n] = &e
	}
	return feldmanCheckFailures, int(m.GetPlaintiffParty())
}
