// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/pkg/errors"

	"github.com/binance-chain/tss-lib/test"
	"github.com/binance-chain/tss-lib/tss"
)

const (
	// To change these parameters, you must first delete the text fixture files in test/_fixtures/ and then run the keygen test alone.
	// Then the signing and resharing tests will work with the new n, t configuration using the newly written fixture files.
	TestParticipants = test.TestParticipants
	TestThreshold    = test.TestThreshold
)

const (
	testFixtureDirFormat  = "%s/../../test/_ecdsa_fixtures"
	testFixtureFileFormat = "keygen_data_%d.json"
)

var (
	constTestNTildei0, _ = hex.DecodeString("deaf005da2e13f26b1821700f495b4bc9f29145055ec1fdba496b85fcd5b217190473c42176104381cc0475385e929798fd09fec37626082e825bdadd54e3910e9e55a0a45903c57ec9f4c26006c62c5d81725d94a3d3ddbe427ef34f11b7f177f78862fff4612d9536272c5951aee9974bb98bdbfebcd4ad40ee26204f3425d18dde90e6976a5cfdd2fb8a476ee5be3fbd6fd5f32d5697735df420f84d6c4ad6f4754dcea0a3f036aeeeefbf65337694f14e442cba0e862449174e7d6edd023cbad7329adae6917fcc028de5e3fc681e6a601ef2de7503a3485b6809ee54dc82ab8edc178a934b42b2dd9b7b778307050373f6b51b20179ef3997befebeb3d5")
	constTestH1i0, _     = hex.DecodeString("8a263bf5d5b19bd0c0ca2a57d7181f987a0ad39ece0ad3dbf747cbcaa4296f048e3b8306a25bb9fb426b00cb78423e8f741e7e1b48bc6c3cb8d036cc482b5734888e66eecb0b33afd026f2bd98fc2ca57aede26f82f416accfc21999442b10fdfa7a962a8607ff10eeb2f3512b0bfa72097cdcc65fe25a1f6681b605804fa2f554e972b9f10931094d1edc3888f1cb98528a77cea2a9597a2c91177e4d28ec50d32a2b26162c28988fac633c5839db916e00a56e5b33130fefd5662ddca80224fd1b9d924f676b944b387b89a283e02aab9def9d3e9be04f59a8b2545b6a55f4a5a4e996d0b2ae431baad205f5a47067bea561885c55a16e52f36bda2a36bc4d")
	constTestH2i0, _     = hex.DecodeString("d375f48fda5728f8d8db394dde4c024922c23ac8e09ba84bf14360da0ded6a257416baac2ef6879aa508f57dd31e120d05976126673dd5df4d677cf24c87eb52dcdd6c47da61c4e221ae45bfa19e088784d7a512f8f0a90fedfbea44e05abe95120a9ec8a0d0bea473677b390a220bd7a83e3d79482314109b17ab8b596f2b46b8c1620ce232a44245c920cbfc7ac94010181c4d10c4cece99da3f3a20359ec3271666b7885b6a94538a7ab4d70066ddeb30a6f40b036f3f9e61dfc4bfdf91a5e2e9719e4ab65f479e9f66fef347795abb0f8ce47ac9ca0aa75471c9fafdba72d2e3b4c7ae231fcefd3bffdc93292b16cc8a28a0c935de64c33d91f750d63635")

	constTestNTildei1, _ = hex.DecodeString("deaf005da2e13f26b1821700f495b4bc9f29145055ec1fdba496b85fcd5b217190473c42176104381cc0475385e929798fd09fec37626082e825bdadd54e3910e9e55a0a45903c57ec9f4c26006c62c5d81725d94a3d3ddbe427ef34f11b7f177f78862fff4612d9536272c5951aee9974bb98bdbfebcd4ad40ee26204f3425d18dde90e6976a5cfdd2fb8a476ee5be3fbd6fd5f32d5697735df420f84d6c4ad6f4754dcea0a3f036aeeeefbf65337694f14e442cba0e862449174e7d6edd023cbad7329adae6917fcc028de5e3fc681e6a601ef2de7503a3485b6809ee54dc82ab8edc178a934b42b2dd9b7b778307050373f6b51b20179ef3997befebeb3d5")
	constTestH1i1, _     = hex.DecodeString("8a263bf5d5b19bd0c0ca2a57d7181f987a0ad39ece0ad3dbf747cbcaa4296f048e3b8306a25bb9fb426b00cb78423e8f741e7e1b48bc6c3cb8d036cc482b5734888e66eecb0b33afd026f2bd98fc2ca57aede26f82f416accfc21999442b10fdfa7a962a8607ff10eeb2f3512b0bfa72097cdcc65fe25a1f6681b605804fa2f554e972b9f10931094d1edc3888f1cb98528a77cea2a9597a2c91177e4d28ec50d32a2b26162c28988fac633c5839db916e00a56e5b33130fefd5662ddca80224fd1b9d924f676b944b387b89a283e02aab9def9d3e9be04f59a8b2545b6a55f4a5a4e996d0b2ae431baad205f5a47067bea561885c55a16e52f36bda2a36bc4d")
	constTestH2i1, _     = hex.DecodeString("d375f48fda5728f8d8db394dde4c024922c23ac8e09ba84bf14360da0ded6a257416baac2ef6879aa508f57dd31e120d05976126673dd5df4d677cf24c87eb52dcdd6c47da61c4e221ae45bfa19e088784d7a512f8f0a90fedfbea44e05abe95120a9ec8a0d0bea473677b390a220bd7a83e3d79482314109b17ab8b596f2b46b8c1620ce232a44245c920cbfc7ac94010181c4d10c4cece99da3f3a20359ec3271666b7885b6a94538a7ab4d70066ddeb30a6f40b036f3f9e61dfc4bfdf91a5e2e9719e4ab65f479e9f66fef347795abb0f8ce47ac9ca0aa75471c9fafdba72d2e3b4c7ae231fcefd3bffdc93292b16cc8a28a0c935de64c33d91f750d63635")

	constTestNTildeiArray = [][]byte{constTestNTildei0, constTestNTildei1}
	constTestH1iArray     = [][]byte{constTestH1i0, constTestH1i1}
	constTestH2iArray     = [][]byte{constTestH2i0, constTestH2i1}
)

func LoadKeygenTestFixtures(qty int, optionalStart ...int) ([]LocalPartySaveData, tss.SortedPartyIDs, error) {
	keys := make([]LocalPartySaveData, 0, qty)
	start := 0
	if 0 < len(optionalStart) {
		start = optionalStart[0]
	}
	for i := start; i < qty; i++ {
		fixtureFilePath := makeTestFixtureFilePath(i)
		bz, err := ioutil.ReadFile(fixtureFilePath)
		if err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not open the test fixture for party %d in the expected location: %s. run keygen tests first.",
				i, fixtureFilePath)
		}
		var key LocalPartySaveData
		if err = json.Unmarshal(bz, &key); err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not unmarshal fixture data for party %d located at: %s",
				i, fixtureFilePath)
		}
		for _, kbxj := range key.BigXj {
			kbxj.SetCurve(tss.S256())
		}
		key.ECDSAPub.SetCurve(tss.S256())
		keys = append(keys, key)
	}
	partyIDs := make(tss.UnSortedPartyIDs, len(keys))
	for i, key := range keys {
		pMoniker := fmt.Sprintf("%d", i+start+1)
		partyIDs[i] = tss.NewPartyID(pMoniker, pMoniker, key.ShareID)
	}
	sortedPIDs := tss.SortPartyIDs(partyIDs)
	return keys, sortedPIDs, nil
}

func LoadKeygenTestFixturesRandomSet(qty, fixtureCount int) ([]LocalPartySaveData, tss.SortedPartyIDs, error) {
	keys := make([]LocalPartySaveData, 0, qty)
	plucked := make(map[int]interface{}, qty)
	for i := 0; len(plucked) < qty; i = (i + 1) % fixtureCount {
		_, have := plucked[i]
		if pluck := rand.Float32() < 0.5; !have && pluck {
			plucked[i] = new(struct{})
		}
	}
	for i := range plucked {
		fixtureFilePath := makeTestFixtureFilePath(i)
		bz, err := ioutil.ReadFile(fixtureFilePath)
		if err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not open the test fixture for party %d in the expected location: %s. run keygen tests first.",
				i, fixtureFilePath)
		}
		var key LocalPartySaveData
		if err = json.Unmarshal(bz, &key); err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not unmarshal fixture data for party %d located at: %s",
				i, fixtureFilePath)
		}
		for _, kbxj := range key.BigXj {
			kbxj.SetCurve(tss.S256())
		}
		key.ECDSAPub.SetCurve(tss.S256())
		keys = append(keys, key)
	}
	partyIDs := make(tss.UnSortedPartyIDs, len(keys))
	j := 0
	for i := range plucked {
		key := keys[j]
		pMoniker := fmt.Sprintf("%d", i+1)
		partyIDs[j] = tss.NewPartyID(pMoniker, pMoniker, key.ShareID)
		j++
	}
	sortedPIDs := tss.SortPartyIDs(partyIDs)
	sort.Slice(keys, func(i, j int) bool { return keys[i].ShareID.Cmp(keys[j].ShareID) == -1 })
	return keys, sortedPIDs, nil
}

func LoadNTildeH1H2FromTestFixture(idx int) (NTildei, h1i, h2i *big.Int, err error) {
	fixtures, _, err := LoadKeygenTestFixtures(idx + 1)
	if err != nil {
		return
	}
	fixture := fixtures[idx]
	NTildei, h1i, h2i = fixture.NTildei, fixture.H1i, fixture.H2i
	return
}

func ConstantTestNTildeH1H2(idx int) (NTildei, h1i, h2i *big.Int, err error) {
	NTildei = big.NewInt(0).SetBytes(constTestNTildeiArray[idx])
	h1i, h2i = big.NewInt(0).SetBytes(constTestH1iArray[idx]), big.NewInt(0).SetBytes(constTestH2iArray[idx])
	return
}

func makeTestFixtureFilePath(partyIndex int) string {
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	fixtureDirName := fmt.Sprintf(testFixtureDirFormat, srcDirName)
	return fmt.Sprintf("%s/"+testFixtureFileFormat, fixtureDirName, partyIndex)
}
