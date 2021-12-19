package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/ecdsa/signing"
	"github.com/binance-chain/tss-lib/test"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/btcsuite/btcd/btcec"
	"github.com/ipfs/go-log"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

const libLogLevel = "warn"

type result struct {
	quorum   int
	duration time.Duration
}

func usage() {
	if _, err := fmt.Fprintf(os.Stderr, "usage: tss-benchsign [-flag=value, ...] datadir\n"); err != nil {
		panic(err)
	}
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	prt := message.NewPrinter(language.English)
	var (
		startQuorum = flag.Int("q", 3, "the minimum quorum (t+1) to use (default: 6)")
		endQuorum   = flag.Int("n", 8, "the maximum quorum (t+1) to benchmark up to (min: 2, default: 10)")
		runs        = flag.Int("r", 3, "the number of benchmarking runs (default: 3)")
		msgLatency  = flag.Int("l", 50, "the target network latency (simulated) per message in milliseconds (default: 50)")
		procs       = flag.Int("procs", runtime.NumCPU(), "the number of max go procs (threads) to use")
	)
	flag.Usage = usage
	if flag.Parse(); !flag.Parsed() {
		usage()
		os.Exit(1)
	}
	if *endQuorum <= 1 || *runs < 1 || *endQuorum < *startQuorum {
		fmt.Println("Error: q must be greater than 1, r must be greater than 0, endQuorum must be after startQuorum.")
		os.Exit(1)
	}
	if flag.NArg() < 1 {
		usage()
		os.Exit(1)
	}
	dir := flag.Args()[0]
	if stat, err := os.Stat(dir); os.IsNotExist(err) || stat == nil || !stat.IsDir() {
		fmt.Printf("Error: `%s` does not exist; run tss-benchgen to generate shares first.\n", dir)
		os.Exit(1)
	}
	if _, err := os.Stat(makeKeyGenDataFilePath(dir, *endQuorum-1)); os.IsNotExist(err) {
		fmt.Printf("Error: insufficient shares for the specified quorum; run tss-benchgen and generate at least %d shares.\n", *endQuorum)
		os.Exit(1)
	}

	fmt.Println("ECDSA/GG20 Benchmark Tool - Signing")
	fmt.Println("-----------------------------------")
	fmt.Printf("Will test quorums %d-%d in %d runs\n", *startQuorum, *endQuorum, *runs)
	fmt.Printf("Max go procs (threads): %d\n", *procs)
	if *msgLatency == 0 {
		fmt.Println("No network latency.")
	} else {
		fmt.Println("Network latency per message:", *msgLatency, "ms.")
	}
	fmt.Println("-----------------------------------")

	runtime.GOMAXPROCS(*procs)
	results := make([][]result, 0, *runs)
	for run := 0; run < *runs; run++ {
		fmt.Printf("Signing run %d... \n", run+1)
		results = append(results, make([]result, 0, *endQuorum))
		for q := *startQuorum; q <= *endQuorum; q++ {
			fmt.Printf("  Quorum %d... ", q)
			start := time.Now()
			runSign(dir, q-1, *msgLatency)
			elapsed := time.Since(start)
			results[run] = append(results[run], result{
				quorum:   q,
				duration: elapsed,
			})
			_, _ = prt.Printf("%d ms.\n", elapsed.Milliseconds())
		}
	}

	fmt.Println("Results summary:")
	printSummary(results)
	os.Exit(0)
}

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
}

func runSign(dir string, t, msgLatency int) {
	setUp(libLogLevel)

	q := t + 1
	minMsgLatency, maxMsgLatency := msgLatency/2, 3*(msgLatency)/2
	keys, signPIDs, err := loadKeyGenData(dir, q)
	if err != nil {
		panic(err)
	}
	if len(keys) != q || len(signPIDs) != q {
		panic(fmt.Errorf("wanted %d keys but got %d keys and %d signPIDs", q, len(keys), len(signPIDs)))
	}

	msg := common.GetRandomPrimeInt(256)
	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*signing.LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.EC(), p2pCtx, signPIDs[i], len(signPIDs), t)
		P := signing.NewLocalParty(msg, params, keys[i], big.NewInt(0), outCh, endCh).(*signing.LocalParty)
		parties = append(parties, P)
		go func(P *signing.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
outer:
	for {
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			panic(err)

		case msg := <-outCh:
			dest := msg.GetTo()
			if msgLatency > 0 {
				delay(minMsgLatency, maxMsgLatency)
			}
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					panic(fmt.Errorf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index))
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case data := <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				// BEGIN ECDSA verify
				pkX, pkY := keys[0].ECDSAPub.X(), keys[0].ECDSAPub.Y()
				pk := ecdsa.PublicKey{
					Curve: tss.EC(),
					X:     pkX,
					Y:     pkY,
				}

				r := new(big.Int).SetBytes(data.R)
				s := new(big.Int).SetBytes(data.S)
				var ok bool
				if ok = ecdsa.Verify(
					&pk,
					msg.Bytes(),
					r, s,
				); !ok {
					panic("ECDSA signature verification did not pass")
				}
				btcecSig := &btcec.Signature{R: r, S: s}
				if ok = btcecSig.Verify(msg.Bytes(), (*btcec.PublicKey)(&pk)); !ok {
					panic("ECDSA signature verification 2 did not pass")
				}
				break outer
			}
		}
	}
}

func delay(minD, maxD int) {
	time.Sleep(time.Duration(rand.Intn(maxD-minD)+minD) * time.Millisecond)
}

func printSummary(results [][]result) {
	prt := message.NewPrinter(language.English)
	table := tablewriter.NewWriter(os.Stdout)
	header := []string{"Quorum"}
	for run := range results {
		header = append(header, fmt.Sprintf("Run %d", run+1))
	}
	header = append(header, "Mean")
	table.SetHeader(header)
	rows := make([][]string, 0, len(results[0]))
	for q, result := range results[0] {
		row := []string{
			prt.Sprintf("%d", result.quorum),
		}
		var avgDurationMS int64
		for run := range results {
			durationMS := results[run][q].duration.Milliseconds()
			str := prt.Sprintf("%d ms", durationMS)
			row = append(row, str)
			avgDurationMS += durationMS
		}
		avgDurationMS /= int64(len(results))
		row = append(row, prt.Sprintf("%d ms", avgDurationMS))
		rows = append(rows, row)
	}
	table.SetBorders(tablewriter.Border{Left: true, Top: true, Right: true, Bottom: true})
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("|")
	table.AppendBulk(rows)
	table.Render()
}

// ----- //

func loadKeyGenData(dir string, qty int, optionalStart ...int) ([]keygen.LocalPartySaveData, tss.SortedPartyIDs, error) {
	keys := make([]keygen.LocalPartySaveData, 0, qty)
	start := 0
	if 0 < len(optionalStart) {
		start = optionalStart[0]
	}
	for i := start; i < qty; i++ {
		fixtureFilePath := makeKeyGenDataFilePath(dir, i)
		bz, err := ioutil.ReadFile(fixtureFilePath)
		if err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not open the test fixture for party %d in the expected location: %s. run keygen tests first.",
				i, fixtureFilePath)
		}
		var key keygen.LocalPartySaveData
		if err = json.Unmarshal(bz, &key); err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not unmarshal fixture data for party %d located at: %s",
				i, fixtureFilePath)
		}
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

func makeKeyGenDataFilePath(dir string, partyIndex int) string {
	return fmt.Sprintf("%s/keygen_data_%d.json", dir, partyIndex)
}
