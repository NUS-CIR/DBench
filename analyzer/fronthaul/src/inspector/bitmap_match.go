package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type StackPlatform string

const (
	SRS_Eval1 = "srs_eval1"
	OAI_Eval1 = "oai_eval1"
	SRS_Eval3 = "srs_eval3"
	OAI_Eval3 = "oai_eval3"
)

const (
	K              = 20
	symbolPerFrame = 280
	prbPerSymbol   = 273
	platform       = OAI_Eval3
)

type Entry struct {
	diffRate      float64
	filename      string
	frameRound    int
	frameID       string
	subframeID    string
	slotID        string
	startSymbolID string
	timestamp     string
}

func loadFile(filename string) ([][]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	var data [][]string
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		data = append(data, record)
	}
	return data, nil
}

func bitDiff(a, b string) int {
	if len(a) != len(b) {
		fmt.Printf("Warning: Bitmap lengths differ - %d vs %d\n", len(a), len(b))
		return -1
	}
	diff := 0
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			diff++
		}
	}
	return diff
}

func processFile(filename string, template [][]string) (float64, string, string, string, string, string) {
	data, err := loadFile(filename)
	if err != nil {
		fmt.Println(err)
		return 0.0, "", "", "", "", ""
	}

	maxDiff, totalDiff := 0, 0
	var lastFrame, lastSubframe, lastSlot, lastSymbol string
	var maxDiffFrameID, maxDiffSubframeID, maxDiffSlotID, maxDiffStartSymbolID string
	var maxDiffTimestamp string
	// idx 0: previous, idx 1: current
	isFirstSymbolNonZero := [2]bool{true, true}
	firstSymbolTimestamp := [2]string{"", ""}

	uplinkSlotIDs := map[[2]string]struct{}{
		{"2", "0"}: {},
		{"4", "1"}: {},
		{"7", "0"}: {},
		{"9", "1"}: {},
	}

	for _, row := range data[1:] {
		frame := row[0]
		subframe := row[1]
		slot := row[2]
		startSymbol := row[3]
		bitmap := row[4]
		timestamp := row[5]

		// ignore uplink slots, which are SF(subframe) 2:S (slot) 0, SF 4:S 1, SF 7:S 0, SF 9:S 1
		if _, skip := uplinkSlotIDs[[2]string{subframe, slot}]; skip {
			continue
		}

		if startSymbol == "0" {
			firstSymbolTimestamp[0] = firstSymbolTimestamp[1]
			if strings.Contains(bitmap, "1") {
				isFirstSymbolNonZero[1] = true
			} else {
				isFirstSymbolNonZero[1] = false
			}
			firstSymbolTimestamp[1] = timestamp
		}

		var templateRow []string
		for _, tRow := range template[1:] {
			if subframe == tRow[1] && slot == tRow[2] && startSymbol == tRow[3] {
				templateRow = tRow
				break
			}
		}

		if len(templateRow) == 0 {
			fmt.Printf("No matching template row for input row in file %s\n", filename)
			continue
		}
		bitDiff := bitDiff(bitmap, templateRow[4])
		if bitDiff < 0 {
			fmt.Printf("Warning: %s - Row contains invalid bitmap value(s)\n", filename)
			return 0.0, "", "", "", "", ""
		}
		if lastSubframe == "" && lastSlot == "" {
			lastFrame, lastSubframe, lastSlot, lastSymbol = frame, subframe, slot, startSymbol
			totalDiff += bitDiff
		} else {
			if subframe == lastSubframe && slot == lastSlot {
				totalDiff += bitDiff
			} else {
				if totalDiff > maxDiff && isFirstSymbolNonZero[0] {
					maxDiffFrameID, maxDiffSubframeID, maxDiffSlotID, maxDiffStartSymbolID = lastFrame, lastSubframe, lastSlot, lastSymbol
					maxDiff = totalDiff
					maxDiffTimestamp = firstSymbolTimestamp[0]
				}
				lastFrame, lastSubframe, lastSlot, lastSymbol = frame, subframe, slot, startSymbol
				totalDiff = bitDiff
				// update isFirstSymbolNonZero to the current slot
				isFirstSymbolNonZero[0] = isFirstSymbolNonZero[1]
			}
		}
		totalDiff += bitDiff
	}

	return float64(maxDiff), maxDiffFrameID, maxDiffSubframeID, maxDiffSlotID, maxDiffStartSymbolID, maxDiffTimestamp
}

func processFiles(files []string, templateEven [][]string, templateOdd [][]string, wg *sync.WaitGroup, ch chan Entry) {
	defer wg.Done()

	for _, filename := range files {
		frameNumber, _ := strconv.Atoi(strings.Split(strings.Split(filename, "_")[1], ".")[0])
		frameRound, _ := strconv.Atoi(strings.Split(strings.Split(filename, "_")[2], ".")[0])
		var template [][]string
		if frameNumber%2 == 0 {
			template = templateEven
		} else {
			template = templateOdd
		}
		diffRate, frameID, subframeID, slotID, startSymbolID, timestamp := processFile(filename, template)
		ch <- Entry{diffRate, filename, frameRound, frameID, subframeID, slotID, startSymbolID, timestamp}
	}
}

func insertTopK(entries []Entry, newEntry Entry) []Entry {
	if len(entries) < K {
		entries = append(entries, newEntry)
	} else {
		// Ensure entries are sorted in descending order by diffRate
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].diffRate > entries[j].diffRate
		})
		if newEntry.diffRate > entries[K-1].diffRate {
			entries[K-1] = newEntry
		}
	}
	return entries
}

func main() {
	var templateEven [][]string
	var err error
	var fname string

	fname = "../../data/template/" + platform + "/frame_even.csv"

	templateEven, err = loadFile(fname)
	if err != nil {
		fmt.Println(err)
		return
	}

	fname = "../../data/template/" + platform + "/frame_odd.csv"

	var templateOdd [][]string

	templateOdd, err = loadFile(fname)
	if err != nil {
		fmt.Println(err)
		return
	}

	var csvFiles []string
	err = filepath.Walk("../../data/prb_bitmaps/split", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(info.Name(), ".csv") {
			csvFiles = append(csvFiles, path)
		}
		return nil
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	ch := make(chan Entry, len(csvFiles))
	var wg sync.WaitGroup

	for i := 0; i < len(csvFiles); i += 10 {
		end := i + 10
		if end > len(csvFiles) {
			end = len(csvFiles)
		}
		wg.Add(1)
		go processFiles(csvFiles[i:end], templateEven, templateOdd, &wg, ch)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	var topDiffEntries []Entry

	for entry := range ch {
		topDiffEntries = insertTopK(topDiffEntries, entry)
	}

	// Ensure entries are sorted in descending order by diffRate
	sort.Slice(topDiffEntries, func(i, j int) bool {
		return topDiffEntries[i].diffRate > topDiffEntries[j].diffRate
	})

	var timestamps []string
	for _, entry := range topDiffEntries {
		timestamps = append(timestamps, entry.timestamp)
		fmt.Printf("File: %s, Diff Rate: %f, Frame Round: %d, Frame ID: %s, Subframe ID: %s, Slot ID: %s, Symbol ID: %s, Timestamp: %s\n", entry.filename, entry.diffRate, entry.frameRound, entry.frameID, entry.subframeID, entry.slotID, entry.startSymbolID, entry.timestamp)
	}

	file, err := os.Create("../../data/candidate/candidate.csv")
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	for _, ts := range timestamps {
		err := writer.Write([]string{ts})
		if err != nil {
			fmt.Println("Error writing to CSV:", err)
			return
		}
	}
}
