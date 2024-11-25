package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	prbSize            = 27
	RUPort             = 0
	iqsampleHeaderSize = 1
	batchSize          = 1000 // Batch size constant
)

type PacketInfo struct {
	index         int
	frameID       uint8
	subframeID    uint16
	slotID        uint16
	startSymbolID uint16
	bitmap        []bool
	timestamp     time.Time
}

func extractPRBs(packet []byte, startIndex int) [][]byte {
	prbs := [][]byte{}
	offset := startIndex
	for offset+iqsampleHeaderSize+prbSize <= len(packet) {
		prbs = append(prbs, packet[offset+iqsampleHeaderSize:offset+iqsampleHeaderSize+prbSize])
		offset += (prbSize + iqsampleHeaderSize)
	}
	return prbs
}

func hasNonZeroPRB(prbs [][]byte) bool {
	for _, prb := range prbs {
		for _, b := range prb {
			if b != 0 {
				return true
			}
		}
	}
	return false
}

func extractTimingInfo(packet []byte) (uint8, uint16, uint16, uint16, error) {
	if len(packet) < 30 {
		return 0, 0, 0, 0, fmt.Errorf("packet too short to extract timing info")
	}
	frameID := packet[27]
	combined := (uint16(packet[28]) << 8) | uint16(packet[29])
	subframeID := (combined & 0xF000) >> 12
	slotID := (combined & 0x03F0) >> 6
	startSymbolID := combined & 0x003F
	return frameID, subframeID, slotID, startSymbolID, nil
}

func prbsToBitmap(prbs [][]byte) []bool {
	bitmap := make([]bool, len(prbs))
	for i, prb := range prbs {
		bitmap[i] = hasNonZeroPRB([][]byte{prb})
	}
	return bitmap
}

func parsePacket(index int, packet gopacket.Packet, wg *sync.WaitGroup, results chan<- PacketInfo) {
	defer wg.Done()
	rawPacket := packet.Data()

	// Ensure the packet is long enough to contain the eCPRI Message Type field
	if len(rawPacket) < 20 {
		fmt.Printf("Packet index: %d too short to contain eCPRI Message Type\n", index)
		return
	}

	// Check the RU_port field
	if rawPacket[23] != RUPort {
		return
	}

	// Get the eCPRI Message Type from the 19th byte
	eCPRIMessageType := rawPacket[19]
	if eCPRIMessageType != 0 {
		return
	}

	prbs := extractPRBs(rawPacket, 34)
	frameID, subframeID, slotID, startSymbolID, err := extractTimingInfo(rawPacket)
	if err != nil {
		fmt.Printf("Error extracting timing info: %v\n", err)
		return
	}
	bitmap := prbsToBitmap(prbs)
	results <- PacketInfo{
		index:         index,
		frameID:       frameID,
		subframeID:    subframeID,
		slotID:        slotID,
		startSymbolID: startSymbolID,
		bitmap:        bitmap,
		timestamp:     packet.Metadata().Timestamp,
	}
}

func main() {
	handle, err := pcap.OpenOffline("../../data/eval1/oai/ru.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	var wg sync.WaitGroup
	results := make(chan PacketInfo, 100)

	packetLookupTable := make(map[uint8][]PacketInfo)
	totalPackets := 0

	// Goroutine to parse results
	go func() {
		for result := range results {
			totalPackets++
			packetLookupTable[result.frameID] = append(packetLookupTable[result.frameID], result)
		}
	}()

	index := 0
	batch := make([]gopacket.Packet, 0, batchSize)

	for packet := range packetChan {
		batch = append(batch, packet)
		index++
		if len(batch) >= batchSize {
			wg.Add(len(batch))
			for i, pkt := range batch {
				go parsePacket(index-batchSize+i, pkt, &wg, results)
			}
			wg.Wait()
			batch = batch[:0]
		}

	}

	// Process any remaining packets in the batch
	if len(batch) > 0 {
		wg.Add(len(batch))
		for i, pkt := range batch {
			go parsePacket(index-len(batch)+i, pkt, &wg, results)
		}
		wg.Wait()
	}

	close(results)

	// Sort and write to files
	for frameID, packets := range packetLookupTable {
		sort.SliceStable(packets, func(i, j int) bool {
			if packets[i].subframeID != packets[j].subframeID {
				return packets[i].subframeID < packets[j].subframeID
			}
			if packets[i].slotID != packets[j].slotID {
				return packets[i].slotID < packets[j].slotID
			}
			return packets[i].startSymbolID < packets[j].startSymbolID
		})

		fileName := fmt.Sprintf("../../data/prb_bitmaps/frame_%d.csv", frameID)
		file, err := os.Create(fileName)
		if err != nil {
			log.Fatal("Cannot create file", err)
		}
		defer file.Close()

		writer := csv.NewWriter(file)
		defer writer.Flush()

		writer.Write([]string{"Frame", "Subframe", "Slot", "StartSymbol", "Bitmap", "Timestamp(ms)"})
		for _, packet := range packets {
			bitmapStr := ""
			for _, bit := range packet.bitmap {
				if bit {
					bitmapStr += "1"
				} else {
					bitmapStr += "0"
				}
			}
			writer.Write([]string{
				fmt.Sprintf("%d", packet.frameID),
				fmt.Sprintf("%d", packet.subframeID),
				fmt.Sprintf("%d", packet.slotID),
				fmt.Sprintf("%d", packet.startSymbolID),
				bitmapStr,
				fmt.Sprintf("%.6f", float64(packet.timestamp.UnixNano())/1e6),
			})
		}
	}

	fmt.Printf("Total packets processed: %d\n", totalPackets)
}
