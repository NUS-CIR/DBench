package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Normal case

/*
const (
	IP_EXT = "192.168.1.9"
	IP_UE  = "192.168.1.3"
)
*/

// Eval 1

const (
	IP_EXT = "192.168.1.9"
	IP_UE  = "192.168.69.195"
)

type PacketInfo struct {
	TimestampMS float64
	RawPacket   []byte
}

func readCandidateTimestamps(filePath string) ([]float64, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	var timestamps []float64

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		timestamp, err := strconv.ParseFloat(record[0], 64)
		if err != nil {
			return nil, err
		}
		timestamps = append(timestamps, timestamp)
	}

	return timestamps, nil
}

func readAndFilterPackets(pcapFile string, filterRequest bool, filterResponse bool, findRU bool) ([]PacketInfo, error) {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	var packets []PacketInfo

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if findRU {
			if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
				icmp, _ := icmpLayer.(*layers.ICMPv4)
				if (filterRequest && icmp.TypeCode.Type() == layers.ICMPv4TypeEchoRequest) ||
					(filterResponse && icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply) ||
					(!filterRequest && !filterResponse) {
					timestampMS := float64(packet.Metadata().Timestamp.UnixNano() / 1e6)
					packets = append(packets, PacketInfo{
						TimestampMS: timestampMS,
						RawPacket:   packet.Data(),
					})
				}
			}
		} else {
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				if (filterRequest && ip.SrcIP.String() == IP_UE && ip.DstIP.String() == IP_EXT) ||
					(filterResponse && ip.SrcIP.String() == IP_EXT && ip.DstIP.String() == IP_UE) {
					timestampMS := float64(packet.Metadata().Timestamp.UnixNano() / 1e6)
					packets = append(packets, PacketInfo{
						TimestampMS: timestampMS,
						RawPacket:   packet.Data(),
					})
				}
			}
		}
	}
	fmt.Println("Number of packets:", len(packets))

	return packets, nil
}

func findClosestTimestamp(candidate float64, packets []PacketInfo, findSmaller bool) (float64, bool) {
	closest := float64(0)
	found := false

	for _, packet := range packets {
		if findSmaller {
			if packet.TimestampMS < candidate && (!found || packet.TimestampMS > closest) {
				closest = packet.TimestampMS
				found = true
			}
		} else {
			if packet.TimestampMS > candidate && (!found || packet.TimestampMS < closest) {
				closest = packet.TimestampMS
				found = true
			}
		}
	}

	return closest, found
}

func main() {
	pcapFile := flag.String("pcap", "file.pcap", "Path to the pcap file")
	csvFile := flag.String("csv", "../../data/candidate/candidate.csv", "Path to the CSV file with candidate timestamps")
	filterRequest := flag.Bool("request", false, "Filter only ICMP requests")
	filterResponse := flag.Bool("response", false, "Filter only ICMP responses")
	findSmaller := flag.Bool("smaller", false, "Find the closest smaller timestamp (default expect bigger tstamp at UE)")
	rangeMin := flag.Float64("range_min", 0, "Minimum range in milliseconds")
	rangeMax := flag.Float64("range_max", 1000, "Maximum range in milliseconds")
	findRU := flag.Bool("find_ru", false, "Find RU processing delay")
	outputloc := flag.String("outputLoc", "result.csv", "Path and filename to store the output csv file")

	flag.Parse()

	candidateTimestamps, err := readCandidateTimestamps(*csvFile)
	if err != nil {
		fmt.Printf("Error reading candidate timestamps: %v\n", err)
		return
	}

	packets, err := readAndFilterPackets(*pcapFile, *filterRequest, *filterResponse, *findRU)
	if err != nil {
		fmt.Printf("Error reading pcap file: %v\n", err)
		return
	}

	var results []float64

	for _, candidate := range candidateTimestamps {
		closestTimestamp, found := findClosestTimestamp(candidate, packets, *findSmaller)
		if found {
			diff := math.Abs(closestTimestamp - candidate)
			if diff >= *rangeMin && diff <= *rangeMax {
				results = append(results, diff)
			}
		}
	}

	sort.Float64s(results)

	fmt.Println("Differences within range:")
	// Calculate percentiles
	if len(results) > 0 {
		p25 := percentile(results, 25)
		p50 := percentile(results, 50)
		p75 := percentile(results, 75)

		fmt.Println("Percentiles:")
		fmt.Printf("25th Percentile: %.2f\n", p25)
		fmt.Printf("50th Percentile: %.2f\n", p50)
		fmt.Printf("75th Percentile: %.2f\n", p75)
	} else {
		fmt.Println("No results within the specified range.")
	}

	// Save results to a CSV file
	file, err := os.Create(*outputloc)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	for _, value := range results {
		err := writer.Write([]string{strconv.FormatFloat(value, 'f', -1, 64)})
		if err != nil {
			fmt.Println("Error writing to file:", err)
			return
		}
	}
	fmt.Println("Results saved to", *outputloc)

}

// Function to calculate the percentile
func percentile(data []float64, p float64) float64 {
	k := (p / 100) * float64(len(data)-1)
	f := math.Floor(k)
	c := math.Ceil(k)

	if f == c {
		return data[int(k)]
	}

	d0 := data[int(f)] * (c - k)
	d1 := data[int(c)] * (k - f)
	return d0 + d1
}
