# Latency Validation Module

The `latency_validation` module is designed to validate and compare the PRB candidates identified by the `inspector` module with other pcap files. This helps in determining the processing latency of different components in the network.

## Overview

This module takes the output from the `inspector` module, which lists the candidates for PRBs carrying user data, and compares/validates those candidates with other pcap files. Depending on the type of processing latency you want to measure, you need to attach the corresponding pcap as a reference.

## Quick Start

### Installation

Ensure the following dependencies are installed:

#### Go Dependencies

```sh
go get github.com/google/gopacket
go get github.com/google/gopacket/pcap
```

### Usage

1. Run the Inspector: Ensure you have run the inspector module to produce the list of PRB candidates.
2. Run the Latency Validation: Execute the match.go script to compare the PRB candidates with the reference pcap file:

    ```sh
    cd extractor
    go run timestamp.go -pcap ../../data/eval1/oai/ue.pcap -response -find_ru
    ```

    **Output**:
    This script generates latency measurements based on the comparison of PRB candidates and the reference pcap file, output as a file `result.csv`.

### Notes
- If you want to get RU delay:
  - Uplink data:
  ```sh
  go run timestamp.go -pcap ../../data/eval1/oai/ue.pcap -request -smaller -find_ru
  ```
  - Downlink data:
  ```sh
  go run timestamp.go -pcap ../../data/eval1/oai/ue.pcap -response -find_ru
  ```
- If you want DU delay instead:
  - Uplink data:
  ```sh
  go run timestamp.go -pcap ../../data/eval1/oai/sw.pcap -request
  ```
  - Downlink data:
  ```sh
  go run timestamp.go -pcap ../../data/eval1/oai/sw.pcap -response -smaller
  ```

#### Details
- The script reads the PRB candidate list from the inspector module output.
- It compares the PRB candidates with the reference pcap file to find the closest user traffic within a specified time range.
- The time difference between the matched packets is used to calculate the desired latency (time unit in **milli-second**).