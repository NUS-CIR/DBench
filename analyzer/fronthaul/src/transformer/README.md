Transform PRBs into bitmaps 
===

This tool analyzes fronthaul traffic captured at the Radio Unit (RU) and identifies packets with non-zero Physical Resource Blocks (PRBs), which likely contain data traffic.
If the PRB contains non-zero value, we mark the corresponding bit in the bitmap, hinting that there can be data traffic within this PRB.

Normally, we can simply use the `prb_bitmap.go` to do the transformation. However, another python script is required to adapt to different data nature.
Since PRB frames may wrap around due to indexing limits, `split.py` is provided to split and sort the data.

## Quick Start

### Installation

Ensure the following dependencies are installed.

#### Go Dependencies

```sh
go get github.com/google/gopacket
go get github.com/google/gopacket/pcap
```

#### Python Dependencies

Ensure Python 3 is installed. 

## Usage

1. **Extract PRB Data**: Run the Go script to extract non-zero PRB packets from the .pcap file:  

    ```sh
    go run prb_bitmap.go
    ```

    > TODO: Enable specify input file in arguments, while now it is inline

    **Output**:  
    This script generates `frame_[XX].csv` containing the extracted PRB data in `../../data/eval1/prb_bitmaps/`


2. **Handle Frame Wrap-Arounds**: To sort PRB data across multiple frame cycles, use the Python script:  
*This is a mandatory step now as we haved a fixed naming convention for process pipeline*

    ```sh
    python3 split.py
    ```

    **Output**:  
    This script generates `[frame number]_[iteration idx].csv` containing the extracted PRB data in `../../data/eval1/prb_bitmaps/split/`
