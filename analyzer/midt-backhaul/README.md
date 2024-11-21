# OAI Custom Script

The `oai-custom.py` script is designed to analyze and process 5G protocol data, specifically focusing on GTP control messages (GTP-C) and GTP user data messages (GTP-U). It includes functionalities for plotting and analyzing network traffic data.

There is a need to separate the pcap parsing functionality for different 5G stacks like OAI and SRS. The thing is, these 5G stacks each support different 5G structures. For examples, as we already configured now, with the usage of CU split, the endpoint responsible for each part of the transmission is under lots of changes given different 5G configuration. In order to easily separate these usage available on different stack, here we simply craft scripts tailored to each stack's functionality.

## Overview

This script processes network traffic data captured in pcap files, extracts relevant information, and generates plots to visualize the data. It uses various libraries such as `scapy` for packet processing and `matplotlib` for plotting.

## Quick Start

### Installation

Ensure the following dependencies are installed:

#### Python Dependencies

```sh
pip install scapy matplotlib numpy
```

### Usage
To run the script, simply use the following command:

```sh
python3 oai-custom.py
```

or 
```sh
python3 srs-custom.py
```

### Details
- The script processes network traffic data captured in pcap files.
- It extracts information related to GTP control messages (GTP-C) and GTP user data messages (GTP-U).
- The script generates plots to visualize the extracted data.

### Constants
The script uses the following constants for 5G protocols:

- GTP-C (UDP Port 2153)
- GTP-U (UDP Port 2152)

#### IP Addresses
CU: 192.168.1.3
CUUP: 192.168.69.195
DU: 192.168.1.9
UPF: 192.168.70.134
EXT: 192.168.1.5
CORE: 192.168.1.2

#### Default Values
Bucket Size: 30000
- OAI
    UE IP: 12.1.1.161
- SRS
    UE IP: 12.1.1.11