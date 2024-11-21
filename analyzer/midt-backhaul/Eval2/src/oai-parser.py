# This is a spin-off from gtp-ogre, it aims to provide more resilient from interference from different pcaps
# We only combine necessary pcaps to refer different fields, mainly because some file corrupts the pattern under certain conditions
# For example, for ping size larger than 256B, the CU pcap start to corrupt the UPF pattern.
# As for performance optimization, it could also benefit since we are now using only smaller pcaps at a time
# Example usage: python3 gcustoms.py 600 ../data/default/data.pcap ../image/eval_result/default/ 12.1.1.2

import argparse
import csv
import ipaddress
import logging
import math
import os
import subprocess
import glob
import pickle
import binascii

from scapy.all import *

from Crypto.Cipher import AES
from matplotlib import pyplot as plt
import numpy as np

# constants for 5G protocols
## GTP control messages (GTP-C) 
UDP_PORT_F1 = 2153
## GTP user data messages (GTP-U) 
UDP_PORT_N3 = 2152

# IP_ADDR_CU = "192.168.69.195"
IP_ADDR_CU_UL = "192.168.1.3"      #192.168.1.3
IP_ADDR_CU_DL = "192.168.69.195"   #192.168.69.195
# IP_ADDR_CU = "192.168.1.3"
IP_ADDR_DU = "192.168.1.6"         #192.168.1.6
IP_ADDR_UPF = "192.168.70.134"
IP_ADDR_EXT = "192.168.1.5"
IP_ADDR_CORE = "192.168.1.2"

DEFAULT_BUCKET_SIZE = 2000
DEFAULT_UE_IP = "12.1.1.33"

AES_KEY_HEX = "a6ab60d579927949ae59299b4b948f98"

# =====================
# |     Plotting      |
# =====================


def dist_draw(statistics: list, title_name: str, file_loc: str):
    # i hate python, or numpy to be specific
    # for some reason, np thinks my data is not coherant with types
    # so here goes hacky type transformation
    dec_data = [float(Decimal(d)) for d in statistics]
    # show the 50 & 99 percentile val
    p50 = np.percentile(dec_data, 50)
    p99 = np.percentile(dec_data, 99)

    if (p99 <= 0):
        logging.error("P99 in " + title_name + " leq than 0, skipped!")
        return -1

    bins = np.linspace(0, float(p99) * 1.2 , 100)
    hist, bins = np.histogram(statistics, bins=bins, density=True)
    bins_centers = 0.5*(bins[1:] + bins[:-1])
    pdf = hist / sum(hist)
    cdf = np.cumsum(pdf)

    f = plt.figure()
    plt.title(title_name)
    plt.plot(bins_centers, pdf, label="PDF", alpha=0.6)
    plt.plot(bins_centers, cdf, label="CDF", alpha=0.6)
    plt.xlabel("Latencies (ms)")
    plt.grid(True, linestyle='--')

    plt.annotate(f'P50: {p50:.2f}', xy=(p50, 0.5), xytext=(p50, 0.3),
    arrowprops=dict(facecolor='black', arrowstyle='->'))
    plt.annotate(f'P99: {p99:.2f}', xy=(p99, 0.97), xytext=(p99, 0.75),
    arrowprops=dict(facecolor='black', arrowstyle='->'))
    plt.legend()

    plt.tight_layout()
    f.savefig(file_loc)
    plt.clf()

    return 0

# =====================
# | Packet Processing |
# =====================

def to_byte_array(pkt):
    return bytearray(bytes(pkt))

def decipher_pdcp(gtp_count: bytearray, gtp_payload: bytearray, direction: bool) -> bytearray:
    key = binascii.unhexlify(AES_KEY_HEX)
    assert len(key) == 16
    iv = bytearray(8)
    iv[2] = gtp_count[0]
    iv[3] = gtp_count[1]
    iv[4] = int(direction) * 4
    cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
    decrypted_data = cipher.decrypt(gtp_payload)
    return decrypted_data

# GTP parsing from Khooi
# Return ICMP seq (if any)
# If not, return 0
def parse_gtp(pkt, udp_port: int):
    gtp_header_size = 0
    # GTP protocols should be either one
    if (udp_port == UDP_PORT_F1):
        gtp_header_size = 11
    elif (udp_port == UDP_PORT_N3):
        gtp_header_size = 16
    else:
        return 0
    udp_payload = pkt.getlayer("UDP").payload
    udp_payload_bytearr = to_byte_array(udp_payload)
    gtp_payload = udp_payload_bytearr[gtp_header_size:]
    
    # Get the 2-byte count which is part of the cipher iv
    gtp_count = udp_payload_bytearr[gtp_header_size-2:gtp_header_size]
    # Only decrypt packets from DU to CU (uplink) or from CU to DU (downlink)
    sip = pkt[IP].src
    dip = pkt[IP].dst
    if (sip == IP_ADDR_DU and dip == IP_ADDR_CU_DL):
        direction = 0     # uplink
        gtp_payload = decipher_pdcp(gtp_count, gtp_payload, direction)
    elif (sip == IP_ADDR_CU_DL and dip == IP_ADDR_DU):
        direction = 1     # downlink
        gtp_payload = decipher_pdcp(gtp_count, gtp_payload, direction)
    ip_pkt = IP(bytes(gtp_payload))

    # Append the ip_pkt to the PCAP file
    # pcap_writer.write(ip_pkt)

    if IP in ip_pkt:
        if ICMP in ip_pkt:
            if (ip_pkt[ICMP].seq is not None):
                return ip_pkt[ICMP].seq
            else:
                return 0
        elif TCP in ip_pkt:
            payload = bytes(ip_pkt[TCP].payload)
            if (payload is not None):
                return int.from_bytes(payload[8:16], "big")
            else:
                return 0
        else:
            return 0
    else:
        return 0


def main(bucket_size: int, input_loc: str, output_loc: str, ue_ip: str, enable_plot: bool):
    # Data preparation
    UE_FNAME = "ue.pcap"
    SW_FNAME = "sw.pcap"

    # UE - DU - CU - UPF - EXT - UPF - CU - DU - UE
    # --(0)--(1)--(2)---(3)---(4)---(5)--(6)--(7)--
    buckets = [[0 for x in range(8)] for y in range(bucket_size)]
    # pcap_writer = PcapWriter('ip_pkt.pcap', append=True, sync=True)

    # First fill in the core part
    with PcapReader(input_loc+UE_FNAME) as pcap_reader:
        for i, packet in enumerate(pcap_reader):
            try:
                if (IP in packet):
                    sip = packet[IP].src
                    dip = packet[IP].dst
                    if (ICMP in packet):
                        idx = packet[ICMP].seq - 1
                        if (idx > bucket_size):
                            logging.debug("ICMP seq " + str(idx) + " greater than bucket size " + str(bucket_size))
                            continue
                        if (sip == ue_ip and dip == IP_ADDR_EXT):
                            if (buckets[idx][0] == 0):
                                buckets[idx][0] = packet.time * 1000
                        elif (sip == IP_ADDR_EXT and dip == ue_ip):
                            if (buckets[idx][7] == 0):
                                buckets[idx][7] = packet.time * 1000
                        else:
                            logging.debug("ICMP in core with random SIP: " + sip + ", DIP: " + dip)
                    elif (TCP in packet):
                        payload = bytes(pkt[TCP].payload)
                        if (payload is not None):
                            seq = int.from_bytes(payload[8:16], "big")
                            if (seq > bucket_size):
                                logging.debug("ICMP seq " + str(seq) + " greater than bucket size " + str(bucket_size))
                                continue
                            if (sip == ue_ip and dip == IP_ADDR_EXT):
                                if (buckets[idx][0] == 0):
                                    buckets[idx][0] = packet.time * 1000
                            elif (sip == IP_ADDR_EXT and dip == ue_ip):
                                if (buckets[idx][7] == 0):
                                    buckets[idx][7] = packet.time * 1000
                            
            except Exception as e:
                logging.error("Throw exception during parsing at i = " + str(i) +" core pcap!")
                break

    # Then fill in the gnb part
    with PcapReader(input_loc+SW_FNAME) as pcap_reader:
        for i, packet in enumerate(pcap_reader):
            try:
                if (IP in packet):
                    sip = packet[IP].src
                    dip = packet[IP].dst
                    if (UDP in packet):
                        sport = packet[UDP].sport
                        dport = packet[UDP].dport
                        if (sport == dport):
                            if (sport == UDP_PORT_N3 or sport == UDP_PORT_F1):
                                seq = parse_gtp(packet, sport)
                                if (seq > bucket_size):
                                    logging.debug("ICMP seq " + str(seq) + " greater than bucket size " + str(bucket_size))
                                    continue
                                elif (seq <= 0):
                                    logging.debug(f"Cannot find ICMP seq in GTP packets within gnb!: seq: {seq}")
                                    continue
                                else:
                                    idx = seq - 1
                                    if (sip == IP_ADDR_DU and dip == IP_ADDR_CU_DL):
                                        if (buckets[idx][1] == 0):
                                            buckets[idx][1] = packet.time * 1000
                                    elif (sip == IP_ADDR_CU_UL and dip == IP_ADDR_UPF):
                                        if (buckets[idx][2] == 0):
                                            buckets[idx][2] = packet.time * 1000
                                    elif (sip == IP_ADDR_CORE and dip == IP_ADDR_CU_DL):
                                        if (buckets[idx][5] == 0):
                                            buckets[idx][5] = packet.time * 1000
                                    elif (sip == IP_ADDR_CU_DL and dip == IP_ADDR_DU):
                                        if (buckets[idx][6] == 0):
                                            buckets[idx][6] = packet.time * 1000                          
                                    else:
                                        logging.debug("GTP in gnb with random SIP: " + sip + ", DIP: " + dip)

                    elif (ICMP in packet):
                        idx = packet[ICMP].seq - 1
                        if (sip == IP_ADDR_CORE and dip == IP_ADDR_EXT):
                            if (buckets[idx][3] == 0):
                                buckets[idx][3] = packet.time * 1000
                        elif (sip == IP_ADDR_EXT and dip == IP_ADDR_CORE):
                            if (buckets[idx][4] == 0):
                                buckets[idx][4] = packet.time * 1000
                        else:
                            logging.debug("ICMP in gnb with random SIP: " + sip + ", DIP: " + dip)
            except Exception as e:
                logging.error("Throw exception during parsing at i = " + str(i) + " gnb pcap!")
                print(e)
                break

    # pcap_writer.close()

    # If it somehow manages survives the massive pcap attack, first congratulations
    # Then we got the processing time at each hop
    # ul_du[0], ul_cu[1], ul_upf[2], ext[3], dl_upf[4], dl_cu[5], dl_du[6]
    process_times = [[] for i in range(7)]
    ## Also do a quality check on the results
    sample_size = 0
    empty_sample_rate = [0 for i in range(7)]
    bad_sample_rate = [0 for i in range(7)]

    for i, bucket in enumerate(buckets):
        is_filled = False
        for idx in range(len(bucket) - 1):              
            if ((bucket[idx] != 0) and (bucket[idx + 1] != 0)):
                is_filled = True                   
                if (bucket[idx + 1] > bucket[idx]):
                    process_times[idx].append(bucket[idx + 1] - bucket[idx])
                else:
                    bad_sample_rate[idx] += 1
            elif ((bucket[idx] != 0) or (bucket[idx + 1] != 0)):
                is_filled = True
                empty_sample_rate[idx] += 1
        if (is_filled):
            sample_size += 1

    # Finally, let's end with some sanity check
    # Provide some useful statics, like the average processing of each component
    avg_process_times = [0 for i in range(7)]
    for idx, process_time in enumerate(process_times):
        if (len(process_time) > 0):
            avg_process_times[idx] = sum(process_time) / len(process_time)
        else:
            avg_process_times[idx] = -1
    
    if (sample_size == 0):
        logging.error("Sample size = 0!")

    logging.info("--- Average UL Latencies ---")
    logging.info("### [ CU  ] ###")
    if (avg_process_times[1] > 0):
        logging.info("Average Process Time: " + '{0:.{1}f}'.format(avg_process_times[1], 4))
        logging.info("Maximum Process Time: " + '{0:.{1}f}'.format(max(process_times[1]), 4))
        if (enable_plot):
            dist_draw(statistics=process_times[1], title_name="Uplink CU", file_loc=output_loc+"CU-UL-latencies.png")
        else:
            pickle.dump(process_times[1], open(output_loc+"CU-UL-latencies.pkl", "wb"))
    logging.info("Bad Result Rate: " + '{0:.{1}f}'.format(bad_sample_rate[1]/sample_size, 4))
    logging.info("Empty Result Rate: " + '{0:.{1}f}'.format(empty_sample_rate[1]/sample_size, 4))
    
    logging.info("### [ UPF ] ###")
    if (avg_process_times[2] > 0):
        logging.info("Average Process Time: " + '{0:.{1}f}'.format(avg_process_times[2], 4))
        logging.info("Maximum Process Time: " + '{0:.{1}f}'.format(max(process_times[2]), 4))
        if (enable_plot):
            dist_draw(statistics=process_times[2], title_name="Uplink UPF", file_loc=output_loc+"UPF-UL-latencies.png")
        else:
            pickle.dump(process_times[2], open(output_loc+"UPF-UL-latencies.pkl", "wb"))
    logging.info("Bad Result Rate: " + '{0:.{1}f}'.format(bad_sample_rate[2]/sample_size, 4))
    logging.info("Empty Result Rate: " + '{0:.{1}f}'.format(empty_sample_rate[2]/sample_size, 4))

    logging.info("---------------------")

    logging.info("### [ EXT ] ###")
    if (avg_process_times[3] > 0):
        logging.info("Average Process Time: " + '{0:.{1}f}'.format(avg_process_times[3], 4))
        logging.info("Maximum Process Time: " + '{0:.{1}f}'.format(max(process_times[3]), 4))
    logging.info("Bad Result Rate: " + '{0:.{1}f}'.format(bad_sample_rate[3]/sample_size, 4))
    logging.info("Empty Result Rate: " + '{0:.{1}f}'.format(empty_sample_rate[3]/sample_size, 4))

    logging.info("---------------------")
    logging.info("--- Average DL Latencies ---")
    logging.info("### [ CU  ] ###")
    if (avg_process_times[5] > 0):
        logging.info("Average Process Time: " + '{0:.{1}f}'.format(avg_process_times[5], 4))
        logging.info("Maximum Process Time: " + '{0:.{1}f}'.format(max(process_times[5]), 4))
        if (enable_plot):
            dist_draw(statistics=process_times[5], title_name="Downlink CU", file_loc=output_loc+"CU-DL-latencies.png")
        else:
            pickle.dump(process_times[5], open(output_loc+"CU-DL-latencies.pkl", "wb"))
    logging.info("Bad Result Rate: " + '{0:.{1}f}'.format(bad_sample_rate[5]/sample_size, 4))
    logging.info("Empty Result Rate: " + '{0:.{1}f}'.format(empty_sample_rate[5]/sample_size, 4))


    logging.info("### [ UPF ] ###")
    if (avg_process_times[4] > 0):
        logging.info("Average Process Time: " + '{0:.{1}f}'.format(avg_process_times[4], 4))
        logging.info("Maximum Process Time: " + '{0:.{1}f}'.format(max(process_times[4]), 4))
        if (enable_plot):
            dist_draw(statistics=process_times[4], title_name="Downlink UPF", file_loc=output_loc+"UPF-DL-latencies.png")
        else:
            pickle.dump(process_times[4], open(output_loc+"UPF-DL-latencies.pkl", "wb"))
    logging.info("Bad Result Rate: " + '{0:.{1}f}'.format(bad_sample_rate[4]/sample_size, 4))
    logging.info("Empty Result Rate: " + '{0:.{1}f}'.format(empty_sample_rate[4]/sample_size, 4))


if (__name__ == "__main__"):
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()

    parser.add_argument("--size", "-s", type=int, default=DEFAULT_BUCKET_SIZE, help="Assigned bucket size, or the overall session numbers")
    parser.add_argument("--input", "-i", type=str, default="../data/oai/", help="Input pcap file directory")
    parser.add_argument("--output", "-o", type=str, default="../result/", help="Output pcap file directory")
    parser.add_argument("--ue", "-u", type=str, default=DEFAULT_UE_IP, help="UE ip")
    parser.add_argument("--plot", "-p", action="store_true", help="Enable plotting")

    args = parser.parse_args()
    
    main(bucket_size=args.size, input_loc=args.input, output_loc=args.output, ue_ip=args.ue, enable_plot=args.plot)
    
