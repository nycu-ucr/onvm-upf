"""
python3 gtpu_editor.py \
  --in pktgen-dpdk/pcap/gtpv1-u-1024.pcap \
  --out pktgen-dpdk/pcap/gtpv1-u-1024-modified.pcap \
  --outer-src-mac 90:e2:ba:b3:74:b0 \
  --outer-dst-mac 90:e2:ba:b2:92:5c \
  --outer-src-ip 10.10.1.1 \
  --outer-dst-ip 10.10.1.2 \
  --inner-src-ip 10.60.0.1 \
  --inner-dst-ip 192.168.1.4 \
  --teid 0x1 \
  --gtpu-type 255
"""

#!/usr/bin/env python3
import argparse
from scapy.all import rdpcap, wrpcap, Ether, IP, UDP
from scapy.contrib.gtp import GTP_U_Header


def rewrite_gtpu_packet(pkt, args):
    """
    Rewrite outer MAC/IP/UDP, inner MAC/IP/UDP, and GTP-U header fields.
    """
    # Must be GTP-U over UDP/2152 (match BEFORE changing ports)
    if not (UDP in pkt and pkt[UDP].dport == 2152 and GTP_U_Header in pkt):
        return pkt

    # ---------- Outer Ethernet ----------
    if Ether in pkt and args.outer_src_mac and args.outer_dst_mac:
        pkt[Ether].src = args.outer_src_mac
        pkt[Ether].dst = args.outer_dst_mac

    # ---------- Outer IP ----------
    if IP in pkt and args.outer_src_ip and args.outer_dst_ip:
        pkt[IP].src = args.outer_src_ip
        pkt[IP].dst = args.outer_dst_ip
        if hasattr(pkt[IP], "len"):
            del pkt[IP].len
        if hasattr(pkt[IP], "chksum"):
            del pkt[IP].chksum

    # ---------- Outer UDP (GTP-U UDP header) ----------
    if UDP in pkt:
        if args.outer_src_port is not None:
            pkt[UDP].sport = args.outer_src_port
        if args.outer_dst_port is not None:
            pkt[UDP].dport = args.outer_dst_port
        if hasattr(pkt[UDP], "len"):
            del pkt[UDP].len
        if hasattr(pkt[UDP], "chksum"):
            del pkt[UDP].chksum

    # ---------- GTP-U Header ----------
    gtp = pkt[GTP_U_Header]
    if args.teid is not None:
        gtp.teid = args.teid
    if args.gtpu_type is not None:
        gtp.gtp_type = args.gtpu_type

    # ---------- Inner payload (inside GTP-U) ----------
    inner = gtp.payload

    # Inner Ethernet
    if Ether in inner and args.inner_src_mac and args.inner_dst_mac:
        inner[Ether].src = args.inner_src_mac
        inner[Ether].dst = args.inner_dst_mac

    # Inner IP
    if IP in inner and args.inner_src_ip and args.inner_dst_ip:
        inner[IP].src = args.inner_src_ip
        inner[IP].dst = args.inner_dst_ip
        if hasattr(inner[IP], "len"):
            del inner[IP].len
        if hasattr(inner[IP], "chksum"):
            del inner[IP].chksum

    # Inner UDP (user-plane flow)
    if UDP in inner:
        if args.inner_src_port is not None:
            inner[UDP].sport = args.inner_src_port
        if args.inner_dst_port is not None:
            inner[UDP].dport = args.inner_dst_port
        if hasattr(inner[UDP], "len"):
            del inner[UDP].len
        if hasattr(inner[UDP], "chksum"):
            del inner[UDP].chksum

    return pkt


def main():
    parser = argparse.ArgumentParser(description="Rewrite GTP-U headers and inner/outer L2/L3/L4 fields")

    # Input/output
    parser.add_argument("--in", dest="in_pcap", required=True, help="Input PCAP file")
    parser.add_argument("--out", dest="out_pcap", required=True, help="Output PCAP file")

    # Outer L2/L3
    parser.add_argument("--outer-src-mac", required=True)
    parser.add_argument("--outer-dst-mac", required=True)
    parser.add_argument("--outer-src-ip", required=True)
    parser.add_argument("--outer-dst-ip", required=True)

    # Outer UDP ports (GTP-U UDP)
    parser.add_argument("--outer-src-port", type=int, required=False,
                        help="Outer UDP source port (default: keep original)")
    parser.add_argument("--outer-dst-port", type=int, required=False,
                        help="Outer UDP dest port (default: keep original)")

    # Inner L2/L3
    parser.add_argument("--inner-src-mac", required=False)
    parser.add_argument("--inner-dst-mac", required=False)
    parser.add_argument("--inner-src-ip", required=True)
    parser.add_argument("--inner-dst-ip", required=True)

    # Inner UDP ports (user traffic)
    parser.add_argument("--inner-src-port", type=int, required=False,
                        help="Inner UDP source port (default: keep original)")
    parser.add_argument("--inner-dst-port", type=int, required=False,
                        help="Inner UDP dest port (default: keep original)")

    # GTP-U header fields
    parser.add_argument("--teid", type=lambda x: int(x, 0), required=True,
                        help="New TEID (decimal or hex, e.g., 0x1234)")
    parser.add_argument("--gtpu-type", dest="gtpu_type", type=int, required=True,
                        help="GTP-U Message Type (e.g., 255 for G-PDU)")

    args = parser.parse_args()

    print(f"[*] Reading {args.in_pcap}")
    packets = rdpcap(args.in_pcap)

    new_packets = []
    modified = 0

    for pkt in packets:
        if UDP in pkt and pkt[UDP].dport == 2152 and GTP_U_Header in pkt:
            modified += 1
        new_packets.append(rewrite_gtpu_packet(pkt, args))

    print(f"[*] Modified {modified} GTP-U packets")
    print(f"[*] Writing {args.out_pcap}")
    wrpcap(args.out_pcap, new_packets)


if __name__ == "__main__":
    main()