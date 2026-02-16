#!/usr/bin/env python3
"""
Generate a simple VxLAN PCAP file for testing
"""
import struct
import time

def write_pcap_header(f):
    """Write PCAP global header"""
    f.write(struct.pack('I', 0xa1b2c3d4))  # Magic number
    f.write(struct.pack('H', 2))            # Major version
    f.write(struct.pack('H', 4))            # Minor version
    f.write(struct.pack('I', 0))            # Timezone offset
    f.write(struct.pack('I', 0))            # Timestamp accuracy
    f.write(struct.pack('I', 65535))        # Max packet length
    f.write(struct.pack('I', 1))            # Data link type (Ethernet)

def write_pcap_packet(f, data, timestamp=None):
    """Write a packet to PCAP file"""
    if timestamp is None:
        timestamp = time.time()
    
    ts_sec = int(timestamp)
    ts_usec = int((timestamp - ts_sec) * 1000000)
    
    f.write(struct.pack('I', ts_sec))       # Timestamp seconds
    f.write(struct.pack('I', ts_usec))      # Timestamp microseconds
    f.write(struct.pack('I', len(data)))    # Packet length (saved)
    f.write(struct.pack('I', len(data)))    # Packet length (original)
    f.write(data)                           # Packet data

def create_vxlan_packet():
    """Create a VxLAN encapsulated packet"""
    
    # Ethernet header (outer)
    eth_dst = b'\x00\x00\x00\x00\x00\x01'
    eth_src = b'\x00\x00\x00\x00\x00\x02'
    eth_type = b'\x08\x00'  # IPv4
    eth_header = eth_dst + eth_src + eth_type
    
    # IP header (outer) - Simplified
    ip_ver_ihl = b'\x45'
    ip_tos = b'\x00'
    ip_tot_len = struct.pack('!H', 100)  # Total length
    ip_id = b'\x00\x01'
    ip_frag = b'\x00\x00'
    ip_ttl = b'\x40'
    ip_proto = b'\x11'  # UDP
    ip_checksum = b'\x00\x00'  # Simplified - normally calculated
    ip_src = b'\x0a\x00\x00\x01'  # 10.0.0.1
    ip_dst = b'\x0a\x00\x00\x02'  # 10.0.0.2
    
    ip_header = (ip_ver_ihl + ip_tos + ip_tot_len + ip_id + ip_frag + 
                 ip_ttl + ip_proto + ip_checksum + ip_src + ip_dst)
    
    # UDP header (outer)
    udp_src = struct.pack('!H', 12345)  # Source port
    udp_dst = struct.pack('!H', 4789)   # VxLAN port
    udp_len = struct.pack('!H', 80)     # UDP length
    udp_checksum = b'\x00\x00'          # Simplified
    udp_header = udp_src + udp_dst + udp_len + udp_checksum
    
    # VxLAN header (8 bytes)
    vxlan_flags = b'\x08'       # Flags: I flag set
    vxlan_reserved1 = b'\x00\x00\x00'  # Reserved
    vxlan_vni = b'\x00\x00\x01'        # VNI = 1
    vxlan_reserved2 = b'\x00'          # Reserved
    vxlan_header = vxlan_flags + vxlan_reserved1 + vxlan_vni + vxlan_reserved2
    
    # Inner Ethernet frame
    inner_eth_dst = b'\x00\x11\x22\x33\x44\x55'
    inner_eth_src = b'\x00\x66\x77\x88\x99\xaa'
    inner_eth_type = b'\x08\x00'  # IPv4
    inner_eth_header = inner_eth_dst + inner_eth_src + inner_eth_type
    
    # Inner IP header (simplified ICMP echo request)
    inner_ip_header = (b'\x45\x00\x00\x54'  # Version, IHL, TOS, Total Length
                      b'\x00\x01\x00\x00'   # ID, Flags, Fragment Offset
                      b'\x40\x01\x00\x00'   # TTL, Protocol (ICMP), Checksum
                      b'\xc0\xa8\x01\x0a'   # Source IP (192.168.1.10)
                      b'\xc0\xa8\x01\x14')  # Dest IP (192.168.1.20)
    
    # Combine all parts
    packet = (eth_header + ip_header + udp_header + vxlan_header + 
              inner_eth_header + inner_ip_header)
    
    return packet

def main():
    """Generate VxLAN test PCAP"""
    output_file = 'test/pcaps/vxlan.pcap'
    
    with open(output_file, 'wb') as f:
        write_pcap_header(f)
        
        # Write 3 VxLAN packets
        for i in range(3):
            packet = create_vxlan_packet()
            write_pcap_packet(f, packet, timestamp=time.time() + i * 0.1)
    
    print(f"Generated {output_file} with 3 VxLAN packets")

if __name__ == '__main__':
    main()
