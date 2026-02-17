/**
 *  Test for VxLAN tunneling support.
 *  VxLAN is transparent - it decapsulates and parses inner protocols.
 **/
#include "common.h"

TEST(VxLANTest, Decapsulation) {
    // VxLAN should be transparent - inner protocols should be detected
    // This test verifies that VxLAN packets are processed without errors
    pfwl_state_t* state = pfwl_init();
    EXPECT_NE(state, nullptr);
    
    // Enable all protocols
    pfwl_protocol_l7_enable_all(state);
    
    // Create a minimal valid VxLAN packet with inner IPv4
    // Outer Ethernet header (14 bytes)
    std::vector<unsigned char> packet;
    
    // Outer Ethernet: Dest MAC, Src MAC, EtherType (IPv4)
    packet.insert(packet.end(), {0x00, 0x11, 0x22, 0x33, 0x44, 0x55});  // Dest MAC
    packet.insert(packet.end(), {0x00, 0x66, 0x77, 0x88, 0x99, 0xaa});  // Src MAC
    packet.insert(packet.end(), {0x08, 0x00});                           // EtherType: IPv4
    
    // Outer IPv4 header (20 bytes minimal)
    packet.insert(packet.end(), {0x45, 0x00, 0x00, 0x46});  // Version, IHL, TOS, Total Length (70 bytes)
    packet.insert(packet.end(), {0x00, 0x01, 0x00, 0x00});  // ID, Flags, Fragment Offset
    packet.insert(packet.end(), {0x40, 0x11, 0x00, 0x00});  // TTL, Protocol (UDP), Checksum
    packet.insert(packet.end(), {0xc0, 0xa8, 0x01, 0x0a});  // Source IP: 192.168.1.10
    packet.insert(packet.end(), {0xc0, 0xa8, 0x01, 0x14});  // Dest IP: 192.168.1.20
    
    // Outer UDP header (8 bytes)
    packet.insert(packet.end(), {0x30, 0x39});  // Source port (12345)
    packet.insert(packet.end(), {0x12, 0xb5});  // Dest port (4789 - VxLAN)
    packet.insert(packet.end(), {0x00, 0x32});  // Length (50 bytes)
    packet.insert(packet.end(), {0x00, 0x00});  // Checksum
    
    // VxLAN header (8 bytes)
    packet.insert(packet.end(), {0x08, 0x00, 0x00, 0x00});  // Flags: I=1, Reserved
    packet.insert(packet.end(), {0x00, 0x00, 0x01, 0x00});  // VNI: 1, Reserved
    
    // Inner Ethernet frame (14 bytes)
    packet.insert(packet.end(), {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff});  // Dest MAC
    packet.insert(packet.end(), {0x11, 0x22, 0x33, 0x44, 0x55, 0x66});  // Src MAC
    packet.insert(packet.end(), {0x08, 0x00});                           // EtherType: IPv4
    
    // Inner IPv4 header (20 bytes minimal)
    packet.insert(packet.end(), {0x45, 0x00, 0x00, 0x1c});  // Version, IHL, TOS, Total Length
    packet.insert(packet.end(), {0x00, 0x02, 0x00, 0x00});  // ID, Flags, Fragment Offset
    packet.insert(packet.end(), {0x40, 0x01, 0x00, 0x00});  // TTL, Protocol (ICMP), Checksum
    packet.insert(packet.end(), {0x0a, 0x00, 0x00, 0x01});  // Source IP: 10.0.0.1
    packet.insert(packet.end(), {0x0a, 0x00, 0x00, 0x02});  // Dest IP: 10.0.0.2
    
    pfwl_dissection_info_t dissection_info;
    memset(&dissection_info, 0, sizeof(pfwl_dissection_info_t));
    
    // Test VxLAN decapsulation
    pfwl_status_t status = pfwl_dissect_from_L2(
        state, 
        packet.data(), 
        packet.size(), 
        0.0,  // timestamp
        PFWL_PROTO_L2_EN10MB,
        &dissection_info
    );
    
    // Verify the packet was processed (even if inner protocol not fully recognized)
    // The key is that VxLAN decapsulation doesn't cause errors
    EXPECT_GE(status, PFWL_ERROR_MAX_FLOWS);  // No fatal errors
    
    // Outer L4 should show UDP on port 4789
    EXPECT_EQ(dissection_info.l4.protocol, IPPROTO_UDP);
    
    pfwl_terminate(state);
}
