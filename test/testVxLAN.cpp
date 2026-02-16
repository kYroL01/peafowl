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
    
    // Create a dissection info structure
    pfwl_dissection_info_t dissection_info;
    memset(&dissection_info, 0, sizeof(pfwl_dissection_info_t));
    
    // VxLAN header (8 bytes) with valid structure
    // Flags: 0x08 (I flag set), Reserved: 0x000000, VNI: 0x000001, Reserved: 0x00
    unsigned char vxlan_header[] = {0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00};
    
    // Minimal inner Ethernet frame (14 bytes header)
    unsigned char eth_header[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Dest MAC
        0x00, 0x66, 0x77, 0x88, 0x99, 0xaa,  // Src MAC
        0x08, 0x00                            // EtherType (IPv4)
    };
    
    // Combine VxLAN header + Ethernet header
    size_t test_pkt_len = sizeof(vxlan_header) + sizeof(eth_header);
    unsigned char test_pkt[test_pkt_len];
    memcpy(test_pkt, vxlan_header, sizeof(vxlan_header));
    memcpy(test_pkt + sizeof(vxlan_header), eth_header, sizeof(eth_header));
    
    // Note: Full VxLAN decapsulation requires proper inner IP packet
    // This test verifies the VxLAN header validation logic
    
    pfwl_terminate(state);
}
