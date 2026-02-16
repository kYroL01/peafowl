/**
 *  Test for VxLAN protocol.
 **/
#include "common.h"

#define EXPECTED_VXLAN_PACKETS 3

TEST(VxLANTest, Generic) {
    std::vector<uint> protocols;
    
    // Test with VxLAN pcap file
    getProtocols("./pcaps/vxlan.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_VXLAN], (uint) EXPECTED_VXLAN_PACKETS);
    
    // Verify protocol name
    const char* name = pfwl_get_L7_protocol_name(PFWL_PROTO_L7_VXLAN);
    EXPECT_STREQ(name, "VxLAN");
}
