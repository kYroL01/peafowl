# VxLAN Detection Implementation

## Overview
This implementation adds VxLAN (Virtual eXtensible Local Area Network) protocol detection support to the Peafowl DPI framework.

## What is VxLAN?
VxLAN is a network virtualization technology that encapsulates Layer 2 Ethernet frames within Layer 4 UDP packets. It was designed to address the scalability problems associated with large cloud computing deployments.

**Key Features:**
- Uses UDP port 4789
- Provides 24-bit segment ID (VNI - VXLAN Network Identifier)
- Defined in RFC 7348
- Commonly used in data center network virtualization and overlay networks

## Implementation Details

### Files Modified/Created:
1. **include/peafowl/peafowl.h** - Added PFWL_PROTO_L7_VXLAN to protocol enum
2. **include/peafowl/inspectors/protocols_identifiers.h** - Added port_vxlan (4789) definitions
3. **include/peafowl/inspectors/inspectors.h** - Added check_vxlan() declaration
4. **src/inspectors/vxlan.c** - New VxLAN protocol inspector
5. **src/parsing_l7.c** - Registered VxLAN in protocol descriptors and known UDP ports
6. **test/testVxLAN.cpp** - Unit test for VxLAN detection
7. **test/pcaps/vxlan.pcap** - Sample VxLAN traffic for testing
8. **.gitignore** - Updated to exclude build artifacts

### VxLAN Header Format (8 bytes):
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|R|R|R|R|I|R|R|R|            Reserved                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                VXLAN Network Identifier (VNI) |   Reserved    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Detection Logic (src/inspectors/vxlan.c):
1. **Port Check**: Verifies UDP port 4789 (source or destination)
2. **Size Check**: Minimum 22 bytes (8-byte VxLAN header + 14-byte inner Ethernet frame)
3. **Flags Validation**: 
   - Bit 3 (I flag) must be set (0x08)
   - All other flag bits must be zero (strict RFC 7348 compliance)
4. **Reserved Fields**: All reserved fields must be zero

### Usage Example:
```c
#include <peafowl/peafowl.h>

pfwl_state_t* state = pfwl_init();
pfwl_protocol_l7_enable(state, PFWL_PROTO_L7_VXLAN);

// Process packets...
// VxLAN packets will be identified with PFWL_PROTO_L7_VXLAN

pfwl_terminate(state);
```

## Testing
- **Test File**: test/testVxLAN.cpp
- **Test PCAP**: test/pcaps/vxlan.pcap (3 VxLAN packets)
- **Code Coverage**: Protocol name verification and packet detection
- **Security**: Passed CodeQL security scan with no vulnerabilities

## Build Instructions
```bash
mkdir build && cd build
cmake .. -DENABLE_TESTS=OFF -DENABLE_C=ON
make -j$(nproc)
```

The VxLAN inspector will be automatically included via the glob pattern in CMakeLists.txt.

## Future Enhancements
While the current implementation successfully detects VxLAN encapsulation, a future enhancement could:
1. Parse the inner Ethernet frame
2. Continue L2/L3/L4/L7 analysis on the decapsulated traffic
3. Report both VxLAN and the inner protocol(s)
4. Extract VNI (VXLAN Network Identifier) information

This would require modifications to the packet parsing flow to support recursive protocol inspection, similar to how the project currently handles IP-in-IP tunneling in parsing_l3.c.

## Compliance
- **RFC 7348**: Virtual eXtensible Local Area Network (VXLAN)
- All flag bits validated per specification
- Reserved fields checked for zero values
- Minimum packet size enforced

## Security Summary
- No vulnerabilities detected by CodeQL scan
- Input validation on all header fields
- Bounds checking on packet size
- Safe memory access using get_u8() helper functions
- No buffer overflows or memory leaks

## References
- [RFC 7348 - Virtual eXtensible Local Area Network (VXLAN)](https://tools.ietf.org/html/rfc7348)
- [Peafowl Documentation](https://peafowl.readthedocs.io/)
