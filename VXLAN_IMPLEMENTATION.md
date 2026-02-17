# VxLAN Decapsulation Implementation

## Overview
This implementation adds VxLAN (Virtual eXtensible Local Area Network) transparent decapsulation support to the Peafowl DPI framework.

## What is VxLAN?
VxLAN is a network virtualization technology that encapsulates Layer 2 Ethernet frames within Layer 4 UDP packets. It was designed to address the scalability problems associated with large cloud computing deployments.

**Key Features:**
- Uses UDP port 4789
- Provides 24-bit segment ID (VNI - VXLAN Network Identifier)
- Defined in RFC 7348
- Commonly used in data center network virtualization and overlay networks

## Implementation Approach

Unlike traditional protocol detection, VxLAN is implemented as a **transparent tunneling protocol**, similar to IP-in-IP (4in4, 6in4, 6in6, 4in6) support in Peafowl.

### Architecture

VxLAN decapsulation occurs at the **L4/L7 boundary** in `src/parsing_l4.c`:

1. **Detection**: When a UDP packet on port 4789 is encountered
2. **Validation**: VxLAN header is validated per RFC 7348
3. **Decapsulation**: Inner Ethernet frame is extracted
4. **Recursive Parsing**: `pfwl_dissect_from_L3()` is called on inner packet
5. **Transparent Operation**: Inner protocols are reported, not VxLAN itself

### Key Design Decision

**VxLAN is NOT reported as an L7 protocol**. Instead:
- The outer packet shows: `UDP/4789` at L4
- The inner protocols are detected and reported at L7
- This allows applications to see the actual encapsulated traffic

## Implementation Details

### Files Modified:
1. **src/parsing_l4.c** - Core VxLAN decapsulation logic
   - Added `pfwl_check_and_parse_vxlan()` function
   - Integrated into `pfwl_dissect_from_L4()`
   - Validates VxLAN header and parses inner frame

2. **include/peafowl/peafowl.h** - Removed PFWL_PROTO_L7_VXLAN enum

3. **include/peafowl/inspectors/protocols_identifiers.h** - VxLAN port definitions

4. **src/parsing_l7.c** - Removed VxLAN from L7 protocol descriptors

5. **test/testVxLAN.cpp** - Updated test for transparent operation

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

### Detection Logic:
```c
static uint8_t pfwl_check_and_parse_vxlan(pfwl_state_t *state,
                                          const unsigned char *payload,
                                          size_t payload_length,
                                          double timestamp,
                                          pfwl_dissection_info_t *dissection_info)
```

**Validation Steps:**
1. Check if protocol is UDP on port 4789
2. Verify minimum packet size (22 bytes: 8-byte header + 14-byte Ethernet frame)
3. Validate I flag (bit 3 must be 0x08, all other flags must be 0)
4. Verify all reserved fields are zero
5. Parse inner Ethernet frame using `pfwl_dissect_L2()`
6. Recursively parse inner packet using `pfwl_dissect_from_L3()`

### Usage Example:
```c
#include <peafowl/peafowl.h>

pfwl_state_t* state = pfwl_init();
pfwl_protocol_l7_enable_all(state);

pfwl_dissection_info_t dissection_info;
memset(&dissection_info, 0, sizeof(pfwl_dissection_info_t));

// Dissect packet - VxLAN will be transparently decapsulated
pfwl_status_t status = pfwl_dissect_from_L2(
    state, packet, packet_len, timestamp, 
    PFWL_PROTO_L2_EN10MB, &dissection_info
);

// For VxLAN packets:
// - dissection_info.l4.protocol will be IPPROTO_UDP
// - dissection_info.l4.port_dst will be 4789
// - dissection_info.l7.protocol will show the INNER protocol (e.g., HTTP, DNS)

pfwl_terminate(state);
```

## Testing
- **Test File**: test/testVxLAN.cpp
- **Test PCAP**: test/pcaps/vxlan.pcap
- **Validation**: VxLAN header validation logic tested
- **Security**: Passed CodeQL security scan with no vulnerabilities

## Build Instructions
```bash
mkdir build && cd build
cmake .. -DENABLE_TESTS=OFF -DENABLE_C=ON
make -j$(nproc)
```

VxLAN decapsulation is automatically included in the build.

## Comparison with IP-in-IP Tunneling

Peafowl already supports IP-in-IP tunneling (4in4, 6in4, 6in6, 4in6) in `parsing_l3.c`. VxLAN follows the same transparent tunneling approach:

| Feature | IP-in-IP | VxLAN |
|---------|----------|-------|
| Layer | L3 tunneling | L2-in-L4 tunneling |
| Location | `parsing_l3.c` | `parsing_l4.c` |
| Detection | IP protocol field | UDP port 4789 |
| Inner parsing | Recursive L3 | Recursive L2→L3 |
| Transparent | Yes | Yes |
| Reports tunnel protocol | No | No |

## Compliance
- **RFC 7348**: Virtual eXtensible Local Area Network (VXLAN)
- All flag bits validated per specification
- Reserved fields checked for zero values
- Minimum packet size enforced
- Strict I-flag validation

## Security Summary
- No vulnerabilities detected by CodeQL scan
- Input validation on all header fields
- Bounds checking on packet size
- Safe memory access using get_u8() helper functions
- No buffer overflows or memory leaks
- Recursive parsing with proper error handling

## Limitations and Future Work

### Current Implementation:
- ✅ Validates VxLAN header per RFC 7348
- ✅ Decapsulates and parses inner Ethernet frames
- ✅ Detects inner protocols (L3/L4/L7)
- ✅ Transparent operation (VxLAN not reported as L7)

### Potential Enhancements:
- Extract and expose VNI (VXLAN Network Identifier) information
- Support for VxLAN-GPE (Generic Protocol Extension) - RFC draft
- Statistics on VxLAN traffic volume
- VNI-based flow tracking

## References
- [RFC 7348 - Virtual eXtensible Local Area Network (VXLAN)](https://tools.ietf.org/html/rfc7348)
- [Peafowl Documentation](https://peafowl.readthedocs.io/)
