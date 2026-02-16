/*
 * vxlan.c
 *
 * =========================================================================
 * Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * =========================================================================
 */

#include <peafowl/inspectors/inspectors.h>
#include <peafowl/peafowl.h>

/**
 * VxLAN header structure (8 bytes):
 * - Flags (1 byte): bit 3 must be set (I flag = 0x08)
 * - Reserved (3 bytes): must be zero
 * - VNI (3 bytes): VXLAN Network Identifier
 * - Reserved (1 byte): must be zero
 */
#define PFWL_VXLAN_HEADER_LEN 8
#define PFWL_VXLAN_FLAGS_I 0x08

uint8_t check_vxlan(pfwl_state_t *state, const unsigned char *app_data,
                    size_t data_length, pfwl_dissection_info_t *pkt_info,
                    pfwl_flow_info_private_t *flow_info_private) {
  /* VxLAN uses UDP port 4789 */
  if (pkt_info->l4.port_src != port_vxlan &&
      pkt_info->l4.port_dst != port_vxlan) {
    return PFWL_PROTOCOL_NO_MATCHES;
  }

  /* Minimum packet size: VxLAN header (8 bytes) + inner Ethernet frame (14 bytes min) */
  if (data_length < PFWL_VXLAN_HEADER_LEN + 14) {
    return PFWL_PROTOCOL_NO_MATCHES;
  }

  /* Check VxLAN flags - bit 3 (I flag) must be set */
  uint8_t flags = get_u8(app_data, 0);
  if ((flags & PFWL_VXLAN_FLAGS_I) == 0) {
    return PFWL_PROTOCOL_NO_MATCHES;
  }

  /* Check that reserved fields are zero (bytes 1-3) */
  if (get_u8(app_data, 1) != 0 || get_u8(app_data, 2) != 0 ||
      get_u8(app_data, 3) != 0) {
    return PFWL_PROTOCOL_NO_MATCHES;
  }

  /* Check that last reserved field is zero (byte 7) */
  if (get_u8(app_data, 7) != 0) {
    return PFWL_PROTOCOL_NO_MATCHES;
  }

  return PFWL_PROTOCOL_MATCHES;
}
