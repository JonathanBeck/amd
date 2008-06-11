/* packet-amd.c
 * Routines for Apple Mobile Device (AMD) Protocol disassembly
 *
 * $Id: packet-amd.c 24123 2008-06-08 17:15:32Z stig $
 *
 * Copyright (c) 2008 by Jonathan Beck <jonabeck@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-usb.h>

/* forward reference */
void proto_register_amd();
void proto_reg_handoff_amd();
static void dissect_amd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);


static int hf_amd_version = -1;
static int hf_amd_packet_length = -1;
static int hf_amd_session_id = -1;
static int hf_amd_self_count = -1;
static int hf_amd_other_count = -1;
static int hf_amd_operation = -1;
static int hf_amd_packet_length2 = -1;
static int hf_amd_mode = -1;
static int hf_amd_payload_length = -1;

static int proto_amd = -1;
static dissector_handle_t amd_handle;
static gint ett_amd = -1;

static dissector_handle_t ssl_handle;

#define AMD_SHORT_HEADER_LENGTH 28
#define AMD_LONG_HEADER_LENGTH 32

#define AMD_VERSION_1 0x00000006
#define AMD_VERSION_2 0x00000060

#define IS_AMD_PACKET(first_four_bytes) ( (first_four_bytes == AMD_VERSION_1) || (first_four_bytes == AMD_VERSION_2))

void
proto_register_amd(void)
{

    static hf_register_info hf[] = {
	{ &hf_amd_version,
	  { "AMD Protocol Version", "amd.version",
	  FT_UINT32, BASE_DEC,
	  NULL, 0x0,
	  NULL, HFILL }
	},
	{ &hf_amd_packet_length,
	  { "Packet Length", "amd.packet_length",
	  FT_UINT32, BASE_DEC,
	  NULL, 0x0,
	  NULL, HFILL }
	},
	{ &hf_amd_session_id,
	  { "Session ID", "amd.session_id",
	  FT_UINT32, BASE_HEX,
	  NULL, 0x0,
	  NULL, HFILL }
	},
	{ &hf_amd_self_count,
	  { "Self Count", "amd.self_count",
	  FT_UINT32, BASE_DEC,
	  NULL, 0x0,
	  NULL, HFILL }
	},
	{ &hf_amd_other_count,
	  { "Other Count", "amd.other_count",
	  FT_UINT32, BASE_DEC,
	  NULL, 0x0,
	  NULL, HFILL }
	},
	{ &hf_amd_operation,
	  { "Operation", "amd.operation",
	  FT_UINT32, BASE_HEX,
	  NULL, 0x0,
	  NULL, HFILL }
	},
	{ &hf_amd_packet_length2,
	  { "Packet Length", "amd.packet_length2",
	  FT_UINT32, BASE_DEC,
	  NULL, 0x0,
	  NULL, HFILL }
	},
	{ &hf_amd_mode,
	  { "Mode", "amd.mode",
	  FT_UINT16, BASE_HEX,
	  NULL, 0x0,
	  NULL, HFILL }
	},
	{ &hf_amd_payload_length,
	  { "Payload Length", "amd.payload_length",
	  FT_UINT16, BASE_DEC,
	  NULL, 0x0,
	  NULL, HFILL }
	}
    };

    static gint *ett[] = {
		&ett_amd
    };

	proto_amd = proto_register_protocol (
			"Apple Mobile Device Protocol",	/* name */
			"Apple Mobile Device",		/* short name */
			"amd"		/* abbrev */
			);

	proto_register_field_array(proto_amd, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_amd(void)
{
	static gboolean initialized = FALSE;

	if (!initialized) {
		amd_handle = create_dissector_handle(dissect_amd, proto_amd);
		dissector_add("usb.bulk", IF_CLASS_VENDOR_SPECIFIC, amd_handle);
		initialized = TRUE;

		ssl_handle = find_dissector("ssl");
	}
}

static void
dissect_amd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	//First check if we are really in the Apple Mobile Device Protocol
	guint length = tvb_length(tvb);

	if (length >= SHORT_HEADER_LENGTH) { //min header size

		guint32 version =  tvb_get_ntohl(tvb, 0);

		if ( IS_AMD_PACKET(version) ) { //if packet begins with 00 00 00 00 60 we assume it is an AMD packet
	
			if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
				col_set_str(pinfo->cinfo, COL_PROTOCOL, "Apple Mobile Device");
			}
			/* Clear out stuff in the info column */
			if (check_col(pinfo->cinfo,COL_INFO)) {
				col_clear(pinfo->cinfo,COL_INFO);
			}

			if (tree) {
				//try only with short header
				proto_item *ti = NULL;
				proto_tree *amd_tree = NULL;

				tvbuff_t *next_tvb;

				guint offset = 0;
				guint32 flen2; //will be used to determine if we are in a short or long header

				flen2 =  tvb_get_ntohl(tvb, 24);

				if (0 != flen2)
					ti = proto_tree_add_item(tree, proto_amd, tvb, 0, 32, FALSE); //long header
				else 
					ti = proto_tree_add_item(tree, proto_amd, tvb, 0, 28, FALSE); //short header

				amd_tree = proto_item_add_subtree(ti, ett_amd);
				proto_tree_add_item(amd_tree, hf_amd_version, tvb, offset, 4, FALSE);
				offset += 4;
				proto_tree_add_item(amd_tree, hf_amd_packet_length, tvb, offset, 4, FALSE);
				offset += 4;
				proto_tree_add_item(amd_tree, hf_amd_session_id, tvb, offset, 4, FALSE);
				offset += 4;
				proto_tree_add_item(amd_tree, hf_amd_self_count, tvb, offset, 4, FALSE);
				offset += 4;
				proto_tree_add_item(amd_tree, hf_amd_other_count, tvb, offset, 4, FALSE);
				offset += 4;
				proto_tree_add_item(amd_tree, hf_amd_operation, tvb, offset, 4, FALSE);
				offset += 4;

				
				if (0 != flen2){

					proto_tree_add_item(amd_tree, hf_amd_packet_length2, tvb, offset, 4, FALSE);
					offset += 4;
					proto_tree_add_item(amd_tree, hf_amd_mode, tvb, offset, 2, FALSE);
					offset += 2;
					proto_tree_add_item(amd_tree, hf_amd_payload_length, tvb, offset, 2, FALSE);
					offset += 2;
				}

				next_tvb = tvb_new_subset(tvb, offset, -1, length);

				if (ssl_handle)
					call_dissector(ssl_handle, next_tvb, pinfo, tree);
			}
		}
	}
}
