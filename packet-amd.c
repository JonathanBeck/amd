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
void proto_register_usbmux();
void proto_reg_handoff_usbmux();
static void dissect_usbmux(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static int hf_usbmux_init_ret = -1;
static int hf_usbmux_msg_type = -1;
static int hf_usbmux_packet_length = -1;
static int hf_usbmux_from_port = -1;
static int hf_usbmux_to_port = -1;
static int hf_usbmux_self_count = -1;
static int hf_usbmux_other_count = -1;
static int hf_usbmux_offset = -1;
static int hf_usbmux_flag = -1;
static int hf_usbmux_window = -1;
static int hf_usbmux_unknown = -1;
static int hf_usbmux_packet_length2 = -1;



static int proto_usbmux = -1;
static dissector_handle_t usbmux_handle;
static gint ett_usbmux = -1;

static dissector_handle_t ssl_handle;

#define USBMUX_HEADER_LENGTH 28
#define USBMUX_TCP_TYPE 0x00000006

#define USBMUX_INIT_MSG_LENGTH 20
#define USBMUX_INIT_TYPE   0x00000000
#define USBMUX_INIT_LENGTH 0x00000014
#define USBMUX_INIT_MAJOR  0x00000001
#define USBMUX_INIT_MINOR  0x00000000



#define USBMUX_TCP_SYN    0x02
#define USBMUX_TCP_ACK    0x10
#define USBMUX_TCP_SYNACK 0x12
#define USBMUX_TCP_RST    0x04

static const value_string packettypenames[] = {
        { USBMUX_INIT_TYPE, "Init packet" },
        { USBMUX_TCP_TYPE, "Tcp packet" }
};

static const value_string tcp_flags[] = {
        {USBMUX_TCP_SYN, "SYN"},
        {USBMUX_TCP_RST, "RST"},
        {USBMUX_TCP_ACK, "ACK"},
        {USBMUX_TCP_SYNACK, "SYN/ACK"},
        {0, NULL}
};


void
proto_register_usbmux(void)
{

    static hf_register_info hf[] = {
        { &hf_usbmux_init_ret,
        { "Init message return value", "usbmux.init_ret",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_usbmux_msg_type,
        { "USBMUX message type", "usbmux.type",
        FT_UINT32, BASE_HEX,
        VALS(packettypenames), 0x0,
        NULL, HFILL }
        },
        { &hf_usbmux_packet_length,
        { "Packet Length", "usbmux.packet_length",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_usbmux_from_port,
        { "From Port", "usbmux.from_port",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_usbmux_to_port,
        { "To Port", "usbmux.to_port",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_usbmux_self_count,
        { "Self Count", "usbmux.self_count",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_usbmux_other_count,
        { "Other Count", "usbmux.other_count",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_usbmux_offset,
        { "Offset", "usbmux.offset",
        FT_UINT8, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_usbmux_flag,
        { "TCP Flag", "usbmux.flag",
        FT_UINT8, BASE_HEX,
        VALS(tcp_flags), 0x0,
        NULL, HFILL }
        },
        { &hf_usbmux_window,
        { "Window", "usbmux.window",
        FT_UINT16, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_usbmux_unknown,
        { "Unknown", "usbmux.unknown",
        FT_UINT16, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_usbmux_packet_length2,
        { "Packet Length", "usbmux.packet_length2",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
        }
    };

    static gint *ett[] = {
                &ett_usbmux
    };

        proto_usbmux = proto_register_protocol (
                        "USB Mux Protocol used for Apples mobile devices",	/* name */
                        "USB Mux Protocol",		/* short name */
                        "usbmux"		/* abbrev */
                        );

        proto_register_field_array(proto_usbmux, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_usbmux(void)
{
        static gboolean initialized = FALSE;

        if (!initialized) {
                usbmux_handle = create_dissector_handle(dissect_usbmux, proto_usbmux);
                dissector_add("usb.bulk", IF_CLASS_VENDOR_SPECIFIC, usbmux_handle);
                initialized = TRUE;

                ssl_handle = find_dissector("ssl");
        }
}

int is_usbmux_init_msg(tvbuff_t *tvb)
{
        int ret = 0;

        /* First check if size is sufficient */
        guint length = tvb_length(tvb);

        if (length == USBMUX_INIT_MSG_LENGTH) {
                /* Check if this is an initialization msg */
                gint32 type = 0;
                gint32 length = 0;
                gint32 major = 0;
                gint32 minor = 0;

                type   = tvb_get_ntohl(tvb, 0);
                length = tvb_get_ntohl(tvb, 4);
                major  = tvb_get_ntohl(tvb, 8);
                minor  = tvb_get_ntohl(tvb, 16);

                if ( USBMUX_INIT_TYPE   == type   &&
                     USBMUX_INIT_LENGTH == length &&
                     USBMUX_INIT_MAJOR  == major  &&
                     USBMUX_INIT_MINOR  == minor  )
                        ret = 1;
        }
        return ret;
}

int is_usbmux_packet(tvbuff_t *tvb)
{
        int ret = 0;

        /* First check if size is sufficient */
        guint length = tvb_length(tvb);

        if (length >= USBMUX_HEADER_LENGTH) {

                guint32 type  =  tvb_get_ntohl(tvb, 0);

                if ( USBMUX_TCP_TYPE == type )
                        ret = 1;
        }
        return ret;
}

static void
dissect_usbmux(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        /* Treat init msg */
        if ( is_usbmux_init_msg(tvb) ) {

                if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
                        col_set_str(pinfo->cinfo, COL_PROTOCOL, "Apple Mobile Device");
                }
                /* Clear out stuff in the info column */
                if (check_col(pinfo->cinfo,COL_INFO)) {
                        col_clear(pinfo->cinfo,COL_INFO);
                }

                /* we are being asked for details */
                if (tree) {
                        //try only with short header
                        proto_item *ti = NULL;
                        proto_tree *usbmux_tree = NULL;

                        ti = proto_tree_add_item(tree, proto_usbmux, tvb, 0, USBMUX_INIT_MSG_LENGTH, FALSE);
                        usbmux_tree = proto_item_add_subtree(ti, ett_usbmux);
                        proto_tree_add_item(usbmux_tree, hf_usbmux_init_ret, tvb, 16, 4, FALSE);

                }
        }

        /* Treat packet */
        if ( is_usbmux_packet(tvb) ) {

                if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
                        col_set_str(pinfo->cinfo, COL_PROTOCOL, "Apple Mobile Device");
                }
                /* Clear out stuff in the info column */
                if (check_col(pinfo->cinfo,COL_INFO)) {
                        col_clear(pinfo->cinfo,COL_INFO);
                }

                /* we are being asked for details */
                if (tree) {
                        //try only with short header
                        proto_item *ti = NULL;
                        proto_tree *usbmux_tree = NULL;

                        tvbuff_t *next_tvb;
                        guint offset = 0;
                        guint length = tvb_length(tvb);

                        ti = proto_tree_add_item(tree, proto_usbmux, tvb, 0, USBMUX_HEADER_LENGTH, FALSE);
                        usbmux_tree = proto_item_add_subtree(ti, ett_usbmux);
                        proto_tree_add_item(usbmux_tree, hf_usbmux_msg_type, tvb, offset, 4, FALSE);
                        offset += 4;
                        proto_tree_add_item(usbmux_tree, hf_usbmux_packet_length, tvb, offset, 4, FALSE);
                        offset += 4;
                        proto_tree_add_item(usbmux_tree, hf_usbmux_from_port, tvb, offset, 2, FALSE);
                        offset += 2;
                        proto_tree_add_item(usbmux_tree, hf_usbmux_to_port, tvb, offset, 2, FALSE);
                        offset += 2;
                        proto_tree_add_item(usbmux_tree, hf_usbmux_self_count, tvb, offset, 4, FALSE);
                        offset += 4;
                        proto_tree_add_item(usbmux_tree, hf_usbmux_other_count, tvb, offset, 4, FALSE);
                        offset += 4;
                        proto_tree_add_item(usbmux_tree, hf_usbmux_offset, tvb, offset, 1, FALSE);
                        offset += 1;
                        proto_tree_add_item(usbmux_tree, hf_usbmux_flag, tvb, offset, 1, FALSE);
                        offset += 1;
                        proto_tree_add_item(usbmux_tree, hf_usbmux_window, tvb, offset, 2, FALSE);
                        offset += 2;
                        proto_tree_add_item(usbmux_tree, hf_usbmux_unknown, tvb, offset, 2, FALSE);
                        offset += 2;
                        proto_tree_add_item(usbmux_tree, hf_usbmux_packet_length2, tvb, offset, 2, FALSE);
                        offset += 2;


                        next_tvb = tvb_new_subset(tvb, offset, -1, length);

// TODO : need to handle each coupke of from and to port as a separate conversation associated to a dissector
//                         if (ssl_handle) {
//                                 guint next_length = tvb_length(next_tvb);
// 
//                                 //call ssl dissector only if there is data left
//                                 if (next_length > 0)
//                                         call_dissector(ssl_handle, next_tvb, pinfo, tree);
//                         }
                }
        }
}
