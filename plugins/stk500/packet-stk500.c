/*
 * <http://desowin.org/usbpcap/dissectors.html>
 * <https://ask.wireshark.org/questions/56135/how-to-call-my-dissector-on-usb-payload-leftover-capture-data>
 * <http://www.atmel.com/images/doc2591.pdf>
 * <https://stackoverflow.com/questions/38630416/wireshark-lua-dissector-reassembly-dissector-not-called-with-previous-tvbs-da>
 */
#include <stdio.h>
#include "config.h"
#include <epan/packet.h>
#include <epan/dissectors/packet-usb.h>
#include "packet-stk500.h"

static int proto_stk500 = -1;

static int hf_stk500_sequence_number = -1;
static int hf_stk500_message_size = -1;
static int hf_stk500_message_body = -1;
static int hf_stk500_checksum = -1;

void proto_register_stk500(void);
void proto_reg_handoff_stk500(void);

static gint remaining = -1;

static int test_stk500(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_, void *data _U_) {
    if (remaining > 0) {// trying to decode
        fprintf(stderr, "desegment_len\n");
        return TRUE;
    }
    /* 0) Verify needed bytes available in tvb so tvb_get...() doesn't cause exception. */
    if (tvb_captured_length(tvb) < 5)
        return FALSE;

    /* 1) first byte must be 0x42 */
    if (tvb_get_guint8(tvb, 0) != 0x1b)
        return FALSE;

    /* 2) token must be 0x0e */
    if (tvb_get_guint8(tvb, 4) != 0x0e)
        return FALSE;

    return TRUE;
}

static gint ett_usb_hdr = -1;

static int dissect_stk500(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent, void *data) {
    proto_tree *tree = NULL;


    if (!test_stk500(pinfo, tvb, 0, data))
        return FALSE;

    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "STK500");
    proto_item *ti = proto_tree_add_protocol_format(parent, proto_stk500, tvb, 0, -1,
            "STK500");
    tree = proto_item_add_subtree(ti, ett_usb_hdr);

    fprintf(stderr, "remaining: %d\n", remaining);
    /*
     *  First of all, if we have remaining bytes consume that
     */
    if(remaining > 0) {

        gint captured = tvb_captured_length(tvb);

        gboolean need_more = captured < remaining;

        fprintf(stderr, "we use this packet data to complete the previous\n");
        proto_tree_add_item(tree, hf_stk500_message_body,    tvb, 0, need_more ? captured : remaining - 1, ENC_ASCII|ENC_NA);

        if (!need_more)
            proto_tree_add_item(tree, hf_stk500_checksum,        tvb, remaining - 1, 1, ENC_BIG_ENDIAN);

        remaining = need_more ? remaining - captured : -1;

        return captured;
    } /* here we suppose that the first message has the message size*/
    guint16 message_size = tvb_get_guint16(tvb, 2, ENC_BIG_ENDIAN);

    fprintf(stderr, "reported: %d captured: %d\n", tvb_reported_length(tvb), tvb_captured_length(tvb));
    gint available = tvb_reported_length_remaining(tvb, 5);
    remaining = message_size + 1 - available;

    fprintf(stderr, "available: %d remaining: %d\n", available, remaining);

    proto_tree_add_item(tree, hf_stk500_sequence_number, tvb, 1, 1,                ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_stk500_message_size,    tvb, 2, 2,                ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_stk500_message_body,    tvb, 5, available,     ENC_ASCII|ENC_NA);

    return tvb_captured_length(tvb);
}

void proto_reg_handoff_stk500(void) {
    fprintf(stderr, " [proto_reg_handoff_stk500()]\n");
    //static dissector_handle_t stk500_handle;

    //stk500_handle = create_dissector_handle(dissect_stk500, proto_stk500);

    heur_dissector_add("usb.bulk", dissect_stk500, "stk500 serial comunication", "stk500", proto_stk500, HEURISTIC_ENABLE);
}

void proto_register_stk500(void) {
    fprintf(stderr, " [ENTRO NELLA CASA]\n");
    static hf_register_info hf[] = {

    /* USB packet pseudoheader members */

        { &hf_stk500_message_size,
          { "Message size", "stk500.message_size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_stk500_sequence_number,
          { "Sequence number", "stk500.sequence_number",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_stk500_message_body,
          { "Message body", "stk500.message_body",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_stk500_checksum,
          { "Checksum", "stk500.checksum",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
    };
    static gint *usb_subtrees[] = {
       &ett_usb_hdr, 
    };
    proto_stk500 = proto_register_protocol(
        "STK500 protocol",
        "STK500",
        "stk500"
    );

    // https://stackoverflow.com/questions/38628278/wireshark-c-dissector-error-when-filling-subtree
    proto_register_field_array(proto_stk500, hf, array_length(hf));
    proto_register_subtree_array(usb_subtrees, array_length(usb_subtrees));
}

