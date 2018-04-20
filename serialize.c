#include "serialize.h"
#include "ccp.h"

#ifdef __USRLIB__
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#else
#include <linux/types.h>
#include <linux/string.h> // memcpy
#include <linux/slab.h> // kmalloc
#endif

/* (type, len, socket_id) header
 * -----------------------------------
 * | Msg Type | Len (2B) | Uint32    |
 * | (2 B)    | (2 B)    | (32 bits) |
 * -----------------------------------
 * total: 6 Bytes
 */

/* We only read Install Expr messages.
 */
int read_header(struct CcpMsgHeader *hdr, char *buf) {
    memcpy(hdr, buf, sizeof(struct CcpMsgHeader));

    switch (hdr->Type) {
    case INSTALL_EXPR:
        return sizeof(struct CcpMsgHeader);
    case UPDATE_FIELDS:
        return sizeof(struct CcpMsgHeader);
    default:
        return -hdr->Type;
    }
}

/* We only write Create, and Measure messages.
 */
int serialize_header(char *buf, int bufsize, struct CcpMsgHeader *hdr) {
    switch (hdr->Type) {
    case CREATE:
    case MEASURE:
        break;
    default:
        return -1;
    }

    if (bufsize < ((int)sizeof(struct CcpMsgHeader))) {
        return -2;
    }

    memcpy(buf, hdr, sizeof(struct CcpMsgHeader));
    return sizeof(struct CcpMsgHeader);
}

int write_create_msg(
    char *buf, 
    int bufsize,
    u32 sid, 
    struct CreateMsg cr
) {
    struct CcpMsgHeader hdr;
    int ok;
    u16 msg_len = sizeof(struct CcpMsgHeader) + sizeof(struct CreateMsg);
    
    hdr = (struct CcpMsgHeader){
        .Type = CREATE, 
        .Len = msg_len,
        .SocketId = sid,
    };

    if (bufsize < 0) {
        return -1;
    }
    
    if (((u32) bufsize) < hdr.Len) {
        return -2;
    }
    
    ok = serialize_header(buf, bufsize, &hdr);
    if (ok < 0) {
        return ok;
    }

    buf += ok;
    memcpy(buf, &cr, hdr.Len - sizeof(struct CcpMsgHeader));
    return hdr.Len;
}

int write_measure_msg(
    char *buf,
    int bufsize,
    u32 sid, 
    u64 *msg_fields,
    u8 num_fields
) {
    int ok;
    struct MeasureMsg ms = {
        .num_fields = num_fields,
    };
    
    // 4 bytes for num_fields, which is u32
    u16 msg_len = sizeof(struct CcpMsgHeader) + 4 + ms.num_fields * sizeof(u64);
    struct CcpMsgHeader hdr = {
        .Type = MEASURE, 
        .Len = msg_len,
        .SocketId = sid,
    };
    
    // copy message fields into MeasureMsg struct
    memcpy(ms.fields, msg_fields, ms.num_fields * sizeof(u64));
    
    if (bufsize < 0) {
        return -1;
    }

    if (((u32) bufsize) < hdr.Len) {
        return -2;
    }

    ok = serialize_header(buf, bufsize, &hdr);
    if (ok < 0) {
        return ok;
    }

    buf += ok;
    memcpy(buf, &ms, hdr.Len - sizeof(struct CcpMsgHeader));
    return hdr.Len;
}

int read_install_expr_msg(
    struct CcpMsgHeader *hdr,
    struct InstallExpressionMsg *msg,
    char *buf
) {
    if (hdr->Type != INSTALL_EXPR) {
        return -1;
    } 

    if (hdr->Len - sizeof(struct CcpMsgHeader) > sizeof(struct InstallExpressionMsg)) {
        return -2;
    }

    memcpy(msg, buf, 2 * sizeof(u32));
    buf += 2 * sizeof(u32);

    memcpy(&msg->exprs, buf, msg->num_expressions * sizeof(struct ExpressionMsg));
    buf += msg->num_expressions * sizeof(struct ExpressionMsg);
    memcpy(&msg->instrs, buf, msg->num_instructions * sizeof(struct InstructionMsg));
    buf += msg->num_expressions * sizeof(struct InstructionMsg);

    return hdr->Len - sizeof(struct CcpMsgHeader);
}

int read_update_fields_msg(
    struct CcpMsgHeader *hdr,
    struct UpdateFieldsMsg *msg,
    char *buf
) {
    if (hdr->Type != UPDATE_FIELDS) {
        return -1;
    }

    if ((hdr->Len - sizeof(struct CcpMsgHeader)) > sizeof(struct UpdateFieldsMsg)) {
        return -2;
    }

    memcpy(msg, buf, hdr->Len - sizeof(struct CcpMsgHeader));
    return hdr->Len - sizeof(struct CcpMsgHeader);
}
