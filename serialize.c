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

/* (type, len << 1, socket_id) header
 * -----------------------------------
 * | Msg Type | Len (2B) | Uint32    |
 * | (1 B)    | (1 B)    | (32 bits) |
 * -----------------------------------
 * total: 6 Bytes
 */
struct __attribute__((packed, aligned(2))) CcpMsgHeader_Wire {
    u8 Type;
    u8 Len;
    u32 SocketId;
};

/* We only read Install Expr messages.
 */
int read_header(struct CcpMsgHeader *hdr, char *buf) {
    struct CcpMsgHeader_Wire hdr_wire;
    memcpy(&hdr_wire, buf, sizeof(struct CcpMsgHeader_Wire));
    hdr->Type = hdr_wire.Type;
    hdr->Len = (hdr_wire.Len << 1);
    hdr->SocketId = hdr_wire.SocketId;

    switch (hdr->Type) {
    case INSTALL_EXPR:
        return sizeof(struct CcpMsgHeader_Wire);
    default:
        return -1;
    }
}

/* We only write Create, and Measure messages.
 */
int serialize_header(char *buf, int bufsize, struct CcpMsgHeader *hdr) {
    struct CcpMsgHeader_Wire hdr_wire;

    switch (hdr->Type) {
    case CREATE:
    case MEASURE:
        break;
    default:
        return -1;
    }

    if (bufsize < ((int)sizeof(struct CcpMsgHeader_Wire))) {
        return -2;
    }

    hdr_wire.Type = hdr->Type;
    hdr_wire.SocketId = hdr->SocketId;
    if (hdr->Len % 2 == 1) {
        hdr_wire.Len = (hdr->Len >> 1) + 1;
    } else {
        hdr_wire.Len = (hdr->Len >> 1);
    }
    
    memcpy(buf, &hdr_wire, sizeof(struct CcpMsgHeader_Wire));
    return sizeof(struct CcpMsgHeader_Wire);
}

int write_create_msg(
    char *buf, 
    int bufsize,
    u32 sid, 
    struct CreateMsg cr
) {
    struct CcpMsgHeader hdr;
    int ok, congAlgLen;
    congAlgLen = strlen(cr.congAlg) + 1;
    // ensure length is always even since we lose 1 bit of size info
    if (congAlgLen % 2 == 1) { 
        congAlgLen++;
    }
    
    hdr = (struct CcpMsgHeader){
        .Type = CREATE, 
        .Len = 6 + 24 + congAlgLen, 
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
    memcpy(buf, &cr, hdr.Len - 6);
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
    
    struct CcpMsgHeader hdr = {
        .Type = MEASURE, 
        .Len = 10 + ms.num_fields * sizeof(u64),
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
    memcpy(buf, &ms, hdr.Len - 6);
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

    if (hdr->Len - sizeof(struct CcpMsgHeader_Wire) > sizeof(struct InstallExpressionMsg)) {
        return -2;
    }

    memcpy(msg, buf, 2 * sizeof(u32));
    buf += 2 * sizeof(u32);

    memcpy(&msg->exprs, buf, msg->num_expressions * sizeof(struct ExpressionMsg));
    buf += msg->num_expressions * sizeof(struct ExpressionMsg);
    memcpy(&msg->instrs, buf, msg->num_instructions * sizeof(struct InstructionMsg));
    buf += msg->num_expressions * sizeof(struct InstructionMsg);

    return hdr->Len - sizeof(struct CcpMsgHeader_Wire);
}

int read_update_fields_msg(
    struct CcpMsgHeader *hdr,
    struct UpdateFieldsMsg *msg,
    char *buf
) {
    if (hdr->Type != UPDATE_FIELDS) {
        return -1;
    }

    if (hdr->Len - sizeof(struct CcpMsgHeader_Wire) > sizeof(struct UpdateFieldsMsg)) {
        return -2;
    }

    memcpy(msg, buf, hdr->Len - sizeof(struct CcpMsgHeader_Wire));
    return hdr->Len - sizeof(struct CcpMsgHeader_Wire);
}
