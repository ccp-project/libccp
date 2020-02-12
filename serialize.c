#include "serialize.h"
#include "ccp.h"
#include "ccp_priv.h"
#include "ccp_error.h"

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h> // memcpy
#include <linux/slab.h> // kmalloc
#else
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

/* (type, len, socket_id) header
 * -----------------------------------
 * | Msg Type | Len (2B) | Uint32    |
 * | (2 B)    | (2 B)    | (32 bits) |
 * -----------------------------------
 * total: 6 Bytes
 */

int read_header(struct CcpMsgHeader *hdr, char *buf) {
    memcpy(hdr, buf, sizeof(struct CcpMsgHeader));

    switch (hdr->Type) {
    case INSTALL_EXPR:
        return sizeof(struct CcpMsgHeader);
    case UPDATE_FIELDS:
        return sizeof(struct CcpMsgHeader);
    case CHANGE_PROG:
        return sizeof(struct CcpMsgHeader);
    default:
        return LIBCCP_READ_INVALID_HEADER_TYPE;
    }
}

/* We only write Create, and Measure messages.
 */
int serialize_header(char *buf, int bufsize, struct CcpMsgHeader *hdr) {
    switch (hdr->Type) {
    case CREATE:
    case MEASURE:
    case READY:
        break;
    default:
        return LIBCCP_WRITE_INVALID_HEADER_TYPE;
    }

    if (bufsize < ((int)sizeof(struct CcpMsgHeader))) {
        return LIBCCP_BUFSIZE_TOO_SMALL;
    }

    memcpy(buf, hdr, sizeof(struct CcpMsgHeader));
    return sizeof(struct CcpMsgHeader);
}

int write_ready_msg(
    char *buf,
    int bufsize,
    u32 id
) {
    struct CcpMsgHeader hdr;
    int ret;
    u16 msg_len = sizeof(struct CcpMsgHeader) + sizeof(u32);

    hdr = (struct CcpMsgHeader) {
        .Type = READY,
        .Len = msg_len,
        .SocketId = 0
    };

    if (bufsize < 0) {
        return LIBCCP_BUFSIZE_NEGATIVE;
    }

    if (((u32) bufsize) < hdr.Len) {
        return LIBCCP_BUFSIZE_TOO_SMALL;
    }

    ret = serialize_header(buf, bufsize, &hdr);
    if (ret < 0) {
        return ret;
    }

    buf += ret;
    memcpy(buf, &id, sizeof(u32));
    return hdr.Len;
}

int write_create_msg(
    char *buf, 
    int bufsize,
    u32 sid, 
    struct CreateMsg cr
) {
    struct CcpMsgHeader hdr;
    int ret;
    u16 msg_len = sizeof(struct CcpMsgHeader) + sizeof(struct CreateMsg);
    
    hdr = (struct CcpMsgHeader){
        .Type = CREATE, 
        .Len = msg_len,
        .SocketId = sid,
    };

    if (bufsize < 0) {
        return LIBCCP_BUFSIZE_NEGATIVE;
    }
    
    if (((u32) bufsize) < hdr.Len) {
        return LIBCCP_BUFSIZE_TOO_SMALL;
    }
    
    ret = serialize_header(buf, bufsize, &hdr);
    if (ret < 0) {
        return ret;
    }

    buf += ret;
    memcpy(buf, &cr, hdr.Len - sizeof(struct CcpMsgHeader));
    return hdr.Len;
}

int write_measure_msg(
    char *buf,
    int bufsize,
    u32 sid, 
    u32 program_uid,
    u64 *msg_fields,
    u8 num_fields
) {
    int ret;
    struct MeasureMsg ms = {
        .program_uid = program_uid,
        .num_fields = num_fields,
    };
    
    // 4 bytes for num_fields (u32) and 4 for program_uid = 8
    u16 msg_len = sizeof(struct CcpMsgHeader) + 8 + ms.num_fields * sizeof(u64);
    struct CcpMsgHeader hdr = {
        .Type = MEASURE, 
        .Len = msg_len,
        .SocketId = sid,
    };
    
    // copy message fields into MeasureMsg struct
    if (msg_fields) {
      memcpy(ms.fields, msg_fields, ms.num_fields * sizeof(u64));
    }

    if (bufsize < 0) {
        return LIBCCP_BUFSIZE_NEGATIVE;
    }

    if (((u32) bufsize) < hdr.Len) {
        return LIBCCP_BUFSIZE_TOO_SMALL;
    }

    ret = serialize_header(buf, bufsize, &hdr);
    if (ret < 0) {
        return ret;
    }

    buf += ret;
    memcpy(buf, &ms, hdr.Len - sizeof(struct CcpMsgHeader));
    return hdr.Len;
}

int read_install_expr_msg_hdr(
    struct ccp_datapath *datapath,
    struct CcpMsgHeader *hdr,
    struct InstallExpressionMsgHdr *expr_msg_info,
    char *buf
) {
    if (hdr->Type != INSTALL_EXPR) {
        return LIBCCP_INSTALL_TYPE_MISMATCH;
    } 

    if (expr_msg_info->num_expressions > MAX_EXPRESSIONS) {
        libccp_warn("Program to install has too many expressions: %u\n", expr_msg_info->num_expressions);
        return LIBCCP_INSTALL_TOO_MANY_EXPR;
    }

    if (expr_msg_info->num_instructions > MAX_INSTRUCTIONS) {
        libccp_warn("Program to install has too many instructions: %u\n", expr_msg_info->num_instructions);
        return LIBCCP_INSTALL_TOO_MANY_INSTR;
    }
    memcpy(expr_msg_info, buf, sizeof(struct InstallExpressionMsgHdr));
    return sizeof(struct InstallExpressionMsgHdr);

}

int check_update_fields_msg(
    struct ccp_datapath *datapath,
    struct CcpMsgHeader *hdr,
    u32 *num_updates,
    char *buf
) {
    if (hdr->Type != UPDATE_FIELDS) {
        libccp_warn("check_update_fields_msg: hdr.Type != UPDATE_FIELDS")
        return LIBCCP_UPDATE_TYPE_MISMATCH;
    }

    *num_updates = (u32)*buf;
    if (*num_updates > MAX_MUTABLE_REG) {
        libccp_warn("Too many updates!: %u\n", *num_updates);
        return LIBCCP_UPDATE_TOO_MANY;
    }
    return sizeof(u32);
}

int read_change_prog_msg(
    struct ccp_datapath *datapath,
    struct CcpMsgHeader *hdr,
    struct ChangeProgMsg *change_prog,
    char *buf
) {
    if (hdr->Type != CHANGE_PROG) {
        libccp_warn("read_change_prog_msg: hdr.Type != CHANGE_PROG")
        return LIBCCP_CHANGE_TYPE_MISMATCH;
    }

    memcpy(change_prog, buf, sizeof(struct ChangeProgMsg));
    if (change_prog->num_updates > MAX_MUTABLE_REG) {
        libccp_warn("Too many updates sent with change prog: %u\n", change_prog->num_updates);
        return LIBCCP_CHANGE_TOO_MANY;
    }
    return sizeof(struct ChangeProgMsg);
}
