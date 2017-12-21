#include "serialize.h"

// ugh
#include <linux/types.h>
#include <linux/string.h> // memcpy
#include <linux/slab.h> // kmalloc

/* We only read Pattern and InstallFold messages.
 */
int read_header(struct CcpMsgHeader *hdr, char *buf) {
    memcpy(hdr, buf, sizeof(struct CcpMsgHeader));
    switch (hdr->Type) {
    case PATTERN:
    case INSTALL_FOLD:
        return sizeof(struct CcpMsgHeader);
    default:
        return -1;
    }
}

/* We only write Create, Measure, and Drop messages.
 */
int serialize_header(char *buf, int bufsize, struct CcpMsgHeader *hdr) {
    switch (hdr->Type) {
    case CREATE:
    case MEASURE:
    case DROP:
        break;
    default:
        return -1;
    }

    if (bufsize < sizeof(struct CcpMsgHeader)) {
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
    int ret, ok;
    int congAlgLen = strlen(cr.congAlg) + 1;
    struct CcpMsgHeader hdr = {
        .Type = CREATE, 
        .Len = 10 + congAlgLen, 
        .SocketId = sid,
    };
    
    if (bufsize < hdr.Len) {
        return -2;
    }
    
    ok = serialize_header(buf, bufsize, &hdr);
    if (ok < 0) {
        return ok;
    }

    buf += ok;
    ret = ok;
    memcpy(buf, &cr, hdr.Len - 6);
    return hdr.Len;
}

int write_measure_msg(
    char *buf,
    int bufsize,
    u32 sid, 
    struct MeasureMsg ms
) {
    int ok;
    size_t ret;
    struct CcpMsgHeader hdr = {
        .Type = MEASURE, 
        .Len = 10 + ms.num_fields * sizeof(u64),
        .SocketId = sid,
    };

    if (bufsize < hdr.Len) {
        return -2;
    }

    ok = serialize_header(buf, bufsize, &hdr);
    if (ok < 0) {
        return ok;
    }

    buf += ok;
    ret = ok;
    memcpy(buf, &ms, hdr.Len - 6);
    return hdr.Len;
}

int read_pattern_msg(
    struct CcpMsgHeader *hdr, 
    struct PatternMsg *msg,
    char *buf
) {
    int ok;
    ok = read_header(hdr, buf);
    if (ok < 0) {
        return ok;
    }

    buf += ok;
    if (hdr->Type != PATTERN) {
        return -1;
    }

    memcpy(msg, buf, hdr->Len - 6);
    return hdr->Len;
}

int read_install_fold_msg(
    struct CcpMsgHeader *hdr, 
    struct InstallFoldMsg *msg,
    char *buf 
) {
    int ok;
    ok = read_header(hdr, buf);
    if (ok < 0) {
        return ok;
    }

    buf += ok;
    if (hdr->Type != INSTALL_FOLD) {
        return -1;
    }

    memcpy(msg, buf, hdr->Len - 6);
    return hdr->Len;
}
