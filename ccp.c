#include "ccp.h"
#include "serialize.h"
#include "ccp_priv.h"

#ifdef __USRLIB__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#else
#include <linux/types.h>
#include <linux/string.h> // memcpy
#include <linux/slab.h> // kmalloc
#endif

#define MAX_NUM_CONNECTIONS 100

int send_conn_create(
    struct ccp_datapath *datapath,
    struct ccp_connection *conn
);

// array of active connections
struct ccp_connection* ccp_active_connections;
struct ccp_datapath* datapath;

int ccp_init(struct ccp_datapath *dp) {
    // check that dp is properly filled in.
    if (dp == NULL ||
        dp->set_cwnd == NULL ||
        dp->set_rate_abs == NULL ||
        dp->set_rate_rel == NULL ||
        dp->send_msg == NULL ||
        dp->now == NULL ||
        dp->after_usecs == NULL
    ) {
        return -1;
    }

    datapath = __MALLOC__(sizeof(struct ccp_datapath));
    if (!datapath) {
        return -1;
    }

    // copy function pointers into datapath
    datapath->set_cwnd           = dp->set_cwnd;
    datapath->set_rate_abs       = dp->set_rate_abs;
    datapath->set_rate_rel       = dp->set_rate_rel;
    datapath->send_msg           = dp->send_msg;
    datapath->now                = dp->now;
    datapath->after_usecs        = dp->after_usecs;
    datapath->impl               = dp->impl;

    ccp_active_connections = __MALLOC__(MAX_NUM_CONNECTIONS * sizeof(struct ccp_connection));
    if (!ccp_active_connections) {
        __FREE__(datapath);
        return -1;
    }

    memset(ccp_active_connections, 0, MAX_NUM_CONNECTIONS * sizeof(struct ccp_connection));

    return 0;
}

void ccp_free(void) {
    __FREE__(ccp_active_connections);
    __FREE__(datapath);
    ccp_active_connections = NULL;
    datapath = NULL;
}

struct ccp_connection *ccp_connection_start(void *impl, struct ccp_datapath_info *flow_info) {
    int ok;
    u16 sid;
    struct ccp_connection *conn;

    // scan to find empty place
    // index = 0 means free/unused
    for (sid = 0; sid < MAX_NUM_CONNECTIONS; sid++) {
        conn = &ccp_active_connections[sid];
        if (conn->index == 0) {
            // found a free slot
            conn->index = sid + 1;
            sid = sid + 1;
            break;
        }
    }
    
    if (sid >= MAX_NUM_CONNECTIONS) {
        return NULL;
    }

    conn->impl = impl;
    memcpy(&conn->flow_info, flow_info, sizeof(struct ccp_datapath_info));

    init_ccp_priv_state(conn);

    // send to CCP:
    // index of pointer back to this sock for IPC callback
    ok = send_conn_create(datapath, conn);
    if (ok < 0) {
        PRINT("failed to send create message: %d", ok);
    }

    return conn;
}

__INLINE__ void *ccp_get_global_impl(void) {
    return datapath->impl;
}

__INLINE__ int ccp_set_global_impl(void *ptr) {
    datapath->impl = ptr;
    return 0;
}

__INLINE__ void *ccp_get_impl(struct ccp_connection *conn) {
    return conn->impl;
}

__INLINE__ int ccp_set_impl(struct ccp_connection *conn, void *ptr) {
    conn->impl = ptr;
    return 0;
}

// TODO: make this return an int for error purposes
int ccp_invoke(struct ccp_connection *conn) {
    int ok = 0;
    struct ccp_priv_state *state = get_ccp_priv_state(conn);
    if (state->num_pattern_states == 0) {
        // try contacting the CCP again
        // index of pointer back to this sock for IPC callback
        ok = send_conn_create(datapath, conn);
        if (ok < 0) {
            //pr_info("failed to send create message: %d", ok);
        }

        return ok;
    }

    // TODO measurement_machine and send_machine should return error ints
    measurement_machine(conn);
    send_machine(conn);
    return ok;
}

// lookup existing connection by its ccp socket id
// return NULL on error
struct ccp_connection *ccp_connection_lookup(u16 sid) {
    struct ccp_connection *conn;
    // bounds check
    if (sid == 0 || sid > MAX_NUM_CONNECTIONS) {
        PRINT("index out of bounds: %d", sid);
        return NULL;
    }

    conn = &ccp_active_connections[sid-1];
    if (conn->index != sid) {
        PRINT("index mismatch: sid %d, index %d", sid, conn->index);
        return NULL;
    }

    return conn;
}

// after connection ends, free its slot in the ccp table
// also free slot in ccp instruction table
void ccp_connection_free(u16 sid) {
    struct ccp_connection *conn;
    PRINT("Entering %s\n", __FUNCTION__);
    // bounds check
    if (sid == 0 || sid > MAX_NUM_CONNECTIONS) {
        PRINT("index out of bounds: %d", sid);
        return;
    }

    conn = &ccp_active_connections[sid-1];
    if (conn->index != sid) {
        PRINT("index mismatch: sid %d, index %d", sid, conn->index);
        return;
    }

    conn->index = 0;
    // TODO: figure out if you need to free the array? unclear

    return;
}

int ccp_read_msg(
    char *buf,
    int bufsize
) {
    int ok;
    size_t i;
    struct ccp_connection *conn;
    struct ccp_priv_state *state;
    struct CcpMsgHeader hdr;
    struct InstallFoldMsg imsg;
    struct PatternMsg pmsg;

    ok = read_header(&hdr, buf);  
    if (ok < 0) {
        return ok;
    }

    if (hdr.Len > bufsize) {
        return -1;
    }

    conn = ccp_connection_lookup(hdr.SocketId);
    if (conn == NULL) {
        return -1;
    }

    state = get_ccp_priv_state(conn);

    if (hdr.Type == PATTERN) {
        ok = read_pattern_msg(&hdr, &pmsg, buf);
        if (ok < 0) {
            return ok;
        }

        memset(state->pattern, 0, MAX_INSTRUCTIONS * sizeof(struct PatternState));
        ok = read_pattern(state->pattern, pmsg.pattern, pmsg.numStates);
        if (ok < 0) {
            return ok;
        }
    
        state->num_pattern_states = pmsg.numStates;
        state->curr_pattern_state = pmsg.numStates - 1;
        state->next_event_time = datapath->now();

        send_machine(conn);
    } else if (hdr.Type == INSTALL_FOLD) {
        ok = read_install_fold_msg(&hdr, &imsg, buf);
        if (ok < 0) {
            return ok;
        }

        memset(state->fold_instructions, 0, MAX_INSTRUCTIONS * sizeof(struct Instruction64));
        for (i = 0; i < imsg.num_instrs; i++) {
            ok = read_instruction(&(state->fold_instructions[i]), &(imsg.instrs[i]));
            if (ok < 0) {
                return ok;
            }
        }

        state->num_instructions = imsg.num_instrs;
        reset_state(state);
    }

    return ok;
}

// send create msg
int send_conn_create(
    struct ccp_datapath *datapath,
    struct ccp_connection *conn
) {
    int ok;
    char msg[BIGGEST_MSG_SIZE];
    int msg_size;
    struct CreateMsg cr = {
        .init_cwnd = conn->flow_info.init_cwnd,
        .mss = conn->flow_info.mss,
        .src_ip = conn->flow_info.src_ip,
        .src_port = conn->flow_info.src_port,
        .dst_ip = conn->flow_info.dst_ip,
        .dst_port = conn->flow_info.dst_port,
    };

    if (conn->index < 1) {
        return -1;
    }

    msg_size = write_create_msg(msg, BIGGEST_MSG_SIZE, conn->index, cr);
    ok = datapath->send_msg(datapath, conn, msg, msg_size);
    return ok;
}

// send datapath measurements
// acks, rtt, rin, rout
int send_measurement(
    struct ccp_connection *conn,
    u64 *fields,
    u8 num_fields
) {
    int ok;
    char msg[BIGGEST_MSG_SIZE];
    int msg_size;
    struct MeasureMsg ms = {
        .num_fields = num_fields,
    };

    memcpy(ms.fields, fields, ms.num_fields * sizeof(u64));

    if (conn->index < 1) {
        ok = -1;
        return ok;
    }

    msg_size = write_measure_msg(msg, BIGGEST_MSG_SIZE, conn->index, ms);
    ok = datapath->send_msg(datapath, conn, msg, msg_size);
    return ok;
}
