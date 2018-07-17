#include "ccp.h"
#include "serialize.h"
#include "ccp_priv.h"

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h> // memcpy
#include <linux/slab.h> // kmalloc
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

#define MAX_NUM_CONNECTIONS 4096
#define CREATE_TIMEOUT_US 1000000 // 1 second

int send_conn_create(
    struct ccp_datapath *datapath,
    struct ccp_connection *conn
);

// array of active connections
struct ccp_connection* ccp_active_connections;
struct ccp_datapath* datapath;

int ccp_init(struct ccp_datapath *dp) {
    // check that dp is properly filled in.
    if (
        dp                ==  NULL  ||
        dp->set_cwnd      ==  NULL  ||
        dp->set_rate_abs  ==  NULL  ||
        dp->set_rate_rel  ==  NULL  ||
        dp->send_msg      ==  NULL  ||
        dp->now           ==  NULL  ||
        dp->since_usecs   ==  NULL  ||
        dp->after_usecs   ==  NULL
    ) {
        return -1;
    }

    datapath = (struct ccp_datapath*)__MALLOC__(sizeof(struct ccp_datapath));
    if (!datapath) {
        return -1;
    }

    // copy function pointers into datapath
    datapath->set_cwnd           = dp->set_cwnd;
    datapath->set_rate_abs       = dp->set_rate_abs;
    datapath->set_rate_rel       = dp->set_rate_rel;
    datapath->send_msg           = dp->send_msg;
    datapath->now                = dp->now;
    datapath->since_usecs        = dp->since_usecs;
    datapath->after_usecs        = dp->after_usecs;
    datapath->impl               = dp->impl;

    datapath->time_zero = datapath->now();

    ccp_active_connections = (struct ccp_connection*)__MALLOC__(MAX_NUM_CONNECTIONS * sizeof(struct ccp_connection));
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
        return conn;
    }
    
    struct ccp_priv_state *state = get_ccp_priv_state(conn);
    state->sent_create = true;
    INIT_LOCK(&state->lock);

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

int ccp_invoke(struct ccp_connection *conn) {
    int ok = 0;
    struct ccp_priv_state *state = get_ccp_priv_state(conn);
    if (!(state->sent_create)) {
        // try contacting the CCP again
        // index of pointer back to this sock for IPC callback
        ok = send_conn_create(datapath, conn);
        if (ok < 0) {
            PRINT("failed to send create message: %d", ok);
        }
        return ok;
    }
    ACQUIRE_LOCK(&state->lock);
    ok = state_machine(conn);
    RELEASE_LOCK(&state->lock);
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
    int msg_size, ok;
    struct ccp_connection *conn;
    char msg[REPORT_MSG_SIZE];
    struct ccp_priv_state* state;

    DBG_PRINT("Entering %s\n", __FUNCTION__);
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

    msg_size = write_measure_msg(msg, REPORT_MSG_SIZE, 0, conn->index, 0, 0);
    ok = datapath->send_msg(datapath, conn, msg, msg_size);
    if (ok < 0) {
        PRINT("error sending close message: %d", ok);
    }

    state = get_ccp_priv_state(conn);
    DESTROY_LOCK(&state->lock);

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
    struct InstallExpressionMsgHdr expr_msg_info;
    struct InstructionMsg *current_instr; // cast message memory to this, and copy over fields
    u32 num_updates;
    struct UpdateField *current_update;
    char* msg_ptr;

    ok = read_header(&hdr, buf);  
    if (ok < 0) {
        PRINT("read header failed: %d", ok);
        return -1;
    }

    if (bufsize < 0) {
        PRINT("negative bufsize: %d", bufsize);
        return -2;
    }
    if (hdr.Len > ((u32) bufsize)) {
        PRINT("message size wrong: %u > %d\n", hdr.Len, bufsize);
        return -3;
    }

    if (hdr.Len > BIGGEST_MSG_SIZE) {
        PRINT("message too long: %u > %d\n", hdr.Len, BIGGEST_MSG_SIZE);
        return -4;
    }

    conn = ccp_connection_lookup(hdr.SocketId);
    if (conn == NULL) {
        PRINT("unknown connection: %u\n", hdr.SocketId);
        return -5;
    }
    msg_ptr = buf + ok;

    state = get_ccp_priv_state(conn);
    if (hdr.Type == INSTALL_EXPR) {
        memset(&expr_msg_info, 0, sizeof(struct InstallExpressionMsgHdr));
        ok = read_install_expr_msg_hdr(&hdr, &expr_msg_info, msg_ptr);
        if (ok < 0) {
            PRINT("could not read install expression msg header: %d\n", ok);
            return -6;
        }
        msg_ptr += ok;

        ACQUIRE_LOCK(&state->lock);
        memset(state->expressions, 0, MAX_EXPRESSIONS * sizeof(struct Expression));
        memset(state->fold_instructions, 0, MAX_INSTRUCTIONS * sizeof(struct Instruction64));
    
        state->program_uid = expr_msg_info.program_uid;
        state->num_expressions = expr_msg_info.num_expressions;
        state->num_instructions = expr_msg_info.num_instructions;

        // copy expressions directly from buffer (memory layout is the same)
        memcpy(state->expressions, msg_ptr, state->num_expressions * sizeof(struct ExpressionMsg));
        msg_ptr += state->num_expressions * sizeof(struct ExpressionMsg);

        // parse the instructions
        for (i=0; i<state->num_instructions; i++) {
            current_instr = (struct InstructionMsg*)(msg_ptr);
            ok = read_instruction(&(state->fold_instructions[i]), current_instr);
            if (ok < 0) {
                PRINT("could not read instruction # %lu: %d\n", i, ok);
                RELEASE_LOCK(&state->lock);
                return -8;
            }
            msg_ptr += sizeof(struct InstructionMsg);
        }

        // call reset state to initialize all variables
        reset_state(state);
        init_register_state(state);
        reset_time(state);
        DBG_PRINT("installed new program (uid=%d) with %d expressions and %d instructions\n", state->program_uid, state->num_expressions, state->num_instructions);
        RELEASE_LOCK(&state->lock);

    } else if (hdr.Type == UPDATE_FIELDS) {
        ok = check_update_fields_msg(&hdr, &num_updates, msg_ptr);
        msg_ptr += ok;
        if (ok < 0) {
            PRINT("Update fields message failed: %d\n", ok);
            return -9;
        }
        ACQUIRE_LOCK(&state->lock);
        for (i=0; i<num_updates; i++) {
            current_update = (struct UpdateField*)(msg_ptr);
            update_register(conn, state, current_update);
            msg_ptr += sizeof(struct UpdateField);
        }
        RELEASE_LOCK(&state->lock);
    }

    return ok;
}

// send create msg
int send_conn_create(
    struct ccp_datapath *datapath,
    struct ccp_connection *conn
) {
    int ok;
    char msg[REPORT_MSG_SIZE];
    int msg_size;
    struct ccp_priv_state* state = get_ccp_priv_state(conn);
    struct CreateMsg cr = {
        .init_cwnd = conn->flow_info.init_cwnd,
        .mss = conn->flow_info.mss,
        .src_ip = conn->flow_info.src_ip,
        .src_port = conn->flow_info.src_port,
        .dst_ip = conn->flow_info.dst_ip,
        .dst_port = conn->flow_info.dst_port,
    };

    if (
        conn->last_create_msg_sent != 0 &&
        datapath->since_usecs(conn->last_create_msg_sent) < CREATE_TIMEOUT_US
    ) {
        state->sent_create = true;
        return 0;
    }

    if (conn->index < 1) {
        return -1;
    }

    conn->last_create_msg_sent = datapath->now();
    msg_size = write_create_msg(msg, REPORT_MSG_SIZE, conn->index, cr);
    ok = datapath->send_msg(datapath, conn, msg, msg_size);
    return ok;
}

// send datapath measurements
// acks, rtt, rin, rout
int send_measurement(
    struct ccp_connection *conn,
    u32 program_uid,
    u64 *fields,
    u8 num_fields
) {
    int ok;
    char msg[REPORT_MSG_SIZE];
    int msg_size;
    if (conn->index < 1) {
        ok = -1;
        return ok;
    }

    msg_size = write_measure_msg(msg, REPORT_MSG_SIZE, conn->index, program_uid, fields, num_fields);
    DBG_PRINT("In %s\n", __FUNCTION__);
    ok = datapath->send_msg(datapath, conn, msg, msg_size);
    return ok;
}
