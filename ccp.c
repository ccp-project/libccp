#include "ccp.h"
#include "serialize.h"
#include "ccp_priv.h"

#ifdef __USRLIB__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h> // for mutex
#ifdef __APPLE__
#include "spinlock.h"
#endif
#else
#include <linux/types.h>
#include <linux/string.h> // memcpy
#include <linux/slab.h> // kmalloc
#include <linux/spinlock.h> // spinlock
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

DEFINE_LOCK(ccp_state_lock);

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

    INIT_LOCK(&ccp_state_lock);

    return 0;
}

void ccp_free(void) {
    __FREE__(ccp_active_connections);
    __FREE__(datapath);
    DESTROY_LOCK(&ccp_state_lock);
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
        
    get_ccp_priv_state(conn)->sent_create = true;

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
    ACQUIRE_LOCK(&ccp_state_lock);
    ok = state_machine(conn);
    RELEASE_LOCK(&ccp_state_lock);
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

    msg_size = write_measure_msg(msg, REPORT_MSG_SIZE, conn->index, 0, 0);
    ok = datapath->send_msg(datapath, conn, msg, msg_size);
    if (ok < 0) {
        PRINT("error sending close message: %d", ok);
    }

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
    struct InstallExpressionMsg emsg;
    struct UpdateFieldsMsg fields_msg;

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

    state = get_ccp_priv_state(conn);
    if (hdr.Type == INSTALL_EXPR) {
        memset(&emsg, 0, sizeof(struct InstallExpressionMsg));
        ok = read_install_expr_msg(&hdr, &emsg, buf + ok);
        if (ok < 0) {
            PRINT("could not read install expression msg: %d\n", ok);
            return -6;
        }

        ACQUIRE_LOCK(&ccp_state_lock);
        memset(state->expressions, 0, MAX_EXPRESSIONS * sizeof(struct Expression));
        memset(state->fold_instructions, 0, MAX_INSTRUCTIONS * sizeof(struct Instruction64));
    
        state->num_expressions = emsg.num_expressions;
        state->num_instructions = emsg.num_instructions;

        // parse the expressions 
        for (i=0; i<state->num_expressions; i++) {
            ok = read_expression(&(state->expressions[i]), &(emsg.exprs[i]));
            if (ok < 0) {
                PRINT("could not read expression\n");
                RELEASE_LOCK(&ccp_state_lock);
                return -7;
            }
        }

        // parse the instructions
        for (i=0; i<state->num_instructions; i++) {
            ok = read_instruction(&(state->fold_instructions[i]), &(emsg.instrs[i]));
            if (ok < 0) {
                PRINT("could not read instruction %lu: %d\n", i, ok);
                RELEASE_LOCK(&ccp_state_lock);
                return -8;
            }
        }

        // call reset state to initialize all variables
        reset_state(state);
        init_register_state(state);
        reset_time(state);
        DBG_PRINT("installed new program with %d expressions and %d instructions\n", state->num_expressions, state->num_instructions);
        RELEASE_LOCK(&ccp_state_lock);
    } else if (hdr.Type == UPDATE_FIELDS) {
        ok = read_update_fields_msg(&hdr, &fields_msg, buf + ok);
        if (ok < 0) {
            PRINT("could not read update fields msg\n");
            return -9;
        }

        ACQUIRE_LOCK(&ccp_state_lock);
        for (i=0; i<fields_msg.num_updates; i++) {
            update_register(conn, state, &(fields_msg.updates[i]));
        }
        RELEASE_LOCK(&ccp_state_lock);
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

    msg_size = write_measure_msg(msg, REPORT_MSG_SIZE, conn->index, fields, num_fields);
    DBG_PRINT("In %s\n", __FUNCTION__);
    ok = datapath->send_msg(datapath, conn, msg, msg_size);
    return ok;
}
