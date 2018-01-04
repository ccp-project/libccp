#include "ccp.h"
#include "serialize.h"
#include "ccp_priv.h"

// ugh
#include <linux/types.h>
#include <linux/string.h> // memcpy
#include <linux/slab.h> // kmalloc

#define MAX_NUM_CONNECTIONS 100

int send_conn_create(
    struct ccp_connection *dp
);

// array of active connections
struct ccp_connection* ccp_active_connections;

int ccp_init_connection_map(void) {
    ccp_active_connections = kmalloc(MAX_NUM_CONNECTIONS * sizeof(struct ccp_connection), GFP_KERNEL);
    if (!ccp_active_connections) {
        return -1;
    }

    memset(ccp_active_connections, 0, MAX_NUM_CONNECTIONS * sizeof(struct ccp_connection));

    return 0;
}

void ccp_free_connection_map(void) {
    kfree(ccp_active_connections);
    ccp_active_connections = NULL;
}

struct ccp_connection *ccp_connection_start(struct ccp_connection *dp) {
    int ok;
    u16 sid;
    struct ccp_connection *conn;

    // check that dp is properly filled in.
    if (dp == NULL ||
        dp->set_cwnd == NULL ||
        dp->set_rate_abs == NULL ||
        dp->set_rate_rel == NULL ||
        dp->get_ccp_primitives == NULL ||
        dp->send_msg == NULL ||
        dp->now == NULL ||
        dp->after_usecs == NULL
    ) {
        return NULL;
    }

    // scan to find empty place
    // index = 0 means free/unused
    for (sid = 0; sid < MAX_NUM_CONNECTIONS; sid++) {
        conn = &ccp_active_connections[sid];
        if (conn->index == 0) {
            // found a free slot
            conn->index = sid + 1;
            //load_dummy_instr(conn);
            sid = sid + 1;
            break;
        }
    }
    
    if (sid >= MAX_NUM_CONNECTIONS) {
        return NULL;
    }

    // copy function pointers from dp into conn
    conn->set_cwnd           = dp->set_cwnd;
    conn->set_rate_abs       = dp->set_rate_abs;
    conn->set_rate_rel       = dp->set_rate_rel;
    conn->get_ccp_primitives = dp->get_ccp_primitives;
    conn->send_msg           = dp->send_msg;
    conn->now                = dp->now;
    conn->after_usecs        = dp->after_usecs;
    conn->impl               = dp->impl;

    init_ccp_priv_state(conn);

    // send to CCP:
    // index of pointer back to this sock for IPC callback
    ok = send_conn_create(conn);
    if (ok < 0) {
        pr_info("failed to send create message: %d", ok);
    }

    return conn;
}

inline void *ccp_get_impl(struct ccp_connection *dp) {
    return dp->impl;
}

inline int ccp_set_impl(struct ccp_connection *dp, void *ptr) {
    dp->impl = ptr;
    return 0;
}

// TODO: make this return an int for error purposes
int ccp_invoke(struct ccp_connection *dp) {
    measurement_machine(dp);
    send_machine(dp);
    return 0; // NOT OKAY
}

// lookup existing connection by its ccp socket id
// return NULL on error
struct ccp_connection *ccp_connection_lookup(u16 sid) {
    struct ccp_connection *conn;
    //printk(KERN_INFO "Entering %s\n", __FUNCTION__);
    // bounds check
    if (sid == 0 || sid > MAX_NUM_CONNECTIONS) {
        printk(KERN_INFO "index out of bounds: %d", sid);
        return NULL;
    }

    conn = &ccp_active_connections[sid-1];
    if (conn->index != sid) {
        printk(KERN_INFO "index mismatch: sid %d, index %d", sid, conn->index);
        return NULL;
    }

    return conn;
}

// after connection ends, free its slot in the ccp table
// also free slot in ccp instruction table
void ccp_connection_free(u16 sid) {
    struct ccp_connection *conn;
    printk(KERN_INFO "Entering %s\n", __FUNCTION__);
    // bounds check
    if (sid == 0 || sid > MAX_NUM_CONNECTIONS) {
        printk(KERN_INFO "index out of bounds: %d", sid);
        return;
    }

    conn = &ccp_active_connections[sid-1];
    if (conn->index != sid) {
        printk(KERN_INFO "index mismatch: sid %d, index %d", sid, conn->index);
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
    struct ccp_connection *ccp;
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

    ccp = ccp_connection_lookup(hdr.SocketId);
    if (ccp == NULL) {
        return -1;
    }

    state = get_ccp_priv_state(ccp);

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
        state->next_event_time = ccp->now();

        send_machine(ccp);
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
    struct ccp_connection *dp
) {
    int ok;
    char msg[BIGGEST_MSG_SIZE];
    int msg_size;
    struct CreateMsg cr = {
        .congAlg = "reno"
    };

    if (dp->index < 1) {
        return -1;
    }

    msg_size = write_create_msg(msg, BIGGEST_MSG_SIZE, dp->index, cr);
    ok = dp->send_msg(msg, msg_size);
    return ok;
}

// send datapath measurements
// acks, rtt, rin, rout
int send_measurement(
    struct ccp_connection *dp,
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

    if (dp->index < 1) {
        ok = -1;
        return ok;
    }

    msg_size = write_measure_msg(msg, BIGGEST_MSG_SIZE, dp->index, ms);
    ok = dp->send_msg(msg, msg_size);
    return ok;
}
