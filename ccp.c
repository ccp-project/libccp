#include "ccp.h"
#include "serialize.h"

// ugh
#include <linux/types.h>
#include <linux/string.h> // memcpy
#include <linux/slab.h> // kmalloc

#define MAX_NUM_CONNECTIONS 100

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
    u16 sid;
    u32 first_ack;
    struct ccp_connection *conn;
    struct ccp_instruction_list *instructions;
    printk(KERN_INFO "Entering %s\n", __FUNCTION__);

    // linear search to find empty place
    // index = 0 means free/unused
    for (sid = 0; sid < MAX_NUM_CONNECTIONS; sid++) {
        conn = &ccp_active_connections[sid];
        instructions = &ccp_instruction_map[sid];
        if (conn->index == 0) {
            printk(KERN_INFO "Initializing a flow, found a free slot");
            // found a free slot
            conn->index = sid + 1;
            conn->sk = sk;
            instructions->index = sid + 1;
            instructions->num_instructions = 0;
            load_dummy_instr(instructions);
            sid = sid + 1;
            break;
        }
    }
    
    if (sid >= MAX_NUM_CONNECTIONS) {
        return 0;
    }

    // initialize send_machine state in dp
    dp->next_event_time = tcp_time_stamp; // don't use tcp_time_stamp, get time from datapath
    dp->curr_pattern_state = 0;
    dp->num_pattern_states = 0;

    // TODO initialize measurement_machine state in dp

    // send to CCP:
    // index of pointer back to this sock for IPC callback
    // first ack to expect
    first_ack = dp->get_ccp_primitives()->ack;
    ok = send_conn_create(dp, first_ack);
    if (ok < 0) {
        pr_info("failed to send create message: %d", ok);
    }

    return conn;
}

inline int ccp_set_impl(struct ccp_connection *dp, void *impl, int impl_size) {
    if (impl_size > 88) {
        return -1;
    }

    memcpy((void*) &dp->impl, impl, impl_size);
    return 0;
}

int ccp_invoke(struct ccp_connection *dp) {
    measurement_machine(dp);
    send_machine(dp);
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

    return conn->sk;
}

// after connection ends, free its slot in the ccp table
// also free slot in ccp instruction table
void ccp_connection_free(u16 sid) {
    struct ccp_connection *conn;
    struct ccp_instruction_list *instr;
    printk(KERN_INFO "Entering %s\n", __FUNCTION__);
    // bounds check
    if (sid == 0 || sid > MAX_NUM_CONNECTIONS) {
        printk(KERN_INFO "index out of bounds: %d", sid);
        return;
    }

    conn = &ccp_active_connections[sid-1];
    instr = &ccp_instruction_map[sid-1];
    if (conn->index != sid) {
        printk(KERN_INFO "index mismatch: sid %d, index %d", sid, conn->index);
        return;
    }

    conn->index = 0;
    conn->sk = NULL;
    instr->index = 0;
    // TODO: figure out if you need to free the array? unclear

    return;
}

int ccp_read_msg(
    char *buf
) {
    int ok;
    size_t i;
    struct ccp_connection *ccp;
    struct CcpMsgHeader hdr;
    struct InstallFoldMsg imsg;
    struct PatternMsg pmsg;

    ok = read_header(&hdr, buf);  
    if (ok < 0) {
        return ok;
    }

    ccp = ccp_connection_lookup(hdr.SocketId);
    if (sk == NULL) {
        return -1;
    }

    if (hdr.Type == PATTERN) {
        ok = read_pattern_msg(&hdr, &pmsg, buf);
        if (ok < 0) {
            return ok;
        }

        memset(ccp->pattern, 0, MAX_INSTRUCTIONS * sizeof(struct PatternState));
        ok = read_pattern(ccp->pattern, pmsg.pattern, pmsg.numStates);
        if (ok < 0) {
            return ok;
        }
    
        ccp->num_pattern_states = pmsg.numStates;
        ccp->curr_pattern_state = pmsg.numStates - 1;
        ccp->next_event_time = ccp->now();

        send_machine(ccp);
    } else if (hdr.Type == INSTALL_FOLD) {
        ok = read_install_fold_msg(&hdr, &imsg, buf);
        if (ok < 0) {
            return ok;
        }

        memset(ccp->fold_instructions, 0, MAX_INSTRUCTIONS * sizeof(struct Instruction64));
        for (i = 0; i < imsg.num_instrs; i++) {
            ok = read_instruction(&(ccp->fold_instructions[i]), imsg.instrs[i]);
            if (ok < 0) {
                return ok;
            }
        }
    }
}

// send create msg
int send_conn_create(
    struct ccp_connection *dp,
    u32 startSeq
) {
    char msg[BIGGEST_MSG_SIZE];
    int ok;
    int msg_size;
    
    if (dp->index < 1) {
        return -1;
    }

    printk(KERN_INFO "sending create: id=%u, startSeq=%u\n", dp->index, startSeq);

    msg_size = write_create_msg(msg, BIGGEST_MSG_SIZE, dp->index, startSeq, "reno");
    ok = dp->send_msg(msg, msg_size);
    if (ok < 0) {
        printk(KERN_INFO "create notif failed: id=%u, err=%d\n", dp->index, ok);
    }

    return ok;
}

// send datapath measurements
// acks, rtt, rin, rout
void send_measurement(
    struct ccp_connection *dp,
    struct ccp_measurement mmt
) {
    char msg[BIGGEST_MSG_SIZE];
    int ok;
    int msg_size;
    
    if (dp->index < 1) {
        return;
    }
        
    printk(KERN_INFO "sending measurement notif: id=%u, cumAck=%u, rtt=%u, loss=%u, rin=%llu, rout=%llu\n", dp->index, mmt.ack, mmt.rtt, mmt.loss, mmt.rin, mmt.rout);
    msg_size = write_measure_msg(msg, BIGGEST_MSG_SIZE, dp->index, mmt.ack, mmt.rtt, mmt.loss, mmt.rin, mmt.rout);
    // it's ok if this send fails
    // will auto-retry on the next ack
    ok = dp->send_msg(msg, msg_size);
    if (ok < 0) {
        printk(KERN_INFO "mmt notif failed: id=%u, cumAck=%u, rtt=%u, loss=%u, rin=%llu, rout=%llu\n", dp->index, mmt.ack, mmt.rtt, mmt.loss, mmt.rin, mmt.rout);
    }
}

int send_drop_notif(
    struct ccp_connection *dp,
    enum drop_type dtype
) {
    char msg[BIGGEST_MSG_SIZE];
    int ok;
    int msg_size;
    
    if (dp->index < 1) {
        pr_info("ccp_index malformed: %d\n", dp->index);
        return -1;
    }

    printk(KERN_INFO "sending drop: id=%u, ev=%d\n", dp->index, dtype);

    switch (dtype) {
        case DROP_TIMEOUT:
            msg_size = write_drop_msg(msg, BIGGEST_MSG_SIZE, dp->index, "timeout");
            break;
        case DROP_DUPACK:
            msg_size = write_drop_msg(msg, BIGGEST_MSG_SIZE, dp->index, "dupack");
            break;
        case DROP_ECN:
            msg_size = write_drop_msg(msg, BIGGEST_MSG_SIZE, dp->index, "ecn");
            break;
        default:
            printk(KERN_INFO "sending drop: unknown event? id=%u, ev=%d != {%d, %d, %d}\n", dp->index, dtype, DROP_TIMEOUT, DROP_DUPACK, DROP_ECN);
            return -2;
    }
        
    ok = dp->send_msg(msg, msg_size);
    if (ok < 0) {
        printk(KERN_INFO "drop notif failed: id=%u, ev=%d, err=%d\n", dp->index, dtype, ok);
    }

    return ok;
}
