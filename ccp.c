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

void load_dummy_instr(struct ccp_connection *ccp) {
    int i;
    // space for the array should already be allocated
    struct Register ack_state = { .type = PERM_REG, .index = ACK, .value = 0 };
    struct Register rtt_state = { .type = PERM_REG, .index = RTT, .value = 0 };
    struct Register loss_state = { .type = PERM_REG, .index = LOSS, .value = 0 };
    struct Register rin_state = { .type = PERM_REG, .index = RIN, .value = 0 };
    struct Register rout_state = { .type = PERM_REG, .index = ROUT, .value = 0 };

    // primitive state
    struct Register ack_prim = { .type = CONST_REG, .index = ACK, .value = 0 };
    struct Register rtt_prim = { .type = CONST_REG, .index = RTT, .value = 0 };
    struct Register loss_prim = { .type = CONST_REG, .index = LOSS, .value = 0 };
    struct Register rin_prim = { .type = CONST_REG, .index = RIN, .value = 0 };
    struct Register rout_prim = { .type = CONST_REG, .index = ROUT, .value = 0 };

    // extra instructions for ewma constant
    struct Register ewma_constant = { .type = CONST_REG, .index = 0, .value = 60 };

    // instruction structs
    struct Instruction64 ack_instr = { .op = MAX64, .rLeft = ack_state, .rRight = ack_prim, .rRet = ack_state };
    struct Instruction64 rtt_instr = { .op = EWMA64, .rLeft = ewma_constant, .rRight = rtt_prim, .rRet = rtt_state }; // * special - rLeft is actually rtt State reg
    struct Instruction64 loss_instr = { .op = ADD64, .rLeft = loss_state, .rRight = loss_prim, .rRet = loss_state };
    struct Instruction64 rin_instr = { .op = EWMA64, .rLeft = ewma_constant, .rRight = rin_prim, .rRet = rin_state };
    struct Instruction64 rout_instr = { .op = EWMA64, .rLeft = ewma_constant, .rRight = rout_prim, .rRet = rout_state };

    // load the instructions
    ccp->fold_instructions[0] = ack_instr;
    ccp->fold_instructions[1] = rtt_instr;
    ccp->fold_instructions[2] = loss_instr;
    ccp->fold_instructions[3] = rin_instr;
    ccp->fold_instructions[4] = rout_instr;
    ccp->num_instructions =5;
    for ( i = 0; i < MAX_PERM_REG; i++ ) {
        ccp->state_registers[i] = 0;
    }
    //printk("In load dummy instructions function\n");
}
struct ccp_connection *ccp_connection_start(struct ccp_connection *dp) {
    int ok;
    u16 sid;
    u32 first_ack;
    struct ccp_connection *conn;
    printk(KERN_INFO "Entering %s\n", __FUNCTION__);

    // linear search to find empty place
    // index = 0 means free/unused
    for (sid = 0; sid < MAX_NUM_CONNECTIONS; sid++) {
        conn = &ccp_active_connections[sid];
        if (conn->index == 0) {
            printk(KERN_INFO "Initializing a flow, found a free slot");
            // found a free slot
            conn->index = sid + 1;
            load_dummy_instr(conn);
            sid = sid + 1;
            break;
        }
    }
    
    if (sid >= MAX_NUM_CONNECTIONS) {
        return 0;
    }

    // initialize send_machine state in dp
    dp->next_event_time = dp->now(); // don't use tcp_time_stamp, get time from datapath
    dp->curr_pattern_state = 0;
    dp->num_pattern_states = 0;

    // TODO initialize measurement_machine state in dp

    // send to CCP:
    // index of pointer back to this sock for IPC callback
    // first ack to expect
    first_ack = dp->get_ccp_primitives(dp)->ack;
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
    if (ccp == NULL) {
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
            ok = read_instruction(&(ccp->fold_instructions[i]), &(imsg.instrs[i]));
            if (ok < 0) {
                return ok;
            }
        }
    }
    return ok;
}

// send create msg
int send_conn_create(
    struct ccp_connection *dp,
    u32 startSeq
) {
    char msg[BIGGEST_MSG_SIZE];
    int ok;
    int msg_size;
    
    struct CreateMsg cr = {
        .startSeq = startSeq,
        .congAlg = "reno"
    };
    if (dp->index < 1) {
        return -1;
    }

    printk(KERN_INFO "sending create: id=%u, startSeq=%u\n", dp->index, startSeq);
    msg_size = write_create_msg(msg, BIGGEST_MSG_SIZE, dp->index, cr);
    ok = dp->send_msg(msg, msg_size);
    if (ok < 0) {
        printk(KERN_INFO "create notif failed: id=%u, err=%d\n", dp->index, ok);
    }

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
    // TODO: finish this based on what gets done within the do report function 
    if (dp->index < 1) {
        ok = -1;
        return ok;
    }
    if ( num_fields > 0 ) {
    printk(KERN_INFO "num ields: %u, first field: %llu\n", num_fields, *fields);
    }
    ok = 0;
    return ok;
}

int send_drop_notif(
    struct ccp_connection *dp,
    enum drop_type dtype
) {
    char msg[BIGGEST_MSG_SIZE];
    int ok;
    int msg_size;
    struct DropMsg dr;
    
    if (dp->index < 1) {
        pr_info("ccp_index malformed: %d\n", dp->index);
        return -1;
    }

    printk(KERN_INFO "sending drop: id=%u, ev=%d\n", dp->index, dtype);

    switch (dtype) {
        case DROP_TIMEOUT:
            strcpy(dr.type, "timeout");
            msg_size = write_drop_msg(msg, BIGGEST_MSG_SIZE, dp->index, dr);
            break;
        case DROP_DUPACK:
            strcpy(dr.type, "dupack");
            msg_size = write_drop_msg(msg, BIGGEST_MSG_SIZE, dp->index, dr);
            break;
        case DROP_ECN:
            strcpy(dr.type, "ecn");
            msg_size = write_drop_msg(msg, BIGGEST_MSG_SIZE, dp->index, dr);
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


