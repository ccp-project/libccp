#include "ccp.h"
#include "serialize.h"
#include "ccp_priv.h"
#include "ccp_error.h"

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h> // memcpy
#include <linux/slab.h> // kmalloc
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

#define CREATE_TIMEOUT_US 100000 // 100 ms

/* CCP Datapath Connection Map
 *
 * When we receive a message from userspace CCP, we are not
 * in the flow context and need to access state (e.g. primitives) for
 * the appropriate connection.
 *
 * So, we maintain a map of ccp sock_id -> flow state information.
 * This flow state information is the API that datapaths must implement to support CCP.
 */

/* Drop log messages if no log output is defined.
 */
void __INLINE__ null_log(struct ccp_datapath *dp, enum ccp_log_level level, const char* msg, int msg_size) {
    (void)(dp);
    (void)(level);
    (void)(msg);
    (void)(msg_size);
}

/*
 * IMPORTANT: caller must allocate..
 * 1. ccp_datapath
 * 2. ccp_datapath.ccp_active_connections with enough space for `max_connections` `ccp_connections`
 * ccp_init has no way of checking if enough space has been allocated, so any memory oob errors are
 * likely a result not allocating enough space
 *
 * All calls to libccp require a ccp_datapath structure. This function should be called before any
 * other libccp functions and ensures (as much as possible) that the datapath structure has been
 * initialized correctly. A valid ccp_datapath must contain:
 *   1. 6 callback functions: set_cwnd, set_rate_abs, send_msg, now, since_users, after_usecs
 *   2. an optional callback function for logging
 *   3. a pointer to memory allocated for a list of ccp_connection objects
 *      (as well as the number of connections it can hold)
 *   4. a fallback timeout value in microseconds (must be > 0)
 *
 * This function returns 0 if the structure has been initialized correctly and a negative value
 * with an error code otherwise. 
 */
int ccp_init(struct ccp_datapath *datapath) {
    if (
        datapath                         ==  NULL  ||
        datapath->set_cwnd               ==  NULL  ||
        datapath->set_rate_abs           ==  NULL  ||
        datapath->send_msg               ==  NULL  ||
        datapath->now                    ==  NULL  ||
        datapath->since_usecs            ==  NULL  ||
        datapath->after_usecs            ==  NULL  ||
        datapath->ccp_active_connections ==  NULL  ||
        datapath->max_connections        ==  0     ||
        datapath->max_programs           ==  0     ||
        datapath->fto_us                 ==  0
    ) {
        return LIBCCP_MISSING_ARG;
    }

    datapath->programs = __CALLOC__(datapath->max_programs, sizeof(struct DatapathProgram));

    if (datapath->log == NULL) {
        datapath->log = &null_log;
    }

    libccp_trace("ccp_init");

    datapath->time_zero = datapath->now();
    datapath->last_msg_sent = 0;
    datapath->_in_fallback = false;

    return LIBCCP_OK;
}

void ccp_free(struct ccp_datapath *datapath) {
  __FREE__(datapath->programs);
}

void ccp_conn_create_success(struct ccp_priv_state *state) {
    state->sent_create = true;
}

struct ccp_connection *ccp_connection_start(struct ccp_datapath *datapath, void *impl, struct ccp_datapath_info *flow_info) {
    int ret;
    u16 sid;
    struct ccp_connection *conn;

    // scan to find empty place
    // index = 0 means free/unused
    for (sid = 0; sid < datapath->max_connections; sid++) {
        conn = &datapath->ccp_active_connections[sid];
        if (CAS(&(conn->index), 0, sid+1)) {
            sid = sid + 1;
            break;
        }
    }
    
    if (sid >= datapath->max_connections) {
        return NULL;
    }

    conn->impl = impl;
    memcpy(&conn->flow_info, flow_info, sizeof(struct ccp_datapath_info));

    init_ccp_priv_state(datapath, conn);

    // send to CCP:
    // index of pointer back to this sock for IPC callback
    ret = send_conn_create(datapath, conn);
    if (ret < 0) {
        if (!datapath->_in_fallback) {
            libccp_warn("failed to send create message: %d\n", ret);
        }
        return conn;
    }

    struct ccp_priv_state *state = get_ccp_priv_state(conn);
    ccp_conn_create_success(state);

    return conn;
}

__INLINE__ void *ccp_get_impl(struct ccp_connection *conn) {
    return conn->impl;
}

__INLINE__ void ccp_set_impl(struct ccp_connection *conn, void *ptr) {
    conn->impl = ptr;
}

int ccp_invoke(struct ccp_connection *conn) {
    int i;
    int ret = 0;
    struct ccp_priv_state *state;
    struct ccp_datapath *datapath;

    if (conn == NULL) {
        return LIBCCP_NULL_ARG;
    }

    datapath = conn->datapath;

    if (_check_fto(datapath)) {
        return LIBCCP_FALLBACK_TIMED_OUT;
    }

    state = get_ccp_priv_state(conn);

    if (!(state->sent_create)) {
        // try contacting the CCP again
        // index of pointer back to this sock for IPC callback
        libccp_trace("%s retx create message\n", __FUNCTION__);
        ret = send_conn_create(datapath, conn);
        if (ret < 0) {
            if (!datapath->_in_fallback) {
                libccp_warn("failed to retx create message: %d\n", ret);
            }
        } else {
            ccp_conn_create_success(state);
        }

        // TODO should we really be returning here? shouldn't we just keep going?
        return LIBCCP_OK;
    }

    // set cwnd and rate registers to what they are in the datapath
    libccp_trace("primitives (cwnd, rate): (" FMT_U32 ", " FMT_U64 ")\n", conn->prims.snd_cwnd, conn->prims.snd_rate);
    state->registers.impl_registers[CWND_REG] = (u64)conn->prims.snd_cwnd;
    state->registers.impl_registers[RATE_REG] = (u64)conn->prims.snd_rate;
    
    if (state->staged_program_index >= 0) {
        // change the program to this program, and reset the state
        libccp_debug("[sid=%d] Applying staged program change: %d -> %d\n", conn->index, state->program_index, state->staged_program_index); 
        state->program_index = state->staged_program_index;
        reset_state(conn->datapath, state);
        init_register_state(conn->datapath, state);
        reset_time(conn->datapath, state);
        state->staged_program_index = -1;
    }

    for (i = 0; i < MAX_CONTROL_REG; i++) {
        if (state->pending_update.control_is_pending[i]) {
            libccp_debug("[sid=%d] Applying staged field update: control reg %u (" FMT_U64 "->" FMT_U64 ") \n", 
                conn->index, i,
                state->registers.control_registers[i],
                state->pending_update.control_registers[i]
            );
            state->registers.control_registers[i] = state->pending_update.control_registers[i];
        }
    }

    if (state->pending_update.impl_is_pending[CWND_REG]) {
        libccp_debug("[sid=%d] Applying staged field update: cwnd reg <- " FMT_U64 "\n", conn->index, state->pending_update.impl_registers[CWND_REG]);
        state->registers.impl_registers[CWND_REG] = state->pending_update.impl_registers[CWND_REG];
        if (state->registers.impl_registers[CWND_REG] != 0) {
            conn->datapath->set_cwnd(conn, state->registers.impl_registers[CWND_REG]);
        }
    }

    if (state->pending_update.impl_is_pending[RATE_REG]) {
        libccp_debug("[sid=%d] Applying staged field update: rate reg <- " FMT_U64 "\n", conn->index, state->pending_update.impl_registers[RATE_REG]);
        state->registers.impl_registers[RATE_REG] = state->pending_update.impl_registers[RATE_REG];
        if (state->registers.impl_registers[RATE_REG] != 0) {
            conn->datapath->set_rate_abs(conn, state->registers.impl_registers[RATE_REG]);
        }
    }

    memset(&state->pending_update, 0, sizeof(struct staged_update));
    
    ret = state_machine(conn);
    if (!ret) {
        return ret;
    }

    return ret;
}

// lookup existing connection by its ccp socket id
// return NULL on error
struct ccp_connection *ccp_connection_lookup(struct ccp_datapath *datapath, u16 sid) {
    struct ccp_connection *conn;
    // bounds check
    if (sid == 0 || sid > datapath->max_connections) {
        libccp_warn("index out of bounds: %d", sid);
        return NULL;
    }

    conn = &datapath->ccp_active_connections[sid-1];
    if (conn->index != sid) {
        libccp_trace("index mismatch: sid %d, index %d", sid, conn->index);
        return NULL;
    }

    return conn;
}

// after connection ends, free its slot in the ccp table
// also free slot in ccp instruction table
void ccp_connection_free(struct ccp_datapath *datapath, u16 sid) {
    int msg_size, ret;
    struct ccp_connection *conn;
    char msg[REPORT_MSG_SIZE];

    libccp_trace("Entering %s\n", __FUNCTION__);
    // bounds check
    if (sid == 0 || sid > datapath->max_connections) {
        libccp_warn("index out of bounds: %d", sid);
        return;
    }

    conn = &datapath->ccp_active_connections[sid-1];
    if (conn->index != sid) {
        libccp_warn("index mismatch: sid %d, index %d", sid, conn->index);
        return;
    }

    free_ccp_priv_state(conn);

    msg_size = write_measure_msg(msg, REPORT_MSG_SIZE, sid, 0, 0, 0);
    ret = datapath->send_msg(conn, msg, msg_size);
    if (ret < 0) {
        if (!datapath->_in_fallback)  {
            libccp_warn("error sending close message: %d", ret);
        }
    }
    
    // ccp_connection_start will look for an array entry with index 0
    // to indicate that it's available for a new flow's information.
    // So, we set index to 0 here to reuse the memory.
    conn->index = 0;
    return;
}

// scan through datapath program table for the program with this UID
int datapath_program_lookup_uid(struct ccp_datapath *datapath, u32 program_uid) {
    size_t i;
    struct DatapathProgram *prog;
    struct DatapathProgram *programs = (struct DatapathProgram*) datapath->programs;
    
    for (i=0; i < datapath->max_programs; i++) {
        prog = &programs[i];
        if (prog->index == 0) {
            continue;
        }
        if (prog->program_uid == program_uid) {
            return (int)(prog->index);
        }
    }
    return LIBCCP_PROG_NOT_FOUND;
}

// saves a new datapath program into the array of datapath programs
// returns index into datapath program array where this program is stored
// if there is no more space, returns -1
int datapath_program_install(struct ccp_datapath *datapath, struct InstallExpressionMsgHdr* install_expr_msg, char* buf) {
    int i;
    int ret;
    u16 pid;
    char* msg_ptr; // for reading from char* buf
    struct InstructionMsg* current_instr;
    struct DatapathProgram* program;
    struct DatapathProgram *programs = (struct DatapathProgram*) datapath->programs;

    msg_ptr = buf;
    for (pid = 0; pid < datapath->max_programs; pid++) {
        program = &programs[pid];
        if (program->index == 0) {
            // found a free slot
            program->index = pid + 1;
            pid = pid + 1;
            break;
        }
    }
    if (pid >= datapath->max_programs) {
        libccp_warn("unable to install new program, table is full")
        return LIBCCP_PROG_TABLE_FULL;
    }

    // copy into the program
    program->index = pid;
    program->program_uid = install_expr_msg->program_uid;
    program->num_expressions = install_expr_msg->num_expressions;
    program->num_instructions = install_expr_msg->num_instructions;
    libccp_trace("Trying to install new program with (uid=%d) with %d expressions and %d instructions\n", program->program_uid, program->num_expressions, program->num_instructions);

    memcpy(program->expressions, msg_ptr, program->num_expressions * sizeof(struct ExpressionMsg));
    msg_ptr += program->num_expressions * sizeof(struct ExpressionMsg);

    // parse individual instructions
    for (i=0; i < (int)(program->num_instructions); i++) {
        current_instr = (struct InstructionMsg*)(msg_ptr);
        ret = read_instruction(&(program->fold_instructions[i]), current_instr);
        if (ret < 0) {
            libccp_warn("Could not read instruction # %d: %d in program with uid %u\n", i, ret, program->program_uid);
            return ret;
        }
        msg_ptr += sizeof(struct InstructionMsg);
    }

    libccp_debug("installed new program (uid=%d) with %d expressions and %d instructions\n", program->program_uid, program->num_expressions, program->num_instructions);

    return 0;

}

int stage_update(struct ccp_datapath *datapath __attribute__((unused)), struct staged_update *pending_update, struct UpdateField *update_field) {
    // update the value for these registers
    // for cwnd, rate; update field in datapath
    switch(update_field->reg_type) {
        case NONVOLATILE_CONTROL_REG:
        case VOLATILE_CONTROL_REG:
            // set new value
            libccp_trace(("%s: control " FMT_U32 " <- " FMT_U64 "\n"), __FUNCTION__, update_field->reg_index, update_field->new_value);
            pending_update->control_registers[update_field->reg_index] = update_field->new_value;
            pending_update->control_is_pending[update_field->reg_index] = true;
            return LIBCCP_OK;
        case IMPLICIT_REG:
            if (update_field->reg_index == CWND_REG) {
                libccp_trace("%s: cwnd <- " FMT_U64 "\n", __FUNCTION__, update_field->new_value);
                pending_update->impl_registers[CWND_REG] = update_field->new_value;
                pending_update->impl_is_pending[CWND_REG] = true;
            } else if (update_field->reg_index == RATE_REG) {
                libccp_trace("%s: rate <- " FMT_U64 "\n", __FUNCTION__, update_field->new_value);
                pending_update->impl_registers[RATE_REG] = update_field->new_value;
                pending_update->impl_is_pending[RATE_REG] = true;
            }
            return LIBCCP_OK;
        default:
            return LIBCCP_UPDATE_INVALID_REG_TYPE; // allowed only for CONTROL and CWND and RATE reg within CONTROL_REG
    }
}

int stage_multiple_updates(struct ccp_datapath *datapath, struct staged_update *pending_update, size_t num_updates, struct UpdateField *msg_ptr) {
    int ret;
    for (size_t i = 0; i < num_updates; i++) {
        ret = stage_update(datapath, pending_update, msg_ptr);
        if (ret < 0) {
            return ret;
        }

        msg_ptr++;
    }

    return LIBCCP_OK;
}

int ccp_read_msg(
    struct ccp_datapath *datapath,
    char *buf,
    int bufsize
) {
    int ret;
    int msg_program_index;
    u32 num_updates;
    char* msg_ptr;
    struct CcpMsgHeader hdr;
    struct ccp_connection *conn;
    struct ccp_priv_state *state;
    struct InstallExpressionMsgHdr expr_msg_info;
    struct ChangeProgMsg change_program;
    if (datapath->programs == NULL) {
        libccp_warn("datapath program state not initialized\n");
        return LIBCCP_PROG_IS_NULL;
    }

    ret = read_header(&hdr, buf);
    if (ret < 0) {
        libccp_warn("read header failed: %d", ret);
        return ret;
    }

    if (bufsize < 0) {
        libccp_warn("negative bufsize: %d", bufsize);
        return LIBCCP_BUFSIZE_NEGATIVE;
    }
    if (hdr.Len > ((u32) bufsize)) {
        libccp_warn("message size wrong: %u > %d\n", hdr.Len, bufsize);
        return LIBCCP_BUFSIZE_TOO_SMALL;
    }

    if (hdr.Len > BIGGEST_MSG_SIZE) {
        libccp_warn("message too long: %u > %d\n", hdr.Len, BIGGEST_MSG_SIZE);
        return LIBCCP_MSG_TOO_LONG;
    }
    msg_ptr = buf + ret;


    _turn_off_fto_timer(datapath);

    // INSTALL_EXPR message is for all flows, not a specific connection
    // sock_id in this message should be disregarded (could be before any flows begin)
    if (hdr.Type == INSTALL_EXPR) {
        libccp_trace("Received install message\n");
        memset(&expr_msg_info, 0, sizeof(struct InstallExpressionMsgHdr));
        ret = read_install_expr_msg_hdr(datapath, &hdr, &expr_msg_info, msg_ptr);
        if (ret < 0) {
            libccp_warn("could not read install expression msg header: %d\n", ret);
            return ret;
        }
        // clear the datapath programs
        // TODO: implement a system for which each ccp process has an ID corresponding to its programs
        // as all programs are sent down separately, right now we check if its a new portus starting
        // by checking if the ID of the program is 0
        // TODO: remove this hack
        if (expr_msg_info.program_uid == 1) {
            memset(datapath->programs, 0, datapath->max_programs * sizeof(struct DatapathProgram));
        }

        msg_ptr += ret;
        ret = datapath_program_install(datapath, &expr_msg_info, msg_ptr);
        if ( ret < 0 ) {
            libccp_warn("could not install datapath program: %d\n", ret);
            return ret;
        }
        return LIBCCP_OK; // installed program successfully
    }

    // rest of the messages must be for a specific flow
    conn = ccp_connection_lookup(datapath, hdr.SocketId);
    if (conn == NULL) {
        libccp_trace("unknown connection: %u\n", hdr.SocketId);
        return LIBCCP_UNKNOWN_CONNECTION;
    }
    state = get_ccp_priv_state(conn);

    if (hdr.Type == UPDATE_FIELDS) {
        libccp_debug("[sid=%d] Received update_fields message\n", conn->index);
        ret = check_update_fields_msg(datapath, &hdr, &num_updates, msg_ptr);
        msg_ptr += ret;
        if (ret < 0) {
            libccp_warn("Update fields message failed: %d\n", ret);
            return ret;
        }

        ret = stage_multiple_updates(datapath, &state->pending_update, num_updates, (struct UpdateField*) msg_ptr);
        if (ret < 0) {
            libccp_warn("update_fields: failed to stage updates: %d\n", ret);
            return ret;
        }

        libccp_debug("Staged %u updates\n", num_updates);
    } else if (hdr.Type == CHANGE_PROG) {
        libccp_debug("[sid=%d] Received change_prog message\n", conn->index);
        // check if the program is in the program_table
        ret = read_change_prog_msg(datapath, &hdr, &change_program, msg_ptr);
        if (ret < 0) {
            libccp_warn("Change program message deserialization failed: %d\n", ret);
            return ret;
        }
        msg_ptr += ret;

        msg_program_index = datapath_program_lookup_uid(datapath, change_program.program_uid);
        if (msg_program_index < 0) {
            // TODO: is it possible there is not enough time between when the message is installed and when a flow asks to use the program?
            libccp_info("Could not find datapath program with program uid: %u\n", msg_program_index);
            return ret;
        }

        state->staged_program_index = (u16)msg_program_index; // index into program array for further lookup of instructions

        // clear any staged but not applied updates, as they are now irrelevant
        memset(&state->pending_update, 0, sizeof(struct staged_update));
        // stage any possible update fields to the initialized registers
        // corresponding to the new program
        ret = stage_multiple_updates(datapath, &state->pending_update, change_program.num_updates, (struct UpdateField*)(msg_ptr));
        if (ret < 0) {
            libccp_warn("change_prog: failed to stage updates: %d\n", ret);
            return ret;
        }

        libccp_debug("Staged switch to program %d\n", change_program.program_uid);
    }

    return ret;
}

// send create msg
int send_conn_create(
    struct ccp_datapath *datapath,
    struct ccp_connection *conn
) {
    int ret;
    char msg[CREATE_MSG_SIZE];
    int msg_size;
    struct CreateMsg cr = {
        .init_cwnd = conn->flow_info.init_cwnd,
        .mss = conn->flow_info.mss,
        .src_ip = conn->flow_info.src_ip,
        .src_port = conn->flow_info.src_port,
        .dst_ip = conn->flow_info.dst_ip,
        .dst_port = conn->flow_info.dst_port,
    };
    memcpy(&cr.congAlg, &conn->flow_info.congAlg, MAX_CONG_ALG_SIZE);

    if (
        conn->last_create_msg_sent != 0 &&
        datapath->since_usecs(conn->last_create_msg_sent) < CREATE_TIMEOUT_US
    ) {
        libccp_trace("%s: " FMT_U64 " < " FMT_U32 "\n", 
            __FUNCTION__, 
            datapath->since_usecs(conn->last_create_msg_sent), 
            CREATE_TIMEOUT_US
        );
        return LIBCCP_CREATE_PENDING;
    }

    if (conn->index < 1) {
        return LIBCCP_CONNECTION_NOT_INITIALIZED;
    }

    conn->last_create_msg_sent = datapath->now();
    msg_size = write_create_msg(msg, CREATE_MSG_SIZE, conn->index, cr);
    if (msg_size < 0) {
        return msg_size;
    }

    ret = datapath->send_msg(conn, msg, msg_size);
    if (ret) {
        libccp_debug("error sending create, updating fto_timer")
        _update_fto_timer(datapath);
    }
    return ret;
}

void _update_fto_timer(struct ccp_datapath *datapath) {
    if (!datapath->last_msg_sent) {
        datapath->last_msg_sent = datapath->now();
    }
}

/*
 * Returns true if CCP has timed out, false otherwise
 */
bool _check_fto(struct ccp_datapath *datapath) {
    // TODO not sure how well this will scale with many connections,
    //      may be better to make it per conn
    u64 since_last = datapath->since_usecs(datapath->last_msg_sent);
    bool should_be_in_fallback = datapath->last_msg_sent && (since_last > datapath->fto_us);

    if (should_be_in_fallback && !datapath->_in_fallback) {
        datapath->_in_fallback = true;
        libccp_error("ccp fallback (%lu since last msg)\n", since_last);
    } else if (!should_be_in_fallback && datapath->_in_fallback) {
        datapath->_in_fallback = false;
        libccp_error("ccp should not be in fallback");
    }
    return should_be_in_fallback;
}

void _turn_off_fto_timer(struct ccp_datapath *datapath) {
    if (datapath->_in_fallback) {
        libccp_error("ccp restored!\n");
    }
    datapath->_in_fallback = false;
    datapath->last_msg_sent = 0;
}

// send datapath measurements
// acks, rtt, rin, rout
int send_measurement(
    struct ccp_connection *conn,
    u32 program_uid,
    u64 *fields,
    u8 num_fields
) {
    int ret;
    char msg[REPORT_MSG_SIZE];
    int msg_size;
    struct ccp_datapath *datapath __attribute__((unused)) = conn->datapath;

    if (conn->index < 1) {
        return LIBCCP_CONNECTION_NOT_INITIALIZED;
    }

    msg_size = write_measure_msg(msg, REPORT_MSG_SIZE, conn->index, program_uid, fields, num_fields);
    libccp_trace("[sid=%d] In %s\n", conn->index, __FUNCTION__);
    ret = conn->datapath->send_msg(conn, msg, msg_size);
    if(ret) {
        libccp_debug("error sending measurement, updating fto timer");
        _update_fto_timer(datapath);
    }
    return ret;
}
