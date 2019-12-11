#ifndef CCP_PRIV_H
#define CCP_PRIV_H

#include "ccp.h"
#include "serialize.h"

#ifdef __KERNEL__
#include <linux/kernel.h>
#else
#include <stdio.h>
#endif

#ifdef __KERNEL__
#define FMT_U64 "%llu"
#define FMT_U32 "%lu"
#else
#if defined(__APPLE__)
#define FMT_U64 "%llu"
#else
#define FMT_U64 "%lu"
#endif
#define FMT_U32 "%u"
#endif

#ifdef __KERNEL__
    #define __INLINE__       inline
    #define __CALLOC__(num_elements, block_size) kcalloc(num_elements, block_size, GFP_KERNEL)
    #define __FREE__(ptr)    kfree(ptr)
    #define CAS(a,o,n)       cmpxchg(a,o,n) == o
#else
    #define __INLINE__
    #define __CALLOC__(num_elements, block_size) calloc(num_elements, block_size)
    #define __FREE__(ptr)    free(ptr)
    #define CAS(a,o,n)       __sync_bool_compare_and_swap(a,o,n)
#endif

#define log_fmt(level, fmt, args...) {\
    char msg[80]; \
    int __ok = snprintf((char*) &msg, 80, fmt, ## args); \
    if (__ok >= 0) { \
        datapath->log(datapath, level, (const char*) &msg, __ok); \
    } \
}

// __LOG_INFO__ is default
#define libccp_trace(fmt, args...)
#define libccp_debug(fmt, args...)
#define libccp_info(fmt, args...) log_fmt(INFO, fmt, ## args)
#define libccp_warn(fmt, args...) log_fmt(WARN, fmt, ## args)
#define libccp_error(fmt, args...) log_fmt(ERROR, fmt, ## args)

#ifdef __LOG_TRACE__
#undef libccp_trace
#define libccp_trace(fmt, args...) log_fmt(TRACE, fmt, ## args)
#undef libccp_debug
#define libccp_debug(fmt, args...) log_fmt(DEBUG, fmt, ## args)
#endif

#ifdef __LOG_DEBUG__
#undef libccp_debug
#define libccp_debug(fmt, args...) log_fmt(DEBUG, fmt, ## args)
#endif

#ifdef __LOG_WARN__
#undef libccp_info
#define libccp_info(fmt, args...)
#endif
#ifdef __LOG_ERROR__
#undef libccp_info
#define libccp_info(fmt, args...)
#undef libccp_warn
#define libccp_warn(fmt, args...)
#endif

#ifdef __CPLUSPLUS__
extern "C" {
#endif

/* Triggers the state machine that goes through the expressions and evaluates conditions if true.
 * Should be called on each tick of the ACK clock; i.e. every packet.
 */
int state_machine(
    struct ccp_connection *conn
);

struct Register {
    u8 type;
    int index;
    u64 value;
};

struct Instruction64 {
    u8 op;
    struct Register rRet;
    struct Register rLeft;
    struct Register rRight;
};

/*  Expression contains reference to:
 *  instructions for condition
 *  instructions for body of expression
 */
struct Expression {
    u32 cond_start_idx;
    u32 num_cond_instrs;
    u32 event_start_idx;
    u32 num_event_instrs;
};

/*  Entire datapath program
 *  a set of expressions (conditions)
 *  a set of instructions
 */
struct DatapathProgram {
    u8 num_to_return;
    u16 index; // index in array
    u32 program_uid; // program uid assigned by CCP agent
    u32 num_expressions;
    u32 num_instructions;
    struct Expression expressions[MAX_EXPRESSIONS];
    struct Instruction64 fold_instructions[MAX_INSTRUCTIONS];
};

int read_expression(
    struct Expression *ret,
    struct ExpressionMsg *msg
);

int read_instruction(
    struct Instruction64 *ret,
    struct InstructionMsg *msg
);

struct register_file {
    // report and control registers - users send a DEF for these
    u64 report_registers[MAX_REPORT_REG]; // reported variables, reset to DEF value upon report
    u64 control_registers[MAX_CONTROL_REG]; // extra user defined variables, not reset on report

    // tmp, local and implicit registers
    u64 impl_registers[MAX_IMPLICIT_REG]; // stores special flags and variables
    u64 tmp_registers[MAX_TMP_REG]; // used for temporary calculation in instructions
    u64 local_registers[MAX_LOCAL_REG]; // for local variables within a program - created in a bind in a when clause
};

struct staged_update {
    bool control_is_pending[MAX_CONTROL_REG];
    u64 control_registers[MAX_CONTROL_REG];
    bool impl_is_pending[MAX_IMPLICIT_REG];
    u64 impl_registers[MAX_IMPLICIT_REG];
};

/* libccp Private State
 * struct ccp_connection has a void* state to store libccp's state
 * libccp internally casts this to a struct ccp_priv_state*.
 */
struct ccp_priv_state {
    bool sent_create;
    u64 implicit_time_zero; // can be reset

    u16 program_index; // index into program array
    int staged_program_index;

    struct register_file registers;
    struct staged_update pending_update;
};

/*
 * Resets a specific register's value in response to an update field message.
 * Needs pointer to ccp_connection in case message is for updating the cwnd or rate.
 */
int update_register(
    struct ccp_connection* conn,
    struct ccp_priv_state *state,
    struct UpdateField *update_field
);

/* Reset the output state registers to their default values
 * according to the DEF instruction preamble.
 */
void reset_state(struct ccp_datapath *datapath, struct ccp_priv_state *state);

/* Initializes the control registers to their default values
 * according to the DEF instruction preamble.
 */
void init_register_state(struct ccp_datapath *datapath, struct ccp_priv_state *state);

/* Reset the implicit time registers to count from datapath->now()
 */
void reset_time(struct ccp_datapath *datapath, struct ccp_priv_state *state);

/* Initialize send machine and measurement machine state in ccp_connection.
 * Called from ccp_connection_start()
 */
int init_ccp_priv_state(struct ccp_datapath *datapath, struct ccp_connection *conn);
/* Free the allocated flow memory.
 * Call when the flow has ended.
 */
void free_ccp_priv_state(struct ccp_connection *conn);

// send create message to CCP
int send_conn_create(
    struct ccp_datapath *datapath,
    struct ccp_connection *conn
);

// send measure message to CCP
int send_measurement(
    struct ccp_connection *conn,
    u32 program_uid,
    u64 *fields,
    u8 num_fields
);

/* Retrieve the private state from ccp_connection.
 */
__INLINE__ struct ccp_priv_state *get_ccp_priv_state(struct ccp_connection *conn);

/* Lookup a datapath program, available to all flows
 */
struct DatapathProgram* datapath_program_lookup(struct ccp_datapath *datapath, u16 pid);

/*
 * Reserved Implicit Registers
 */
#define EXPR_FLAG_REG             0
#define SHOULD_FALLTHROUGH_REG    1
#define SHOULD_REPORT_REG         2
#define US_ELAPSED_REG            3
#define CWND_REG                  4
#define RATE_REG                  5

/*
 * Primitive registers
 */
#define  ACK_BYTES_ACKED          0
#define  ACK_BYTES_MISORDERED     1
#define  ACK_ECN_BYTES            2
#define  ACK_ECN_PACKETS          3
#define  ACK_LOST_PKTS_SAMPLE     4
#define  ACK_NOW                  5
#define  ACK_PACKETS_ACKED        6
#define  ACK_PACKETS_MISORDERED   7
#define  FLOW_BYTES_IN_FLIGHT     8
#define  FLOW_BYTES_PENDING       9
#define  FLOW_PACKETS_IN_FLIGHT   10
#define  FLOW_RATE_INCOMING       11
#define  FLOW_RATE_OUTGOING       12
#define  FLOW_RTT_SAMPLE_US       13
#define  FLOW_WAS_TIMEOUT         14

/*
 * Operations
 */
#define    ADD        0
#define    BIND       1
#define    DEF        2
#define    DIV        3
#define    EQUIV      4
#define    EWMA       5
#define    GT         6
#define    IF         7
#define    LT         8
#define    MAX        9
#define    MAXWRAP    10
#define    MIN        11
#define    MUL        12
#define    NOTIF      13
#define    SUB        14
#define    MAX_OP     15

// types of registers
#define NONVOLATILE_CONTROL_REG 0
#define IMMEDIATE_REG           1
#define IMPLICIT_REG            2
#define LOCAL_REG               3
#define PRIMITIVE_REG           4
#define VOLATILE_REPORT_REG     5
#define NONVOLATILE_REPORT_REG  6
#define TMP_REG                 7
#define VOLATILE_CONTROL_REG    8

#ifdef __CPLUSPLUS__
} // extern "C"
#endif

#endif
