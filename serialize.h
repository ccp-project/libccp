/* 
 * CCP Datapath Message Serialization 
 * 
 * Serializes and deserializes messages for communication with userspace CCP.
 */
#ifndef CCP_SERIALIZE_H
#define CCP_SERIALIZE_H

#ifdef __USRLIB__
#include <stdint.h>
#else 
#include <linux/types.h>
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#ifdef __CPLUSPLUS__
extern "C" {
#endif

struct __attribute__((packed, aligned(4))) CcpMsgHeader {
    u16 Type;
    u16 Len;
    u32 SocketId;
};

/* return: sizeof(struct CcpMsgHeader) on success, -1 otherwise.
 */
int read_header(struct CcpMsgHeader *hdr, char *buf);

/* return: sizeof(struct CcpMsgHeader) on success, -1 otherwise.
 */
int serialize_header(char *buf, int bufsize, struct CcpMsgHeader *hdr);

/* There are 4 message types (Type field in header)
 * CREATE and MEASURE are written from datapath to CCP
 * PATTERN and INSTALL_FOLD are received in datapath from CCP
 * 
 * Messages start with the header, then 
 * 1. fixed number of u32
 * 2. fixed number of u64
 * 3. bytes blob, flexible length
 */
#define  CREATE        0
#define  MEASURE       1
#define  INSTALL_EXPR  2
#define  UPDATE_FIELDS 3

// Some messages contain strings.
#define  BIGGEST_MSG_SIZE  1024

// for create messages, we know they are smaller when we send them up
#define CREATE_MSG_SIZE     512
// size of report msg is 12 B * MAX_REPORT_REG
#define REPORT_MSG_SIZE     900

// Some messages contain serialized fold instructions.
#define MAX_EXPRESSIONS    10 // 10 * 4 = 40 bytes for expressions
#define MAX_INSTRUCTIONS   50 // 50 * 16 = 800 bytes for instructions
#define MAX_IMPLICIT_REG   6
#define MAX_REPORT_REG     15 // measure msg is 15*8 + 4 = 124 bytes
#define MAX_CONTROL_REG    15
#define MAX_TMP_REG        8
#define MAX_LOCAL_REG      8

/* CREATE
 * str: the datapath's requested congestion control algorithm (could be overridden)
 * TODO(eventually): convey relevant sockopts to CCP
 */
struct __attribute__((packed, aligned(4))) CreateMsg {
    u32 init_cwnd;
    u32 mss;
    u32 src_ip;
    u32 src_port;
    u32 dst_ip;
    u32 dst_port;
};

/* Write cr: CreateMsg into buf with socketid sid.
 * buf should be preallocated, and bufsize should be its size.
 */
int write_create_msg(
    char *buf,
    int bufsize,
    u32 sid,
    struct CreateMsg cr
);

/* MEASURE
 * program_uid: unique id for the datapath program that generated this report,
 *              so that the ccp can use the corresponding scope
 * num_fields: number of returned fields,
 * bytes: the return registers of the installed fold function ([]uint64).
 *        there will be at most MAX_PERM_REG returned registers
 */
struct __attribute__((packed, aligned(4))) MeasureMsg {
    u32 program_uid;
    u32 num_fields;
    u64 fields[MAX_REPORT_REG];
};

/* Write ms: MeasureMsg into buf with socketid sid.
 * buf should be preallocated, and bufsize should be its size.
 */
int write_measure_msg(
    char *buf,
    int bufsize,
    u32 sid,
    u32 program_uid,
    u64 *msg_fields,
    u8 num_fields
);

/* INSTRUCTION
 * 1 u8 for opcode
 * 3 sets of {u8, u32} for each of the result register, left register and right register
 */
struct __attribute__((packed, aligned(4))) InstructionMsg {
    u8 opcode;
    u8 result_reg_type;
    u32 result_register;
    u8 left_reg_type;
    u32 left_register;
    u8 right_reg_type;
    u32 right_register;
};


/* ExpressionMsg: 4 u8s
 * start of expression condition instr ID
 * number of expression condition instrs
 * start of event body instr ID
 * number of event body instrs
 */
struct __attribute__((packed, aligned(4))) ExpressionMsg {
    u8 cond_start_idx;
    u8 num_cond_instrs;
    u8 event_start_idx;
    u8 num_event_instrs;
};

/* InstallExprMsg: 846 bytes in total
 * 3 u32s: unique id, number of expressions and instructions
 * []ExprMsg: expressions -> 40 bytes, MAX = 10
 * []InstructionMsg: all instructions -> 800 bytes, MAX = 16
 */
struct __attribute__((packed, aligned(4))) InstallExpressionMsg {
    u32 program_uid;
    u32 num_expressions;
    u32 num_instructions;
    struct ExpressionMsg exprs[MAX_EXPRESSIONS];
    struct InstructionMsg instrs[MAX_INSTRUCTIONS];
};

/* return: size of msg
 * When reading this message, the buffer sent down
 * does not fill the entire InstallExpressionMsg,
 * as space is allocated for MAX_EXPRESSIONS and MAX_INSTRUCTIONS, but the message
 * is sent down with exact num_expressions ExpressionMsg structs
 * and exactly num_instructions InstructionMsg structs
 */
int read_install_expr_msg(
    struct CcpMsgHeader *hdr,
    struct InstallExpressionMsg *msg,
    char *buf
);


struct __attribute__((packed, aligned(1))) UpdateField {
    u8 reg_type;
    u32 reg_index;
    u64 new_value;
};

struct __attribute__((packed, aligned(1))) UpdateFieldsMsg {
    u32 num_updates;
    struct UpdateField updates[MAX_REPORT_REG];
};

int read_update_fields_msg(
    struct CcpMsgHeader *hdr,
    struct UpdateFieldsMsg *msg,
    char *buf
);

#ifdef __CPLUSPLUS__
} // extern "C"
#endif

#endif
