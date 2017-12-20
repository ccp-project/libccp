/* 
 * CCP Datapath Message Serialization 
 * 
 * Serializes and deserializes messages for communication with userspace CCP.
 */
#ifndef CCP_SERIALIZE_H
#define CCP_SERIALIZE_H

#include <linux/types.h>
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/* (type, len, socket_id) header
 * -----------------------------------
 * | Msg Type | Len (B)  | Uint32    |
 * | (1 B)    | (1 B)    | (32 bits) |
 * -----------------------------------
 * total: 6 Bytes
 */
struct __attribute__((packed, aligned(2))) CcpMsgHeader {
    u8 Type;
    u8 Len;
    u32 SocketId;
};

/* return: sizeof(struct CcpMsgHeader) on success, -1 otherwise.
 */
int read_header(struct CcpMsgHeader *hdr, char *buf);

/* return: sizeof(struct CcpMsgHeader) on success, -1 otherwise.
 */
int serialize_header(char *buf, int bufsize, struct CcpMsgHeader *hdr);

/* There are 5 message types (Type field in header)
 * CREATE, MEASURE, and DROP are written from datapath to CCP
 * PATTERN and INSTALL_FOLD are received in datapath from CCP
 * 
 * Messages start with the header, then 
 * 1. fixed number of u32
 * 2. fixed number of u64
 * 3. bytes blob, flexible length
 */
#define CREATE  0
#define MEASURE 1
#define DROP    2
#define PATTERN 3
#define INSTALL_FOLD 4

// Some messages contain strings.
#define BIGGEST_MSG_SIZE 256
#define MAX_STRING_SIZE 250

// Some messages contain serialized fold instructions.
#define MAX_INSTRUCTIONS 20
#define MAX_PERM_REG 6
#define MAX_TMP_REG 10

/* CREATE
 * 1 u32: the socket id
 * str: the datapath's requested congestion control algorithm (could be overridden)
 */
struct __attribute__((packed, aligned(4))) CreateMsg {
    u32 startSeq;
    char congAlg[MAX_STRING_SIZE];
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
 * 1 u32: number of returned fields
 * bytes: the return registers of the installed fold function ([]uint64).
 *        there will be at most MAX_PERM_REG returned registers
 */
struct __attribute__((packed, aligned(4))) MeasureMsg {
    u32 num_fields;
    u64 fields[MAX_PERM_REG];
};

/* Write ms: MeasureMsg into buf with socketid sid.
 * buf should be preallocated, and bufsize should be its size.
 */
int write_measure_msg(
    char *buf,
    int bufsize,
    u32 sid,
    struct MeasureMsg ms
);

/* PATTERN
 * 1 u32: number of PatternState
 * bytes: series of PatternState ([]PatternState)
 */
struct __attribute__((packed, aligned(4))) PatternMsg {
    u32 numStates;
    char pattern[MAX_STRING_SIZE];
};

/* 
 * return: size of msg
 */
int read_pattern_msg(
    struct CcpMsgHeader *hdr, 
    struct PatternMsg *msg,
    char *buf 
);

/* INSTRUCTION: 4 u8s - Opcode, Result, Left, Right
 */
struct __attribute__((packed, aligned(4))) InstructionMsg {
    u8 opcode;
    u8 result_register;
    u8 left_register;
    u8 right_register;
};

/* INSTALL_FOLD
 * 1 u32: number of Instruction
 * bytes: series of Instruction ([]Instruction)
 */
struct __attribute__((packed, aligned(4))) InstallFoldMsg {
    u32 num_instrs;
    struct InstructionMsg instrs[MAX_INSTRUCTIONS];
};

/* return: size of msg
 */
int read_install_fold_msg(
    struct CcpMsgHeader *hdr, 
    struct InstallFoldMsg *msg,
    char *buf 
);

#endif
