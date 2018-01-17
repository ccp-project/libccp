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

struct CcpMsgHeader {
    u8 Type;
    u32 Len;
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
#define  PATTERN       3
#define  INSTALL_FOLD  4

// Some messages contain strings.
#define  BIGGEST_MSG_SIZE  510

// Some messages contain serialized fold instructions.
#define  MAX_INSTRUCTIONS  50
#define  MAX_PERM_REG      16
#define  MAX_TMP_REG       8

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
    char congAlg[64];
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
    char pattern[BIGGEST_MSG_SIZE - 10];
};

/* 
 * return: size of msg
 */
int read_pattern_msg(
    struct CcpMsgHeader *hdr, 
    struct PatternMsg *msg,
    char *buf 
);

/* INSTRUCTION: 2 u8s: Opcode, Result + 2 u32s: Left, Right
 */
struct __attribute__((packed, aligned(2))) InstructionMsg {
    u8 opcode;
    u8 result_register;
    u32 left_register;
    u32 right_register;
};

/* INSTALL_FOLD
 * 1 u32: number of Instruction
 * bytes: series of Instruction ([]Instruction)
 */
struct __attribute__((packed, aligned(2))) InstallFoldMsg {
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
