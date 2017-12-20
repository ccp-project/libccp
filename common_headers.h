/*
 * Common Headers for LibCCP related things. 
 */

#ifndef CCP_COMMONHEADERS_H
#define CCP_COMMONHEADERS_H

#include <linux/types.h>

struct ccp_primitives {
    u64 ack;
    u64 rtt;
    u64 loss;
    u64 rin;
    u64 rout;
    u64 cwnd;
};
#define MAX_FOLD_INSTRUCTIONS 20
#define MAX_PERM_REG 6
#define MAX_TMP_REG 10

/* ----------------------------------------------------------------------------
 * CCP Fold Function Primitives
 * -----------------------------------------------------------------------------
 */
// TODO: more than u64 functions
//

// rate sample primitives
#define ACK 0
#define RTT 1
#define LOSS 2
#define RIN 3
#define ROUT 4
#define CWND 5

enum RegType64 {
    CONST_REG, // primitives
    PERM_REG, // state/return values
    TMP_REG, // temporary values
    IMM_REG // immutables
};

enum FoldOp {
    ADD64, // (add a b) return a+b
    BIND64, // add a to store
    DEF64, // set initial output register value
    DIV64, // (div a b) return a/b (integer division)
    EQUIV64, // (eq a b) return a == b
    EWMA64, // (ewma a b) return old * (a/10) + b * (1-(a/10)) old is return reg
    GT64, // (> a b) return a > b
    IFCNT64, // if (a) add 1 to store
    IFNOTCNT64, // if not a, add 1 to store
    LT64, // (< a b) return a < b
    MAX64, // (max a b) return max(a,b)
    MIN64, // (min a b) return min(a,b)
    MUL64, // (mul a b) return a * b
    SUB64, // (sub a b) return a - b
};

struct Register {
    enum RegType64 type;
    int index;
    u64 value;
};

struct InitialValue {
    struct Register reg;
    u64 value;
};

// for EWMA, IFCNT: store register is implicit 'old' state argument
struct Instruction64 {
    enum FoldOp op;
    struct Register rRet;
    struct Register rLeft;
    struct Register rRight;
};


/* Convenience type which DropMsg will map to drop event strings
 */
enum drop_type {
    NO_DROP,
    DROP_TIMEOUT,
    DROP_DUPACK,
    DROP_ECN
};
#endif
