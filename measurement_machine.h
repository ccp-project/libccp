/*
 * CCP Fold State Machine
 *
 * Userspace CCP algorithms specify the measurements they are interested in with a fold function, e.g.:
 *
 * (def (min_rtt 99999999))
 * (= Flow.min_rtt (min Flow.min_rtt Pkt.rtt))
 *
 * This is compiled into an []Instruction, e.g.:
 *
 * TODO make this example correct
 * [
 *   Instruction{_, init, Flow.min_rtt, 99999999},
 *   Instruction{tmp0, min, Flow.min_rtt, Pkt.rtt},
 *   Instruction{Flow.min_rtt, bind, tmp0},
 * ]
 *
 * This []Instruction is serialized into an InstallFold message.
 */
#ifndef CCP_MEASUREMENT_MACHINE_H
#define CCP_MEASUREMENT_MACHINE_H

#include "serialize.h"

struct ccp_connection;

// limits on the number of signals and instructions
// limits on how many registers the user can send down
#define MAX_STATE_REG 5
#define MAX_TMP_REG 5 // for intermediate computations
#define NUM_REG 10

/* -----------------------------------------------------------------------------
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

enum RegType64 {
    STATE_REG,
    TMP_REG,
    PRIMITIVE_REG,
    CONST_REG
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
    struct Register r1;
    struct Register r2; // 2 arguments
    struct Register rStore; // store register
};

int read_instruction(
    struct Instruction64 *ret,
    struct InstructionMsg *msg
);

/* Instructions serialized in the string in InstructionMsg
 * if no val in instructions, set to 0
 */
int install_fold(
    struct ccp_connection *ccp,
    char *buf,
    int num_instrs
);

void measurement_machine(
    struct ccp_connection *ccp
);

#endif
