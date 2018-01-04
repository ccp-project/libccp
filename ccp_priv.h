#ifndef CCP_PRIV_H
#define CCP_PRIV_H

#include "ccp.h"
#include "serialize.h"

/*
 * CCP Send State Machine
 * 
 * Userspace CCP algorithms specify "send patterns", e.g.:
 * SetCwnd(15) => WaitRtts(1.0) => Report()
 *
 * We implement these patterns on the ACK clock.
 *
 * There are 6 states (type field in PatternState)
 * SetRateAbs, SetRateAbsWithCwnd, SetCwndAbs: 
 *   Set the value of the Rate and Cwnd, respectively.
 *   Importantly, setting a Rate does not change the Cwnd, and vice versa;
 *   this way, CCP algorithms can express a window with a maximum rate, or
 *   a rate with a maximum number of packets in flight.
 *
 * SetRateRel: Change the rate by the given relative multiplicative factor.
 * WaitAbs: Maintain the current Rate and Cwnd until the given duration of time, modulo the ACK clock, has passed.
 * WaitRel: Same as WaitAbs, but the duration given is a multiplicative factor of the current RTT.
 * Report: Send the current measurement state to userspace CCP now.
 */
#define  SETRATEABS          0
#define  SETCWNDABS          1
#define  SETRATEREL          2
#define  WAITABS             3
#define  WAITREL             4
#define  REPORT              5
#define  SETRATEABSWITHCWND  6

struct __attribute__((packed, aligned(2))) PatternState {
    u8 type;
    u8 size;
    u32 val;
};

/* Events deserialized from the string in a PatternMsg
 * If a state
 *
 * seq: array of PatternState
 * return: 0 if ok, -1 otherwise
 */
int read_pattern(
    struct PatternState *seq,
    char *pattern,
    int numEvents
);

/* Triggers the sending state machine.
 * Should be called on each tick of the ACK clock; i.e. every packet.
 */
void send_machine(
    struct ccp_connection *ccp
);

/*
 * CCP Fold State Machine
 *
 * Userspace CCP algorithms specify the measurements they are interested in with a fold function, e.g.:
 *
 * (def (min_rtt +infinity))
 * (= Flow.min_rtt (min Flow.min_rtt Pkt.rtt_sample_us))
 *
 * This is compiled into an []Instruction, e.g.:
 *
 * [
 *   Instruction{_, init, Flow.min_rtt, 0x3f},
 *   Instruction{tmp0, min, Flow.min_rtt, Pkt.rtt_sample_us},
 *   Instruction{Flow.min_rtt, bind, tmp0},
 * ]
 *
 * This []Instruction is serialized into an InstallFold message.
 * Once received here, the []Instruction is run through upon every ccp_invoke()
 */

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
    MAX64WRAP, // (max a b) return max(a,b) with MAX_U32 wraparound
};

struct Register {
    enum RegType64 type;
    int index;
    u64 value;
};

// for EWMA, IFCNT: store register is implicit 'old' state argument
struct Instruction64 {
    enum FoldOp op;
    struct Register rRet;
    struct Register rLeft;
    struct Register rRight;
};

// limits on the number of signals and instructions
// limits on how many registers the user can send down

int read_instruction(
    struct Instruction64 *ret,
    struct InstructionMsg *msg
);

void measurement_machine(
    struct ccp_connection *ccp
);

/* libccp Private State
 * struct ccp_connection has a void* state to store libccp's state
 * libccp internally casts this to a struct ccp_priv_state*.
 */
struct ccp_priv_state {
    // send machine state
    u8 num_pattern_states; // 1 B
    struct PatternState pattern[MAX_INSTRUCTIONS]; // 6 B * MAX_INSTRUCTIONS = 120 B
    u8 curr_pattern_state; // 1 B
    u32 next_event_time; // 4 B

    // measure machine state
    u8 num_instructions; // number of instructions
    struct Instruction64 fold_instructions[MAX_INSTRUCTIONS]; // array of instructions
    u8 num_to_return; // how many state_registers are used?
    u64 state_registers[MAX_PERM_REG];
    u64 tmp_registers[MAX_TMP_REG];
};

/* Reset the output state registers to their default values
 * according to the DEF instruction preamble.
 */
void reset_state(struct ccp_priv_state *state);

/* Initialize send machine and measurement machine state in ccp_connection.
 * Called from ccp_connection_start()
 */
int init_ccp_priv_state(struct ccp_connection *ccp);

/* Retrieve the private state from ccp_connection.
 */
inline struct ccp_priv_state *get_ccp_priv_state(struct ccp_connection *ccp);

// rate sample primitives
// must be the same order as in userspace CCP!
#define  BYTES_ACKED         0
#define  PACKETS_ACKED       1
#define  BYTES_MISORDERED    2
#define  PACKETS_MISORDERED  3
#define  ECN_BYTES           4
#define  ECN_PACKETS         5
#define  LOST_PKTS_SAMPLE    6
#define  WAS_TIMEOUT         7
#define  RTT_SAMPLE_US       8
#define  RATE_OUTGOING       9
#define  RATE_INCOMING       10
#define  BYTES_IN_FLIGHT     11
#define  PACKETS_IN_FLIGHT   12
#define  SND_CWND            13

#endif
