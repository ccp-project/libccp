/*
 * CCP Send State Machine
 * 
 * Userspace CCP algorithms specify "send patterns", e.g.:
 * SetCwnd(15) => WaitRtts(1.0) => Report()
 *
 * We implement these patterns on the ACK clock
 */
#ifndef CCP_SEND_STATE_MACHINE_H
#define CCP_SEND_STATE_MACHINE_H

struct ccp_connection;
#include <linux/types.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/* There are 6 states (type field in PatternState)
 * SetRateAbs, SetCwndAbs: set the value of the Rate and Cwnd, respectively.
 *                         Importantly, setting a Rate does not change the Cwnd, and vice versa;
 *                         this way, CCP algorithms can express a window with a maximum rate, or
 *                         a rate with a maximum number of packets in flight.
 *
 * SetRateRel: Change the rate by the given relative multiplicative factor.
 * WaitAbs: Maintain the current Rate and Cwnd until the given duration of time, modulo the ACK clock, has passed.
 * WaitRel: Same as WaitAbs, but the duration given is a multiplicative factor of the current RTT.
 * Report: Send the current measurement state to userspace CCP now.
 */
#define SETRATEABS 0 
#define SETCWNDABS 1 
#define SETRATEREL 2 
#define WAITABS    3
#define WAITREL    4
#define REPORT     5

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

#endif
