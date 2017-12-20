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
#include "common_headers.h"
#include "serialize.h"

struct ccp_connection;

// limits on the number of signals and instructions
// limits on how many registers the user can send down

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
