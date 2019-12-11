#include "ccp_priv.h"
/*
 * CCP Send State Machine
 *
 * Userspace CCP algorithms specify "expressions".
 * Expressions are conditions (a series of instructions that evaluate to a boolean expression)
 * followed by a set of instructions to execute if that event is true
 */

#define CCP_FRAC_DENOM 10

/*
 * Aggregator functions
 * Corresponds to operations sent down in instruction messages
 * Bind, ifcnt, and ifnotcnt are directly inline
 */
static u64 myadd64(u64 a, u64 b) {
    return a + b;
}

static u64 mydiv64(u64 a, u64 b) {
    return a/b;
}

static u64 myequiv64(u64 a, u64 b) {
    return ( a == b );
}

static u64 myewma64(u64 a, u64 b, u64 c) {
    u64 num;
    u64 old = a * b;
    u64 new_val = ( CCP_FRAC_DENOM - a ) * c;
    if ( b == 0 ) {
        return c;
    }
    num = old + new_val;
    return num/CCP_FRAC_DENOM;
}

static u64 mygt64(u64 a, u64 b) {
    return ( a > b );
}

static u64 mylt64(u64 a, u64 b) {
    return ( a < b );
}


// raw difference from left -> right, provided you're walking in direction left -> right
static u32 dif32(u32 left, u32 right) {
    u32 max32 = ((u32)~0U);
    if ( right > left ) {
        return ( right - left );
    }
    // left -> max -> right
    return (max32 - left) + right;
}

/* must handle integer wraparound*/
static u64 mymax64_wrap(u64 a, u64 b) {
    u32 a32 = (u32)a;
    u32 b32 = (u32)b;
    u32 left_to_right = dif32(a32, b32);
    u32 right_to_left = dif32(b32, a32);
    // 0 case
    if ( a == 0 ) {
        return b;
    }
    if ( b == 0 ) {
        return a;
    }
    // difference from b -> a is shorter than difference from a -> b: so order is (b,a)
    if ( right_to_left < left_to_right ) {
        return (u64)a32;
    }
    // else difference from a -> b is sorter than difference from b -> a: so order is (a,b)
    return (u64)b32;
}

static u64 mymax64(u64 a, u64 b) {
    if ( a > b ) {
        return a;
    }
    return b;
}

static u64 mymin64(u64 a, u64 b) {
    if ( a < b ) {
        return a;
    }
    return b;
}

static u64 mymul64(u64 a, u64 b) {
    return a*b;
}

static u64 mysub64(u64 a, u64 b) {
    return a - b;
}

/*
 * Read Operations from operation messages
 */
static int read_op(struct Instruction64* instr, u8 opcode) {
    if (opcode >= MAX_OP) {
        return -1;
    }
    instr->op = opcode;
    return 0;
}

/*
 * Deserialize registers sent down as u32
 * u32 is necessary for value as it could be an immediate register
 */
static int deserialize_register(struct Register *ret, u8 reg_type, u32 reg_value) {
    switch (reg_type) {
       case IMMEDIATE_REG: // immediate - store in value
            ret->type = (int)IMMEDIATE_REG;
            ret->value = (u64)reg_value;
            return 0;
        case NONVOLATILE_CONTROL_REG: // control register
            ret->type = (int)NONVOLATILE_CONTROL_REG;
            break;
        case VOLATILE_CONTROL_REG: // control register
            ret->type = (int)VOLATILE_CONTROL_REG;
            break;
        case IMPLICIT_REG: // implicit
            ret->type = (int)IMPLICIT_REG;
            break;
        case PRIMITIVE_REG: // primitive
            ret->type = (int)PRIMITIVE_REG;
            break;
        case VOLATILE_REPORT_REG: // output/permanent
            ret->type = (int)VOLATILE_REPORT_REG;
            break;
        case NONVOLATILE_REPORT_REG: // output/permanent
            ret->type = (int)NONVOLATILE_REPORT_REG;
            break;
        case TMP_REG: // temporary register
            ret->type = (int)TMP_REG;
            break;
        case LOCAL_REG: // local register
            ret->type = (int)LOCAL_REG;
            break;
        default:
            return -1;
    }

    ret->index = (int)reg_value;
    return 0;
}

/*
 * Write into specified registers
 * Only allowed to write into NONVOLATILE_REPORT_REG, VOLATILE_REPORT_REG, TMP_REG, LOCAL_REG
 * and some of the IMPL_REG: EXPR_FLAG_REG, CWND_REG, RATE_REG, SHOULD_REPORT_REG
 */
static void write_reg(struct ccp_datapath *datapath, struct ccp_priv_state *state, u64 value, struct Register reg) {
    switch (reg.type) {
        case NONVOLATILE_REPORT_REG:
        case VOLATILE_REPORT_REG:
            if (reg.index >= 0 && reg.index < MAX_REPORT_REG) {
                state->registers.report_registers[reg.index] = value;
            }
            break;
        case TMP_REG:
            if (reg.index >= 0 && reg.index < MAX_TMP_REG) {
                state->registers.tmp_registers[reg.index] = value;
            }
            break;
        case LOCAL_REG:
            if (reg.index >= 0 && reg.index < MAX_LOCAL_REG) {
                state->registers.local_registers[reg.index] = value;
            }
            break;
        case IMPLICIT_REG: // cannot write to US_ELAPSED reg
            if (reg.index == EXPR_FLAG_REG || reg.index == CWND_REG || reg.index == RATE_REG || reg.index == SHOULD_REPORT_REG || reg.index == SHOULD_FALLTHROUGH_REG ) {
                state->registers.impl_registers[reg.index] = value;
            } else if (reg.index == US_ELAPSED_REG) {
                // set micros register to this value, and datapath start time to be time before now
                state->implicit_time_zero = datapath->now() - value;
                state->registers.impl_registers[US_ELAPSED_REG] = value;
            }
            break;
        case VOLATILE_CONTROL_REG:
        case NONVOLATILE_CONTROL_REG:
            if (reg.index >= 0 && reg.index < MAX_CONTROL_REG) {
                state->registers.control_registers[reg.index] = value; 
            }
        default:
            break;
    }
}

/*
 * Read specified register
 */
static u64 read_reg(struct ccp_datapath *datapath, struct ccp_priv_state *state, struct ccp_primitives* primitives, struct Register reg) {
    switch (reg.type) {
        case IMMEDIATE_REG:
            return reg.value;
        case NONVOLATILE_REPORT_REG:
        case VOLATILE_REPORT_REG:
            return state->registers.report_registers[reg.index];
        case NONVOLATILE_CONTROL_REG:
        case VOLATILE_CONTROL_REG:
            return state->registers.control_registers[reg.index];
        case TMP_REG:
            return state->registers.tmp_registers[reg.index];
        case LOCAL_REG:
            return state->registers.local_registers[reg.index];
        case PRIMITIVE_REG:
            switch (reg.index) {
                case ACK_BYTES_ACKED:
                    return primitives->bytes_acked;
                case ACK_PACKETS_ACKED:
                    return primitives->packets_acked;
                case ACK_BYTES_MISORDERED:
                    return primitives->bytes_misordered;
                case ACK_PACKETS_MISORDERED:
                    return primitives->packets_misordered;
                case ACK_ECN_BYTES:
                    return primitives->ecn_bytes;
                case ACK_ECN_PACKETS:
                    return primitives->ecn_packets;
                case ACK_LOST_PKTS_SAMPLE:
                    return primitives->lost_pkts_sample;
                case FLOW_WAS_TIMEOUT:
                    return primitives->was_timeout;
                case FLOW_RTT_SAMPLE_US:
                    if (primitives->rtt_sample_us == 0) {
                        return ((u64)~0U);
                    } else {
                        return primitives->rtt_sample_us;
                    }
                case FLOW_RATE_OUTGOING:
                    return primitives->rate_outgoing;
                case FLOW_RATE_INCOMING:
                    return primitives->rate_incoming;
                case FLOW_BYTES_IN_FLIGHT:
                    return primitives->bytes_in_flight;
                case FLOW_PACKETS_IN_FLIGHT:
                    return primitives->packets_in_flight;
                case ACK_NOW:
                    return datapath->since_usecs(datapath->time_zero);
                case FLOW_BYTES_PENDING:
                    return primitives->bytes_pending;
                default:
                    return 0;
            }
            break;
        case IMPLICIT_REG:
            return state->registers.impl_registers[reg.index];
            break;
        default:
            return 0;
    }
}

/*
 * Process instruction at specfied index 
 */
static int process_instruction(struct ccp_datapath *datapath, struct DatapathProgram *program, int instr_index, struct ccp_priv_state *state, struct ccp_primitives* primitives) {
    //struct DatapathProgram* program = datapath_program_lookup(state->program_index);
    struct Instruction64 current_instruction = program->fold_instructions[instr_index];
    u64 arg0, arg1, arg2, result; // extra arg0 for ewma, if, not if

    arg1 = read_reg(datapath, state, primitives, current_instruction.rLeft);
    arg2 = read_reg(datapath, state, primitives, current_instruction.rRight);
    switch (current_instruction.op) {
        case ADD:
            libccp_trace("ADD  " FMT_U64 " + " FMT_U64 " = " FMT_U64 "\n", arg1, arg2, myadd64(arg1, arg2)); 
            result = myadd64(arg1, arg2);
            if (result < arg1) {
                libccp_warn("ERROR! Integer overflow: " FMT_U64 " + " FMT_U64 "\n", arg1, arg2);
                return -1;
            }
            write_reg(datapath, state, result, current_instruction.rRet);
            break;
        case DIV:
            libccp_trace("DIV  " FMT_U64 " / " FMT_U64 " = ", arg1, arg2);
            if (arg2 == 0) {
                libccp_warn("ERROR! Attempt to divide by 0: " FMT_U64 " / " FMT_U64 "\n", arg1, arg2);
                return -1;
            } else {
                libccp_trace("" FMT_U64 "\n", mydiv64(arg1, arg2));
                write_reg(datapath, state, mydiv64(arg1, arg2), current_instruction.rRet);
            }
            break;
        case EQUIV:
            libccp_trace("EQV  " FMT_U64 " == " FMT_U64 " => " FMT_U64 "\n", arg1, arg2, myequiv64(arg1, arg2));
            write_reg(datapath, state, myequiv64(arg1, arg2), current_instruction.rRet);
            break;
        case EWMA: // arg0 = current, arg2 = new, arg1 = constant
            arg0 = read_reg(datapath, state, primitives, current_instruction.rRet); // current state
            write_reg(datapath, state, myewma64(arg1, arg0, arg2), current_instruction.rRet);
            break;
        case GT:
            libccp_trace("GT   " FMT_U64 " > " FMT_U64 " => " FMT_U64 "\n", arg1, arg2, mygt64(arg1, arg2));
            write_reg(datapath, state, mygt64(arg1, arg2), current_instruction.rRet);
            break;
        case LT:
            libccp_trace("LT   " FMT_U64 " > " FMT_U64 " => " FMT_U64 "\n", arg1, arg2, mylt64(arg1, arg2));
            write_reg(datapath, state, mylt64(arg1, arg2), current_instruction.rRet);
            break;
        case MAX:
            libccp_trace("MAX  " FMT_U64 " , " FMT_U64 " => " FMT_U64 "\n", arg1, arg2, mymax64(arg1, arg2));
            write_reg(datapath, state, mymax64(arg1, arg2), current_instruction.rRet);
            break;
        case MIN:
            libccp_trace("MIN  " FMT_U64 " , " FMT_U64 " => " FMT_U64 "\n", arg1, arg2, mymin64(arg1, arg2));
            write_reg(datapath, state, mymin64(arg1, arg2), current_instruction.rRet);
            break;
        case MUL:
            libccp_trace("MUL  " FMT_U64 " * " FMT_U64 " = " FMT_U64 "\n", arg1, arg2, mymul64(arg1, arg2));
            result = mymul64(arg1, arg2);
            if (result < arg1 && arg2 > 0) {
                libccp_error("ERROR! Integer overflow: " FMT_U64 " * " FMT_U64 "\n", arg1, arg2);
                return -1;
            }
            write_reg(datapath, state, result, current_instruction.rRet);
            break;
        case SUB:
            libccp_trace("SUB  " FMT_U64 " - " FMT_U64 " = " FMT_U64 "\n", arg1, arg2, mysub64(arg1, arg2));
            result = mysub64(arg1, arg2);
            if (result > arg1) {
                libccp_error("ERROR! Integer underflow: " FMT_U64 " - " FMT_U64 "\n", arg1, arg2);
                return -1;
            }
            write_reg(datapath, state, result, current_instruction.rRet);
            break;
        case MAXWRAP:
            libccp_trace("MAXW " FMT_U64 " , " FMT_U64 " => " FMT_U64 "\n", arg1, arg2, mymax64_wrap(arg1, arg2));
            write_reg(datapath, state, mymax64_wrap(arg1, arg2), current_instruction.rRet);
            break;
        case IF: // if arg1 (rLeft), stores rRight in rRet
            libccp_trace("IF   " FMT_U64 " : r" FMT_U64 " -> r" FMT_U64 "\n", arg1, arg2, current_instruction.rRet.value);
            if (arg1) {
                write_reg(datapath, state, arg2, current_instruction.rRet);
            }
            break;
        case NOTIF:
            libccp_trace("!IF  " FMT_U64 " : r" FMT_U64 " -> r" FMT_U64 "\n", arg1, arg2, current_instruction.rRet.value);
            if (arg1 == 0) {
                write_reg(datapath, state, arg2, current_instruction.rRet);
            }
            break;
        case BIND: // take arg2, and put it in rRet
            libccp_trace("BIND r%d: " FMT_U64 " -> " FMT_U64 "\n", current_instruction.rRet.index, current_instruction.rRet.value, arg2);
            write_reg(datapath, state, arg2, current_instruction.rRet);
            break;
        default:
            libccp_debug("UNKNOWN OP %d\n", current_instruction.op);
            break;
    }
    return 0;

}

/*
 * Process a single event - check if condition is true, and execute event body if so
 */
static int process_expression(struct ccp_datapath *datapath, struct DatapathProgram *program, int expr_index, struct ccp_priv_state *state, struct ccp_primitives* primitives) {
    //struct DatapathProgram* program = datapath_program_lookup(state->program_index);
    struct Expression *expression = &(program->expressions[expr_index]);
    u8 idx;
    int ret;
    libccp_trace("when #%d {\n", expr_index);
    for (idx=expression->cond_start_idx; idx<(expression->cond_start_idx + expression->num_cond_instrs); idx++) {
       ret = process_instruction(datapath, program, idx, state, primitives);
       if (ret < 0) {
         return -1;
       }
    }
    libccp_trace("} => " FMT_U64 "\n", state->registers.impl_registers[EXPR_FLAG_REG]);

    // flag from event is promised to be stored in this implicit register
    if (state->registers.impl_registers[EXPR_FLAG_REG] ) {
        for (idx = expression->event_start_idx; idx<(expression->event_start_idx + expression->num_event_instrs ); idx++) {
            ret = process_instruction(datapath, program, idx, state, primitives);
            if (ret < 0) {
                return -1;
            }
        }
    }

    return 0;
}

/*
 * Read instructions into an instruction struct
 */
int read_instruction(
    struct Instruction64 *ret,
    struct InstructionMsg *msg
) {
    int ok;
    ok = read_op(ret, msg->opcode);
    if (ok < 0) {
        return -1;
    }
    
    // check if the reg type is IMMEDIATE or PRIMITIVE
    if (msg->result_reg_type == IMMEDIATE_REG || msg->result_reg_type == PRIMITIVE_REG) {
        return -2;
    }

    ok = deserialize_register(&ret->rRet, msg->result_reg_type, msg->result_register);
    if (ok < 0) {
        return -3;
    }

    ok = deserialize_register(&ret->rLeft, msg->left_reg_type, msg->left_register);
    if (ok < 0) {
        return -4;
    }

    ok = deserialize_register(&ret->rRight, msg->right_reg_type, msg->right_register);
    if (ok < 0) {
        return -5;
    }

    return ok;
}

/*
 * Read expression msg into expression struct
 */
int read_expression(
    struct Expression *expr,
    struct ExpressionMsg *msg
) {
    int ok = 0;
    expr->cond_start_idx = msg->cond_start_idx;
    expr->num_cond_instrs = msg->num_cond_instrs;
    expr->event_start_idx = msg->event_start_idx;
    expr->num_event_instrs = msg->num_event_instrs;
    return ok;
}

/*
 * Resets all permanent registers to the DEF values
 */
void reset_state(struct ccp_datapath *datapath, struct ccp_priv_state *state) {
    u8 i;
    struct DatapathProgram* program = datapath_program_lookup(datapath, state->program_index);
    if (program == NULL) {
        libccp_info("Cannot reset state because program is NULL\n");
	return;
    }
    struct Instruction64 current_instruction;
    u8 num_to_return = 0;

    // go through all the DEF instructions, and reset all VOLATILE_REPORT_REG variables
    for (i = 0; i < program->num_instructions; i++) {
        current_instruction = program->fold_instructions[i];
        switch (current_instruction.op) {
            case DEF:
                // This only applies to REPORT_REG and volatile CONTROL_REG.
                if (current_instruction.rLeft.type != NONVOLATILE_REPORT_REG && 
                    current_instruction.rLeft.type != VOLATILE_REPORT_REG && 
                    current_instruction.rLeft.type != VOLATILE_CONTROL_REG) {
                    continue;
                }
                
                // We report both NONVOLATILE_REPORT_REG and VOLATILE_REPORT_REG.
                if (current_instruction.rLeft.type != VOLATILE_CONTROL_REG) {
                    num_to_return += 1;
                }

                // We don't reset NONVOLATILE_REPORT_REG
                if (current_instruction.rLeft.type == NONVOLATILE_REPORT_REG) {
                    continue;
                }

                // set the default value of the state register
                // check for infinity
                if (current_instruction.rRight.value == (0x3fffffff)) {
                    write_reg(datapath, state, ((u64)~0U), current_instruction.rLeft);
                } else {
                    write_reg(datapath, state, current_instruction.rRight.value, current_instruction.rLeft);
                }
                break;
            default:
                // DEF instructions are only at the beginnning
                // Once we see a non-DEF, can stop.
                program->num_to_return = num_to_return;
                return; 
        }
    }    
}

void init_register_state(struct ccp_datapath *datapath, struct ccp_priv_state *state) {
    u8 i;
    struct Instruction64 current_instruction;
    struct DatapathProgram* program = datapath_program_lookup(datapath, state->program_index);
    if (program == NULL) {
        libccp_info("Cannot init register state because program is NULL\n");
	return;
    }

    // go through all the DEF instructions, and reset all nonvolatile CONTROL_REG and REPORT_REG variables
    for (i = 0; i < program->num_instructions; i++) {
        current_instruction = program->fold_instructions[i];
        switch (current_instruction.op) {
            case DEF:
                if (current_instruction.rLeft.type != NONVOLATILE_CONTROL_REG && current_instruction.rLeft.type != NONVOLATILE_REPORT_REG) {
                    continue;
                }
                // set the default value of the state register
                // check for infinity
                if (current_instruction.rRight.value == (0x3fffffff)) {
                    write_reg(datapath, state, ((u64)~0U), current_instruction.rLeft);
                } else {
                    write_reg(datapath, state, current_instruction.rRight.value, current_instruction.rLeft);
                }
                break;
            default:
                return; 
        }
    }    
}

/*
 * Resets implicit registers associated with US_ELAPSED
 */
void reset_time(struct ccp_datapath *datapath, struct ccp_priv_state *state) {
    // reset the ns elapsed register to register now as 0
    state->implicit_time_zero = datapath->now();
    state->registers.impl_registers[US_ELAPSED_REG] = 0;
}

/*
 * Before state machine, reset  some of the implicit registers
 */
static __INLINE__ void reset_impl_registers(struct ccp_priv_state *state) {
    state->registers.impl_registers[EXPR_FLAG_REG] = 0;
    state->registers.impl_registers[SHOULD_FALLTHROUGH_REG] = 0;
    state->registers.impl_registers[SHOULD_REPORT_REG] = 0;
}

/*
 * Called from ccp_invoke
 * Evaluates all the current expressions
 */
int state_machine(struct ccp_connection *conn) {
    struct ccp_priv_state *state = get_ccp_priv_state(conn);
    struct ccp_datapath *datapath = conn->datapath;
    if (state == NULL) {
        libccp_warn("CCP priv state is null");
        return -1;
    }
    struct DatapathProgram* program = datapath_program_lookup(conn->datapath, state->program_index);
    if (program == NULL) {
        libccp_warn("Datapath program is null");
        return -1;
    }
    struct ccp_primitives* primitives = &conn->prims;
    u32 i;
    int ret;
    u64 implicit_now;
    
    // reset should Report, should fall through, and event expression
    reset_impl_registers(state);

    // update the US_ELAPSED registers
    implicit_now = datapath->since_usecs(state->implicit_time_zero);
    state->registers.impl_registers[US_ELAPSED_REG] = implicit_now;
    
    libccp_trace(">>> program starting [sid=%d] <<<\n", conn->index);
    // cycle through expressions, and process instructions
    for (i=0; i < program->num_expressions; i++) {
        ret = process_expression(datapath, program, i, state, primitives);
        if (ret < 0) {
            libccp_trace(">>> program finished [sid=%d] [ret=-1] <<<\n\n", conn->index);
            return -1;
        }

        // break if the expression is true and fall through is NOT true
        if ((state->registers.impl_registers[EXPR_FLAG_REG]) && !(state->registers.impl_registers[SHOULD_FALLTHROUGH_REG])) {
            break;
        }
        libccp_trace("[sid=%d] fallthrough...\n", conn->index);
    }
    // set rate and cwnd from implicit registers
    if (state->registers.impl_registers[CWND_REG] > 0) {
        libccp_debug("[sid=%d] setting cwnd after program: " FMT_U64 "\n", conn->index, state->registers.impl_registers[CWND_REG]);
        datapath->set_cwnd(conn, state->registers.impl_registers[CWND_REG]);
    }

    if (state->registers.impl_registers[RATE_REG] != 0) {
        libccp_debug("[sid=%d] setting rate after program: " FMT_U64 "\n", conn->index, state->registers.impl_registers[CWND_REG]);
        datapath->set_rate_abs(conn, state->registers.impl_registers[RATE_REG]);
    }

    // if we should report, report and reset state
    if (state->registers.impl_registers[SHOULD_REPORT_REG]) {
        send_measurement(conn, program->program_uid, state->registers.report_registers, program->num_to_return);
        reset_state(conn->datapath, state);
    }

    libccp_trace(">>> program finished [sid=%d] [ret=0] <<<\n\n", conn->index);
    return 0;
}
