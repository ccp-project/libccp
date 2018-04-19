#include "ccp_priv.h"
#ifdef __USRLIB__
#include "stdio.h"
#endif

#define CCP_FRAC_DENOM 10

extern struct ccp_datapath *datapath;

extern int send_measurement(
    struct ccp_connection *conn,
    u64 *fields,
    u8 num_fields
);

/*
 * Aggregator functions
 * Corresponds to operations sent down in instruction messages
 * Bind, ifcnt, and ifnotcnt are directly inline
 */
u64 myadd64(u64 a, u64 b) {
    return a + b;
}

u64 mydiv64(u64 a, u64 b) {
    return a/b;
}

u64 myequiv64(u64 a, u64 b) {
    return ( a == b );
}

u64 myewma64(u64 a, u64 b, u64 c) {
    u64 num;
    u64 old = a * b;
    u64 new_val = ( CCP_FRAC_DENOM - a ) * c;
    if ( b == 0 ) {
        return c;
    }
    num = old + new_val;
    return num/CCP_FRAC_DENOM;
}

u64 mygt64(u64 a, u64 b) {
    return ( a > b );
}

u64 mylt64(u64 a, u64 b) {
    return ( a < b );
}


// raw difference from left -> right, provided you're walking in direction left -> right
u32 dif32(u32 left, u32 right) {
    u32 max32 = ((u32)~0U);
    if ( right > left ) {
        return ( right - left );
    }
    // left -> max -> right
    return (max32 - left) + right;
}

/* must handle integer wraparound*/
u64 mymax64_wrap(u64 a, u64 b) {
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

u64 mymax64(u64 a, u64 b) {
    if ( a > b ) {
        return a;
    }
    return b;
}

u64 mymin64(u64 a, u64 b) {
    if ( a < b ) {
        return a;
    }
    return b;
}

u64 mymul64(u64 a, u64 b) {
    return a*b;
}

u64 mysub64(u64 a, u64 b) {
    return a - b;
}

/*
 * Read Operations from operation messages
 */
int read_op(struct Instruction64* instr, u8 opcode) {
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
int deserialize_register(struct Register *ret, u8 reg_type, u32 reg_value) {
    switch (reg_type) {
        case CONTROL_REG: // control register
            ret->type = (int)CONTROL_REG;
            ret->value = (u64)reg_value;
            return 0;
       case IMMEDIATE_REG: // immediate - store in value
            ret->type = (int)IMMEDIATE_REG;
            ret->value = (u64)reg_value;
            return 0;
        case IMPLICIT_REG: // implicit
            ret->type = (int)IMPLICIT_REG;
            ret->index = (int)reg_value;
            return 0;
        case PRIMITIVE_REG: // primitive
            ret->type = (int)PRIMITIVE_REG;
            ret->index = (int)reg_value;
            return 0;
        case REPORT_REG: // output/permanent
            ret->type = (int)REPORT_REG;
            ret->index = (int)reg_value;
            return 0;
        case TMP_REG: // temporary register
            ret->type = (int)TMP_REG;
            ret->index = (int)reg_value;
            return 0;  
        case LOCAL_REG: // local register
            ret->type = (int)LOCAL_REG;
            ret->index = (int)reg_value;
            return 0;
        default:
            return -1;
    }
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

    ok = deserialize_register(&ret->rRet, msg->result_reg_type, msg->result_register);
    // check if the reg type is IMMEDIATE or PRIMITIVE
    if (msg->result_reg_type == IMMEDIATE_REG || msg->result_reg_type == PRIMITIVE_REG) {
        return -2;
    }
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
 * Perform update in update_field struct
 * Only applicable to control registers and cwnd and rate registers
 */
int update_register(struct ccp_connection* conn, struct ccp_priv_state *state, struct UpdateField *update_field) {
    // update the value for these registers
    // for cwnd, rate; update field in datapath
    switch(update_field->reg_type) {
        case CONTROL_REG:
            // set new value
            state->control_registers[update_field->reg_index] = update_field->new_value;
            break;
        case IMPLICIT_REG:
            if (update_field->reg_index == CWND_REG) {
                state->impl_registers[CWND_REG] = update_field->new_value;
                datapath->set_cwnd(datapath, conn, state->impl_registers[CWND_REG]);
            } else if (update_field->reg_index == RATE_REG) {
                state->impl_registers[RATE_REG] = update_field->new_value;
                datapath->set_rate_abs(datapath, conn, state->impl_registers[RATE_REG]);
            }
            return 0;
        default:
            return 0; // allowed only for CONTROL and CWND and RATE reg within CONTROL_REG
    }

    return 0;
}

/*
 * Write into specified registers
 * Only allowed to write into REPORT_REG, TMP_REG, LOCAL_REG
 * and some of the IMPL_REG: EXPR_FLAG_REG, CWND_REG, RATE_REG, SHOULD_REPORT_REG
 */
void write_reg(struct ccp_priv_state *state, u64 value, struct Register reg) {
    switch (reg.type) {
        case REPORT_REG:
            state->report_registers[reg.index] = value;
            break;
        case TMP_REG:
            state->tmp_registers[reg.index] = value;
            break;
        case LOCAL_REG:
            state->local_registers[reg.index] = value;
            break;
        case IMPLICIT_REG: // cannot write to NS_ELAPSED reg
            if (reg.index == EXPR_FLAG_REG || reg.index == CWND_REG || reg.index == RATE_REG || reg.index == SHOULD_REPORT_REG || reg.index == SHOULD_FALLTHROUGH_REG ) {
                state->impl_registers[reg.index] = value;
            }
            break;
        case CONTROL_REG:
            state->control_registers[reg.index] = value; 
        default:
            break;
    }
}

/*
 * Read specified register
 */
u64 read_reg(struct ccp_priv_state *state, struct ccp_primitives* primitives, struct Register reg) {
    switch (reg.type) {
        case IMMEDIATE_REG:
            return reg.value;
        case REPORT_REG:
            return state->report_registers[reg.index];
        case CONTROL_REG:
            return state->control_registers[reg.index];
        case TMP_REG:
            return state->tmp_registers[reg.index];
        case LOCAL_REG:
            return state->local_registers[reg.index];
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
            return state->impl_registers[reg.index];
            break;
        default:
            return 0;
    }
}

/*
 * Resets all permanent registers to the DEF values
 */
void reset_state(struct ccp_priv_state *state) {
    u8 i;
    struct Instruction64 current_instruction;
    u8 num_to_return = 0;

    // go through all the DEF instructions, and reset all REPORT_REG variables
    for (i = 0; i < state->num_instructions; i++) {
        current_instruction = state->fold_instructions[i];
        switch (current_instruction.op) {
            case DEF:
#ifdef __DEBUG__
                print_register(&(current_instruction.rLeft));
#endif
                if (current_instruction.rLeft.type != REPORT_REG) {
                    continue;
                }
                // set the default value of the state register
                // check for infinity
                if (current_instruction.rRight.value == (0x3fffffff)) {
                    write_reg(state, ((u64)~0U), current_instruction.rLeft);
                } else {
                    write_reg(state, current_instruction.rRight.value, current_instruction.rLeft);
                }
                num_to_return += 1;
                break;
            default:
                // DEF instructions are only at the beginnning
                // Once we see a non-DEF, can stop.
                state->num_to_return = num_to_return;
                return; 
        }
    }    
}

void init_control_state(struct ccp_priv_state *state) {
    u8 i;
    struct Instruction64 current_instruction;

    // go through all the DEF instructions, and reset all REPORT_REG variables
    for (i = 0; i < state->num_instructions; i++) {
        current_instruction = state->fold_instructions[i];
        switch (current_instruction.op) {
            case DEF:
#ifdef __DEBUG__
                print_register(&(current_instruction.rLeft));
#endif
                if (current_instruction.rLeft.type != CONTROL_REG) {
                    continue;
                }
                // set the default value of the state register
                // check for infinity
                if (current_instruction.rRight.value == (0x3fffffff)) {
                    write_reg(state, ((u64)~0U), current_instruction.rLeft);
                } else {
                    write_reg(state, current_instruction.rRight.value, current_instruction.rLeft);
                }
                break;
            default:
                return; 
        }
    }    
}

/*
 * Resets implicit registers associated with NS_ELAPSED
 */
void reset_time(struct ccp_priv_state *state) {
    // reset the ns elapsed register to register now as 0
    state->implicit_time_zero = datapath->since_usecs(datapath->time_zero);
    state->impl_registers[NS_ELAPSED_REG] = 0;
}

#ifdef __DEBUG__
void print_register(struct Register* reg) {
    char* type;
    switch(reg->type) {
        case CONTROL_REG:
            type = "CONTROL";
            break;
        case IMMEDIATE_REG:
            type = "IMMEDIATE";
            break;
        case LOCAL_REG:
            type = "LOCAL";
            break;
        case PRIMITIVE_REG:
            type = "PRIMITIVE";
            break;
        case REPORT_REG:
            type = "REPORT";
            break;
        case TMP_REG:
            type = "TMP";
            break;
        case IMPLICIT_REG:
            type = "IMPLICIT";
            break;
        default:
            type = "INVALID";
            break;
    }

    DBG_PRINT("Register{%s(%u), ind: %d, val: %lu}\n", type, reg->type, reg->index, reg->value);
}
#endif


/*
 * Process instruction at specfied index 
 */
int process_instruction(int instr_index, struct ccp_priv_state *state, struct ccp_primitives* primitives) {
    struct Instruction64 current_instruction = state->fold_instructions[instr_index];
    u64 arg0, arg1, arg2; // extra arg0 for ewma, if, not if

    arg1 = read_reg(state, primitives, current_instruction.rLeft);
    arg2 = read_reg(state, primitives, current_instruction.rRight);
    DBG_PRINT("Instruction: %d, left arg: %lu, right arg: %lu\n", current_instruction.op, arg1, arg2);
    
    switch (current_instruction.op) {
        case ADD:
            //DBG_PRINT("Adding: %lu, %lu, result reg type: %u, result reg index: %d\n", arg1, arg2, current_instruction.rRet.type, current_instruction.rRet.index);
            write_reg(state, myadd64(arg1, arg2), current_instruction.rRet);
            break;
        case DIV:
            if (arg2 == 0) {
                return -1;
            } else {
                write_reg(state, mydiv64(arg1, arg2), current_instruction.rRet);
            }
            break;
        case EQUIV:
            write_reg(state, myequiv64(arg1, arg2), current_instruction.rRet);
            break;
        case EWMA: // arg0 = current, arg2 = new, arg1 = constant
            arg0 = read_reg(state, primitives, current_instruction.rRet); // current state
            write_reg(state, myewma64(arg1, arg0, arg2), current_instruction.rRet);
            break;
        case GT:
            write_reg(state, mygt64(arg1, arg2), current_instruction.rRet);
            break;
        case LT:
#ifdef __DEBUG__
            DBG_PRINT("Checking lt: %lu <? %lu\n", arg1, arg2);
            print_register(&current_instruction.rRight);
            print_register(&current_instruction.rLeft);
#endif
            write_reg(state, mylt64(arg1, arg2), current_instruction.rRet);
            break;
        case MAX:
            write_reg(state, mymax64(arg1, arg2), current_instruction.rRet);
            break;
        case MIN:
            write_reg(state, mymin64(arg1, arg2), current_instruction.rRet);
            break;
        case MUL:
            write_reg(state, mymul64(arg1, arg2), current_instruction.rRet);
            break;
        case SUB:
            write_reg(state, mysub64(arg1, arg2), current_instruction.rRet);
            break;
        case MAXWRAP:
            write_reg(state, mymax64_wrap(arg1, arg2), current_instruction.rRet);
            break;
        case RESETTIME: // resets the ns_elapsed time counter
            reset_time(state);
            break;
        case IF: // if arg1 (rLeft), stores rRight in rRet
            if (arg1) {
                write_reg(state, arg2, current_instruction.rRet);
            }
            break;
        case NOTIF:
            if (arg1 == 0) {
                write_reg(state, arg2, current_instruction.rRet);
            }
            break;
        case BIND: // take arg2, and put it in rRet
#ifdef __DEBUG__
            DBG_PRINT("Binding %lu to following register\n", arg2);
            print_register(&(current_instruction.rRet));
#endif
            write_reg(state, arg2, current_instruction.rRet);
            break;
        default:
            break;
    }
    return 0;

}

/*
 * Process a single event - check if condition is true, and execute event body if so
 */
int process_expression(int expr_index, struct ccp_priv_state *state, struct ccp_primitives* primitives) {
    struct Expression *expression = &(state->expressions[expr_index]);
    u8 idx;
    int ret;
    DBG_PRINT("%u, %u, %u, %u\n", expression->cond_start_idx, expression->num_cond_instrs, expression->event_start_idx, expression->num_event_instrs);
    for (idx=expression->cond_start_idx; idx<(expression->cond_start_idx + expression->num_cond_instrs); idx++) {
       DBG_PRINT("processed instr for event condition\n");
       ret = process_instruction(idx, state, primitives);
       if (ret < 0) {
         return -1;
       }
    }

    // flag from event is promised to be stored in this implicit register
    if (state->impl_registers[EXPR_FLAG_REG] ) {
        DBG_PRINT("expr flag reg true\n");
        for (idx = expression->event_start_idx; idx<(expression->event_start_idx + expression->num_event_instrs ); idx++) {
            ret = process_instruction(idx, state, primitives);
            if (ret < 0) {
                return -1;
            }
        }
    }

    return 0;
}

/*
 * Before state machine, reset  some of the implicit registers
 */
void reset_impl_registers(struct ccp_priv_state *state) {
    state->impl_registers[EXPR_FLAG_REG] = 0;
    state->impl_registers[SHOULD_FALLTHROUGH_REG] = 0;
    state->impl_registers[SHOULD_REPORT_REG] = 0;
}

/*
 * Called from ccp_invoke
 * Evaluates all the current expressions
 */
int state_machine(struct ccp_connection *conn) {
    struct ccp_priv_state *state = get_ccp_priv_state(conn);
    struct ccp_primitives* primitives = &conn->prims;
    u32 i;
    int ret;
    u64 implicit_now;
    
    // reset should Report, should fall through, and event expression
    reset_impl_registers(state);


    // update the NS_ELAPSED registers
    implicit_now = datapath->since_usecs(state->implicit_time_zero);
    state->impl_registers[NS_ELAPSED_REG] = implicit_now;

    // cycle through expressions, and process instructions
    for (i=0; i < state->num_expressions; i++) {
        ret = process_expression(i, state, primitives);
        if (ret < 0) {
            return -1;
        }

        // break if the expression is true and fall through is NOT true
        if ((state->impl_registers[EXPR_FLAG_REG]) && !(state->impl_registers[SHOULD_FALLTHROUGH_REG])) {
            break;
        }
    }

    // set rate and cwnd from implicit registers
    datapath->set_cwnd(datapath, conn, state->impl_registers[CWND_REG]);
    datapath->set_rate_abs(datapath, conn, state->impl_registers[RATE_REG]);
#ifdef __DEBUG__
    DBG_PRINT("state: num to return: %u\n", state->num_to_return);
    for (i=0; i < state->num_to_return; i++) {
        DBG_PRINT("i: %d, state: %lu\n", i, state->report_registers[i]);
    }
#endif

    // if we should report, report and reset state
    if (state->impl_registers[SHOULD_REPORT_REG]) {
        DBG_PRINT("sending report\n");
        send_measurement(conn, state->report_registers, state->num_to_return);
        reset_state(state);
    }

    return 0;
}
