#include "ccp_priv.h"

#define CCP_FRAC_DENOM 100
#define CCP_EWMA_RECENCY 60

// TODO: more than u64 functions
// for bind, ifcnt and ifnotcnt, operations are directly inline
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
    u64 new = ( CCP_FRAC_DENOM - a ) * c;
    if ( b == 0 ) {
        return c;
    }
    num = old + new;
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


int read_op(enum FoldOp *op, u8 opcode) {
    switch (opcode) {
        case 0:
            *op = ADD64;
            return 0;
        case 1:
            *op = BIND64;
            return 0;
        case 14:
            *op = DEF64;
            return 0;
        case 2:
            *op = DIV64;
            return 0;
        case 3:
            *op = EQUIV64;
            return 0;
        case 4:
            *op = EWMA64;
            return 0;
        case 5:
            *op = GT64;
            return 0;
        case 6:
            *op = IFCNT64;
            return 0;
        case 8:
            *op = LT64;
            return 0;
        case 9:
            *op = MAX64;
            return 0;
        case 10:
            *op = MIN64;
            return 0;
        case 11:
            *op = MUL64;
            return 0;
        case 12:
            *op = IFNOTCNT64;
            return 0;
        case 13:
            *op = SUB64;
            return 0;
        case 15:
            *op = MAX64WRAP;
            return 0;
        default:
            return -1;
    }
}

int deserialize_reg(struct Register *ret, u8 reg) {
    u8 num = (reg & 0x3f); // unclear: is this correct
    switch (reg >> 6) {
        case 0: // immediate - other 6 bits
            ret->type = IMM_REG;
            ret->value = (u64)num;
            return 0;
        case 1: // primitive
            ret->type = CONST_REG;
            ret->index = (int)num;
            return 0;
        case 2: // tmp
            ret->type = TMP_REG;
            ret->index = (int)num;
            return 0;
        case 3: // output/permanent
            ret->type = PERM_REG;
            ret->index = (int)num;
            return 0;
        default:
            return -1;
    }
}

int read_instruction(
    struct Instruction64 *ret,
    struct InstructionMsg *msg
) {
    int ok;
    ok = read_op(&ret->op, msg->opcode);
    if (ok < 0) {
        return ok;
    }

    ok = deserialize_reg(&ret->rRet, msg->result_register);
    if (ok < 0) {
        return ok;
    }

    ok = deserialize_reg(&ret->rLeft, msg->left_register);
    if (ok < 0) {
        return ok;
    }

    ok = deserialize_reg(&ret->rRight, msg->right_register);
    if (ok < 0) {
        return ok;
    }

    return ok;
}

void write_reg(struct ccp_priv_state *state, u64 value, struct Register reg) {
    switch (reg.type) {
        case PERM_REG:
            state->state_registers[reg.index] = value;
            break;
        case TMP_REG:
            state->tmp_registers[reg.index] = value;
            break;
        default:
            break;
    }
}

void reset_state(struct ccp_priv_state *state) {
    u8 i;
    struct Instruction64 current_instruction;

    // reset the implicit registers
    state->state_registers[0] = 0; // isUrgent

    for (i = 0; i < state->num_instructions; i++) {
        current_instruction = state->fold_instructions[i];
        switch (current_instruction.op) {
            case DEF64:
                // set the default value of the state register
                write_reg(state, current_instruction.rRight.value, current_instruction.rLeft);
                break;
            default:
                // DEF instructions are only at the beginnning
                // Once we see a non-DEF, can stop.
                // Add 1 for the implicit isUrgent return register
                state->num_to_return = i + 1;
                return; 
        }
    }
}

u64 read_reg(struct ccp_priv_state *state, struct ccp_primitives* primitives, struct Register reg) {
    switch (reg.type) {
        case PERM_REG:
            return state->state_registers[reg.index];
        case TMP_REG:
            return state->tmp_registers[reg.index];
        case CONST_REG:
            switch (reg.index) {
                case ACK:
                    return primitives->ack;
                case ECN:
                    return (u64)primitives->ecn;
                case LOSS:
                    return primitives->loss;
                case RCVRATE:
                    return primitives->rcvrate;
                case RTT:
                    return primitives->rtt;
                case SNDCWND:
                    return primitives->sndcwnd;
                case SNDRATE:
                    return primitives->sndrate;
                default:
                    return 0;
            }
            break;
        default:
            return 0;
    }
} 

extern int send_measurement(
    struct ccp_connection *dp,
    u64 *fields,
    u8 num_fields
);

void measurement_machine(struct ccp_connection *ccp) {
    struct ccp_priv_state *state = get_ccp_priv_state(ccp);
    struct ccp_primitives* primitives = ccp->get_ccp_primitives(ccp);
    u8 i;
    u64 arg0; // extra arg for ewma, if, not if
    u64 arg1;
    u64 arg2;
    struct Instruction64 current_instruction;
    for (i = 0; i < state->num_instructions; i++) {
        current_instruction = state->fold_instructions[i];
        arg1 = read_reg(state, primitives, current_instruction.rLeft);
        arg2 = read_reg(state, primitives, current_instruction.rRight);
        switch (current_instruction.op) {
            case ADD64:
                write_reg(state, myadd64(arg1, arg2), current_instruction.rRet);
                break;
            case DIV64:
                write_reg(state, mydiv64(arg1, arg2), current_instruction.rRet);
                break;
            case EQUIV64:
                write_reg(state, myequiv64(arg1, arg2), current_instruction.rRet);
                break;
            case EWMA64: // arg0 = current, arg2 = new, arg1 = constant
                arg0 = read_reg(state, primitives, current_instruction.rRet); // current state
                write_reg(state, myewma64(arg1, arg0, arg2), current_instruction.rRet);
                break;
            case GT64:
                write_reg(state, mygt64(arg1, arg2), current_instruction.rRet);
                break;
            case LT64:
                write_reg(state, mylt64(arg1, arg2), current_instruction.rRet);
                break;
            case MAX64:
                write_reg(state, mymax64(arg1, arg2), current_instruction.rRet);
                break;
            case MIN64:
                write_reg(state, mymin64(arg1, arg2), current_instruction.rRet);
                break;
            case MUL64:
                write_reg(state, mymul64(arg1, arg2), current_instruction.rRet);
                break;
            case SUB64:
                write_reg(state, mysub64(arg1, arg2), current_instruction.rRet);
                break;
            case MAX64WRAP:
                write_reg(state, mymax64_wrap(arg1, arg2), current_instruction.rRet);
                break;
            case IFCNT64: // if arg1, adds 1 to register in rRight and stores it in rRet
                if (arg1 == 1) {
                    write_reg(state, myadd64(1, arg2), current_instruction.rRet);
                }
                break;
            case IFNOTCNT64:
                if (arg1 == 0) {
                    write_reg(state, myadd64(1, arg2), current_instruction.rRet);
                }
                break;
            case BIND64: // take arg2, and put it in rRet
                write_reg(state, arg2, current_instruction.rRet);
            default:
                break;
        }
    };

    if (state->state_registers[0] == 1) { // isUrgent register set
        // immediately send measurement state to CCP, bypassing send pattern
        struct ccp_priv_state *state = get_ccp_priv_state(ccp);
        send_measurement(ccp, state->state_registers, state->num_to_return);
        // reset isUrgent register to 0
        state->state_registers[0] = 0;
    }
}
