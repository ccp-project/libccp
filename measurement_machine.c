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
        default:
            return -1;
    }
}

int deserialize_reg(struct Register *ret, u8 reg) {
    switch (reg >> 6) {
        case 0: // immediate
            // TODO 
            return 0;
        case 1: // primitive
            // TODO
            return 0;
        case 2: // tmp
            // TODO
            return 0;
        case 3: // output/permanent
            // TODO
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

void measurement_machine(struct ccp_connection *ccp) {
    struct ccp_priv_state *state = get_ccp_priv_state(ccp);
    // TODO implement

}

// TODO move?
// read values given a register
/*u64 read_reg(struct Register reg, struct ccp *ca, struct ccp_connection* ccp) {
    switch (reg.type) {
        case PERM_REG:
            return ccp->state_registers[reg.index];
        case TMP_REG:
            return ccp->tmp_registers[reg.index];
        case CONST_REG:
            switch (reg.index) {
                case ACK:
                    return ca->mmt.ack;
                case RTT:
                    return ca->mmt.rtt;
                case LOSS:
                    return ca->mmt.loss;
                case RIN:
                    return ca->mmt.rin;
                case ROUT:
                    return ca->mmt.rout;
                default:
                    return 0;
            }
            break;
        case CONST_REG:
            return reg.value;
        default:
            return 0;
    }
    return 0;
}*/

// TODO move?
// write values given a register and a value
/*void write_reg(struct Register reg, u64 value, struct ccp_connection *ccp) {
    switch (reg.type) {
        case PERM_REG:
            pr_info("valu: %llu, index: %d\n", value, reg.index);
            ccp->state_registers[reg.index] = value;
            break;
        case TMP_REG:
            ccp->tmp_registers[reg.index] = value;
            break;
        default:
            pr_info("Trying to write into register with type %d\n", reg.type);
            break;
    }

}*/

// TODO move?
/*void update_state_registers(struct ccp *ca) {
    // updates dates all the state registers
    // first grab the relevant instruction set
    struct ccp_connection *ccp;
    // for now - just RTT - at state index 0
    int i;
    u64 arg1;
    u64 arg2;
    u64 arg0; // for ewma and if and not if
    int num_instructions;
    struct Instruction64 current_instruction;
    pr_info("about to try to dereference the instr_list for ccp index %d\n", ca->ccp_index);
    instr = ccp_connection_lookup(ca->ccp_index);
    pr_info("deferenced the instr_list for ccp index %d\n", ca->ccp_index);

    num_instructions = ccp->num_instructions;
    pr_info("Num instr is %d\n", num_instructions);
    for ( i = 0; i < num_instructions; i++ ) {
        current_instruction = ccp->fold_instructions[i];
        pr_info("Trying to read registers");
        arg1 = read_reg(current_instruction.rLeft, ca, instr);
        arg2 = read_reg(current_instruction.rRight, ca, instr);
        pr_info("Op: %d, arg1: %llu, arg2: %llu\n", current_instruction.op, arg1, arg2);
        switch (current_instruction.op) {
            case ADD64:
                pr_info("Reg 1 type: %d, Reg 1 index: %d\n", current_instruction.rLeft.type, current_instruction.rLeft.index);
                pr_info("Arg1: %llu, Arg2: %llu\n", arg1, arg2);
                write_reg(current_instruction.rRet, myadd64(arg1, arg2), ccp);
                break;
            case DIV64:
                write_reg(current_instruction.rRet, mydiv64(arg1, arg2), ccp);
                break;
            case EQUIV64:
                write_reg(current_instruction.rRet, myequiv64(arg1, arg2), ccp);
                break;
            case EWMA64:
                arg0 = read_reg(current_instruction.rRet, ca, instr);
                write_reg(current_instruction.rRet, myewma64(arg1, arg0, arg2), ccp);
                break;
            case GT64:
                write_reg(current_instruction.rRet, mygt64(arg1, arg2), ccp);
                break;
            case LT64:
                write_reg(current_instruction.rRet, mylt64(arg1, arg2), ccp);
                break;
            case MAX64:
                write_reg(current_instruction.rRet, mymax64(arg1, arg2), ccp);
                break;
            case MIN64:
                write_reg(current_instruction.rRet, mymin64(arg1, arg2), ccp);
                break;
            case MUL64:
                write_reg(current_instruction.rRet, mymul64(arg1, arg2), ccp);
                break;
            case SUB64:
                write_reg(current_instruction.rRet, mysub64(arg1, arg2), ccp);
                break;
            case IFCNT64: // if arg1, adds 1 to register in rRet
                if (arg1 == 1) {
                    write_reg(current_instruction.rRet, myadd64(1, arg2), ccp);                 
                }
                break;
            case IFNOTCNT64:
                if (arg1 == 0) {
                    write_reg(current_instruction.rRet, myadd64(1, arg2), ccp);
                }
                break;
            case BIND64: // take arg1, and put it in rRet
                pr_info("Arg 1 we're gonna write in is %llu\n", arg1);
                write_reg(current_instruction.rRet, arg1, ccp);
            default:
                break;
            
        }

    }
}*/
