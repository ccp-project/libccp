#include "measurement_machine.h"

#define CCP_FRAC_DENOM 100
#define CCP_EWMA_RECENCY 60

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

// loads dummy instructions into this map for me to test with
// eventually -> will parse real instructions from the userspace thing
// this function is terrible - will eventually not be there
void load_dummy_instr(struct ccp_instruction_list *instructions) {
    int i;
    // space for the array should already be allocated
    struct Register ack_state = { .type = STATE_REG, .index = ACK, .value = 0 };
    struct Register rtt_state = { .type = STATE_REG, .index = RTT, .value = 0 };
    struct Register loss_state = { .type = STATE_REG, .index = LOSS, .value = 0 };
    struct Register rin_state = { .type = STATE_REG, .index = RIN, .value = 0 };
    struct Register rout_state = { .type = STATE_REG, .index = ROUT, .value = 0 };

    // primitive state
    struct Register ack_prim = { .type = PRIMITIVE_REG, .index = ACK, .value = 0 };
    struct Register rtt_prim = { .type = PRIMITIVE_REG, .index = RTT, .value = 0 };
    struct Register loss_prim = { .type = PRIMITIVE_REG, .index = LOSS, .value = 0 };
    struct Register rin_prim = { .type = PRIMITIVE_REG, .index = RIN, .value = 0 };
    struct Register rout_prim = { .type = PRIMITIVE_REG, .index = ROUT, .value = 0 };

    // extra instructions for ewma constant
    struct Register ewma_constant = { .type = CONST_REG, .index = 0, .value = 60 };

    // instruction structs
    struct Instruction64 ack_instr = { .op = MAX64, .r1 = ack_state, .r2 = ack_prim, .rStore = ack_state };
    struct Instruction64 rtt_instr = { .op = EWMA64, .r1 = ewma_constant, .r2 = rtt_prim, .rStore = rtt_state }; // * special - r1 is actually rtt State reg
    struct Instruction64 loss_instr = { .op = ADD64, .r1 = loss_state, .r2 = loss_prim, .rStore = loss_state };
    struct Instruction64 rin_instr = { .op = EWMA64, .r1 = ewma_constant, .r2 = rin_prim, .rStore = rin_state };
    struct Instruction64 rout_instr = { .op = EWMA64, .r1 = ewma_constant, .r2 = rout_prim, .rStore = rout_state };

    // load the instructions
    instructions->fold_instructions[0] = ack_instr;
    instructions->fold_instructions[1] = rtt_instr;
    instructions->fold_instructions[2] = loss_instr;
    instructions->fold_instructions[3] = rin_instr;
    instructions->fold_instructions[4] = rout_instr;
    instructions->num_instructions =5;
    for ( i = 0; i < MAX_STATE_REG; i++ ) {
        instructions->state_registers[i] = 0;
    }
    //printk("In load dummy instructions function\n");
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

    ok = deserialize_reg(&ret->rStore, msg->result_register);
    if (ok < 0) {
        return ok;
    }

    ok = deserialize_reg(&ret->r1, msg->left_register);
    if (ok < 0) {
        return ok;
    }

    ok = deserialize_reg(&ret->r2, msg->right_register);
    if (ok < 0) {
        return ok;
    }

    return ok;
}

// TODO move?
void load_primitives( struct sock *sk, const struct rate_sample *rs) {
    // load the primitive registers of the rate sample - convert all to u64
    // raw values, not averaged
    struct tcp_sock *tp = tcp_sk(sk);
    struct ccp *ca = inet_csk_ca(sk);
    u64 ack = (u64)(tp->snd_una);
    u64 rtt = (u64)(rs->rtt_us);
    u64 loss = (u64)(rs->losses);
    u64 rin = 0; // send bandwidth in bytes per second
    u64 rout = 0; // recv bandwidth in bytes per second
    int measured_valid_rate = rate_sample_valid(rs);
    pr_info("LOSS is %llu\n", loss);
    if ( measured_valid_rate == 0 ) {
       rin = rout  = (u64)rs->delivered * MTU * S_TO_US;
       do_div(rin, rs->snd_int_us);
       do_div(rout, rs->rcv_int_us);
    } else {
        return;
    }
    ca->mmt.ack = ack;
    ca->mmt.rtt = rtt;
    ca->mmt.loss = loss;
    ca->mmt.rin = rin;
    ca->mmt.rout = rout;
    return;
}

// TODO move?
// read values given a register
u64 read_reg(struct Register reg, struct ccp *ca, struct ccp_instruction_list* instr) {
    switch (reg.type) {
        case STATE_REG:
            return instr->state_registers[reg.index];
        case TMP_REG:
            return instr->tmp_registers[reg.index];
        case PRIMITIVE_REG:
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
}

// TODO move?
// write values given a register and a value
void write_reg(struct Register reg, u64 value, struct ccp_instruction_list *instr) {
    switch (reg.type) {
        case STATE_REG:
            pr_info("valu: %llu, index: %d\n", value, reg.index);
            instr->state_registers[reg.index] = value;
            break;
        case TMP_REG:
            instr->tmp_registers[reg.index] = value;
            break;
        default:
            pr_info("Trying to write into register with type %d\n", reg.type);
            break;
    }

}

// TODO move?
void update_state_registers(struct ccp *ca) {
    // updates dates all the state registers
    // first grab the relevant instruction set
    struct ccp_instruction_list *instr;
    // for now - just RTT - at state index 0
    int i;
    u64 arg1;
    u64 arg2;
    u64 arg0; // for ewma and if and not if
    int num_instructions;
    struct Instruction64 current_instruction;
    pr_info("about to try to dereference the instr_list for ccp index %d\n", ca->ccp_index);
    instr = ccp_instruction_list_lookup(ca->ccp_index);
    pr_info("deferenced the instr_list for ccp index %d\n", ca->ccp_index);

    num_instructions = instr->num_instructions;
    pr_info("Num instr is %d\n", num_instructions);
    for ( i = 0; i < num_instructions; i++ ) {
        current_instruction = instr->fold_instructions[i];
        pr_info("Trying to read registers");
        arg1 = read_reg(current_instruction.r1, ca, instr);
        arg2 = read_reg(current_instruction.r2, ca, instr);
        pr_info("Op: %d, arg1: %llu, arg2: %llu\n", current_instruction.op, arg1, arg2);
        switch (current_instruction.op) {
            case ADD64:
                pr_info("Reg 1 type: %d, Reg 1 index: %d\n", current_instruction.r1.type, current_instruction.r1.index);
                pr_info("Arg1: %llu, Arg2: %llu\n", arg1, arg2);
                write_reg(current_instruction.rStore, myadd64(arg1, arg2), instr);
                break;
            case DIV64:
                write_reg(current_instruction.rStore, mydiv64(arg1, arg2), instr);
                break;
            case EQUIV64:
                write_reg(current_instruction.rStore, myequiv64(arg1, arg2), instr);
                break;
            case EWMA64:
                arg0 = read_reg(current_instruction.rStore, ca, instr);
                write_reg(current_instruction.rStore, myewma64(arg1, arg0, arg2), instr);
                break;
            case GT64:
                write_reg(current_instruction.rStore, mygt64(arg1, arg2), instr);
                break;
            case LT64:
                write_reg(current_instruction.rStore, mylt64(arg1, arg2), instr);
                break;
            case MAX64:
                write_reg(current_instruction.rStore, mymax64(arg1, arg2), instr);
                break;
            case MIN64:
                write_reg(current_instruction.rStore, mymin64(arg1, arg2), instr);
                break;
            case MUL64:
                write_reg(current_instruction.rStore, mymul64(arg1, arg2), instr);
                break;
            case SUB64:
                write_reg(current_instruction.rStore, mysub64(arg1, arg2), instr);
                break;
            case IFCNT64: // if arg1, adds 1 to register in rStore
                if (arg1 == 1) {
                    write_reg(current_instruction.rStore, myadd64(1, arg2), instr);                 
                }
                break;
            case IFNOTCNT64:
                if (arg1 == 0) {
                    write_reg(current_instruction.rStore, myadd64(1, arg2), instr);
                }
                break;
            case BIND64: // take arg1, and put it in rStore
                pr_info("Arg 1 we're gonna write in is %llu\n", arg1);
                write_reg(current_instruction.rStore, arg1, instr);
            default:
                break;
            
        }

    }
}
