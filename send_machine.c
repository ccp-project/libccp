#include "ccp_priv.h"

#include <linux/string.h>

int read_pattern(
    struct PatternState *seq,
    char *pattern,
    int numEvents
) {
    int i;
    for (i = 0; i < numEvents; i++) {
        memcpy(&(seq[i]), pattern, sizeof(struct PatternState));
        if (seq[i].size == 2 && seq[i].type == REPORT) {
            pattern += 2;
            seq[i].val = 0;
            continue;
        } else if (seq[i].size != 6) {
            // only report events are 2 bytes
            // all other events are 6 bytes
            return -1;
        }

        pattern += seq[i].size;
    }

    return 0;
}

extern int send_measurement(
    struct ccp_connection *dp,
    u64 *fields,
    u8 num_fields
);

static inline void do_report(
    struct ccp_connection *ccp
) {
    struct ccp_priv_state *state = get_ccp_priv_state(ccp);
    send_measurement(ccp, state->state_registers, state->num_to_return);
}

static inline void do_wait_abs(
    struct ccp_connection *ccp,
    u32 wait_ns
) {
    struct ccp_priv_state *state = get_ccp_priv_state(ccp);
    state->next_event_time = ccp->after_usecs(wait_ns / 1000);
}

static inline void do_wait_rel(
    struct ccp_connection *ccp,
    u32 rtt_factor
) {
    u64 rtt_us = ccp->get_ccp_primitives(ccp)->rtt;
    // rtt_factor is * 1000 in serialization on the userspace side
    // so rtt_factor * (us) has units nanoseconds
    u64 wait_ns = rtt_factor * rtt_us;
    do_wait_abs(ccp, wait_ns);
}

static inline void set_rate_with_cwnd_abs(
    struct ccp_connection *ccp,
    u32 rate
) {
    struct ccp_primitives *prims;
    u32 cwnd, rtt_us;

    prims = ccp->get_ccp_primitives(ccp);
    ccp->set_rate_abs(ccp, rate);
    rtt_us = prims->rtt;
    cwnd = rate * rtt_us + 3 * prims->mss;
    ccp->set_cwnd(ccp, cwnd);
    return;
}

extern int send_conn_create(
    struct ccp_connection *dp,
    u32 startSeq
);

void send_machine(struct ccp_connection *ccp) {
    int ok;
    u32 first_ack;
    struct PatternState ev;
    struct ccp_priv_state *state = get_ccp_priv_state(ccp);
    if (state->num_pattern_states == 0) {
        // try contacting the CCP again
        // index of pointer back to this sock for IPC callback
        // first ack to expect
        first_ack = ccp->get_ccp_primitives(ccp)->ack;
        ok = send_conn_create(ccp, first_ack);
        if (ok < 0) {
            //pr_info("failed to send create message: %d", ok);
        }

        return;
    }

    if (ccp->now() > state->next_event_time) { // TODO handle wraparound
        state->curr_pattern_state = (state->curr_pattern_state + 1) % state->num_pattern_states;
        //pr_info("curr pattern event: %d\n", ccp->currPatternEvent);
    } else {
        return;
    }

    ev = state->pattern[state->curr_pattern_state];
    switch (ev.type) {
    case SETRATEABS:
        ccp->set_rate_abs(ccp, ev.val);
        break;
    case SETRATEABSWITHCWND:
        set_rate_with_cwnd_abs(ccp, ev.val);
        break;
    case SETCWNDABS:
        ccp->set_cwnd(ccp, ev.val);
        break;
    case SETRATEREL:
        ccp->set_rate_rel(ccp, ev.val);
        break;
    case WAITREL:
        do_wait_rel(ccp, ev.val);
        break;
    case WAITABS:
        do_wait_abs(ccp, ev.val);
        break;
    case REPORT:
        do_report(ccp);
        break;
    }
}

//static void log_sequence(struct PatternEvent *seq, int numEvents) {
//    size_t  i;
//    struct PatternEvent ev;
//    pr_info("installed pattern:\n");
//    for (i = 0; i < numEvents; i++) {
//        ev = seq[i];
//        switch (ev.type) {
//        case SETRATEABS:
//            pr_info("[ev %lu] set rate %u\n", i, ev.val);
//            break;
//        case SETCWNDABS:
//            pr_info("[ev %lu] set cwnd %d\n", i, ev.val);
//            break;
//        case SETRATEREL:
//            pr_info("[ev %lu] set rate factor %u/100\n", i, ev.val);
//            break;
//        case WAITREL:
//            pr_info("[ev %lu] wait rtts %d/100\n", i, ev.val);
//            break;
//        case WAITABS:
//            pr_info("[ev %lu] wait %d us\n", i, ev.val);
//            break;
//        case REPORT:
//            pr_info("[ev %lu] send report\n", i);
//            break;
//        }
//    }
//}
