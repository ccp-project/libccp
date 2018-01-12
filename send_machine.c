#include "ccp_priv.h"

#ifdef __USRLIB__
#include <string.h>
#else
#include <linux/string.h>
#endif

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
    struct ccp_connection *conn,
    u64 *fields,
    u8 num_fields
);

static inline void do_report(
    struct ccp_connection *conn
) {
    struct ccp_priv_state *state = get_ccp_priv_state(conn);
    send_measurement(conn, state->state_registers, state->num_to_return);
    reset_state(state);
}

static inline void do_wait_abs(
    struct ccp_connection *conn,
    u32 wait_ns
) {
    struct ccp_priv_state *state = get_ccp_priv_state(conn);
    state->next_event_time = conn->after_usecs(wait_ns / 1000);
}

static inline void do_wait_rel(
    struct ccp_connection *conn,
    u32 rtt_factor
) {
    u64 rtt_us = conn->prims.rtt_sample_us;
    // rtt_factor is * 1000 in serialization on the userspace side
    // so rtt_factor * (us) has units nanoseconds
    u64 wait_ns = rtt_factor * rtt_us;
    do_wait_abs(conn, wait_ns);
}

static inline void set_rate_with_cwnd_abs(
    struct ccp_connection *conn,
    u32 rate
) {
    struct ccp_primitives *prims;
    u32 cwnd, rtt_us;

    prims = &conn->prims;
    conn->set_rate_abs(conn, rate);
    rtt_us = prims->rtt_sample_us;
    if (prims->packets_in_flight > 0) {
        cwnd = rate * rtt_us + 3 * (prims->bytes_in_flight / prims->packets_in_flight);
    } else {
        cwnd = rate * rtt_us;
    }

    conn->set_cwnd(conn, cwnd);
    return;
}

void send_machine(struct ccp_connection *conn) {
    struct PatternState ev;
    struct ccp_priv_state *state = get_ccp_priv_state(conn);
    if (conn->now() > state->next_event_time) { // TODO handle wraparound
        state->curr_pattern_state = (state->curr_pattern_state + 1) % state->num_pattern_states;
        //pr_info("curr pattern event: %d\n", conn->currPatternEvent);
    } else {
        return;
    }

    ev = state->pattern[state->curr_pattern_state];
    switch (ev.type) {
    case SETRATEABS:
        conn->set_rate_abs(conn, ev.val);
        break;
    case SETRATEABSWITHCWND:
        set_rate_with_cwnd_abs(conn, ev.val);
        break;
    case SETCWNDABS:
        conn->set_cwnd(conn, ev.val);
        break;
    case SETRATEREL:
        conn->set_rate_rel(conn, ev.val);
        break;
    case WAITREL:
        do_wait_rel(conn, ev.val);
        break;
    case WAITABS:
        do_wait_abs(conn, ev.val);
        break;
    case REPORT:
        do_report(conn);
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
