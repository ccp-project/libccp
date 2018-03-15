#include "ccp_priv.h"

#ifdef __USRLIB__
#include <string.h>
#else
#include <linux/string.h>
#endif

extern struct ccp_datapath *datapath;

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
    u64 wait_ns
) {
    struct ccp_priv_state *state = get_ccp_priv_state(conn);
    state->next_event_time = datapath->after_usecs(wait_ns / 1000);
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
    u64 cwnd, rtt_us;

    prims = &conn->prims;
    datapath->set_rate_abs(datapath, conn, rate);
    rtt_us = prims->rtt_sample_us;
    cwnd = (rate * rtt_us) / 1000000 + 3 * conn->flow_info.mss;
    datapath->set_cwnd(datapath, conn, (u32) cwnd);
    return;
}

void send_machine(struct ccp_connection *conn) {
    struct PatternState ev;
    struct ccp_priv_state *state = get_ccp_priv_state(conn);
    if (datapath->now() > state->next_event_time) { // TODO handle wraparound
        state->curr_pattern_state = (state->curr_pattern_state + 1) % state->num_pattern_states;
        //pr_info("curr pattern event: %d\n", conn->currPatternEvent);
    } else {
        return;
    }

    ev = state->pattern[state->curr_pattern_state];
    switch (ev.type) {
    case SETRATEABS:
        datapath->set_rate_abs(datapath, conn, ev.val);
        break;
    case SETRATEABSWITHCWND:
        set_rate_with_cwnd_abs(conn, ev.val);
        break;
    case SETCWNDABS:
        datapath->set_cwnd(datapath, conn, ev.val);
        break;
    case SETRATEREL:
        datapath->set_rate_rel(datapath, conn, ev.val);
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
