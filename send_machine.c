#include "ccp.h"
#include "send_machine.h"

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

static inline void do_report(
    struct ccp_connection *ccp
) {
    // TODO get measurement outputs from fold machine state
    //nl_send_measurement(cpl->ccp_index, mmt);
}

static inline void do_wait_abs(
    struct ccp_connection *ccp,
    u32 wait_us
) {
    //pr_info("waiting %u us\n", wait_us);
    ccp->next_event_time = ccp->after_usecs(wait_us);
}

static inline void do_wait_rel(
    struct ccp_connection *ccp,
    u32 rtt_factor
) {
    u64 rtt_us = ccp->get_ccp_primitives(ccp)->rtt;
    u64 wait_us = rtt_factor * rtt_us;
    wait_us /= 100;
    //do_div(wait_us, 100);
    //pr_info("waiting %llu us (%u/100 rtts) (rtt = %llu us)\n", wait_us, rtt_factor, rtt_us);
    do_wait_abs(ccp, wait_us);
}

void send_machine(struct ccp_connection *ccp) {
    int ok;
    u32 first_ack;
    struct PatternState ev;
    if (ccp->num_pattern_states == 0) {
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

    if (ccp->now() > ccp->next_event_time) { // TODO handle wraparound
        ccp->curr_pattern_state = (ccp->curr_pattern_state + 1) % ccp->num_pattern_states;
        //pr_info("curr pattern event: %d\n", ccp->currPatternEvent);
    } else {
        return;
    }

    ev = ccp->pattern[ccp->curr_pattern_state];
    switch (ev.type) {
    case SETRATEABS:
        ccp->set_rate_abs(ccp, ev.val);
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
