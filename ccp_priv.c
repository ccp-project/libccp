#include "ccp_priv.h"
#include <linux/slab.h> // kmalloc

int init_ccp_priv_state(struct ccp_connection *ccp) {
    struct ccp_priv_state *state;
    ccp->state = kmalloc(sizeof(struct ccp_priv_state), GFP_KERNEL);
    state = (struct ccp_priv_state*) ccp->state;
    // initialize send_machine state in conn
    state->next_event_time = ccp->now(); // get time from datapath
    state->curr_pattern_state = 0;
    state->num_pattern_states = 0;

    // TODO initialize measurement_machine state in dp
    
    return 0;
}

inline struct ccp_priv_state* get_ccp_priv_state(struct ccp_connection *ccp) {
    return (struct ccp_priv_state*) ccp->state;
}
