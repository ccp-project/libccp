#include "ccp_priv.h"

#ifdef __USRLIB__
#include <stdlib.h>
#else
#include <linux/slab.h> // kmalloc
#endif

extern struct ccp_datapath *datapath;

int init_ccp_priv_state(struct ccp_connection *conn) {
    struct ccp_priv_state *state;
#ifdef __USRLIB__
    conn->state = malloc(sizeof(struct ccp_priv_state));
#else
    conn->state = kmalloc(sizeof(struct ccp_priv_state), GFP_KERNEL);
#endif
    state = (struct ccp_priv_state*) conn->state;
    state->sent_create = false;
    state->num_expressions = 0;
    state->num_instructions = 0;
    state->num_to_return = 0;
    state->implicit_time_zero = datapath->time_zero;
    return 0;
}

__INLINE__ struct ccp_priv_state* get_ccp_priv_state(struct ccp_connection *conn) {
    return (struct ccp_priv_state*) conn->state;
}
