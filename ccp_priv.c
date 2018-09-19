#include "ccp_priv.h"

#ifdef __KERNEL__
#include <linux/slab.h> // kmalloc
#include <linux/string.h> // memcpy,memset
#else
#include <stdlib.h>
#include <string.h>
#endif

extern struct ccp_datapath *datapath;

int init_ccp_priv_state(struct ccp_connection *conn) {
    struct ccp_priv_state *state;
#ifdef __KERNEL__
    conn->state = kmalloc(sizeof(struct ccp_priv_state), GFP_KERNEL);
#else
    conn->state = malloc(sizeof(struct ccp_priv_state));
#endif
    state = (struct ccp_priv_state*) conn->state;
    state->sent_create = false;
    state->implicit_time_zero = datapath->time_zero;
    memset(&state->pending_update, 0, sizeof(struct staged_update));
    return 0;
}

__INLINE__ struct ccp_priv_state* get_ccp_priv_state(struct ccp_connection *conn) {
    return (struct ccp_priv_state*) conn->state;
}
