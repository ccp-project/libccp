#include "ccp_priv.h"

#ifdef __KERNEL__
#include <linux/slab.h> // kmalloc
#else
#include <stdlib.h>
#endif

extern struct ccp_datapath *datapath;

int init_ccp_priv_state(struct ccp_connection *conn) {
    struct ccp_priv_state *state;
    conn->state = __MALLOC__(sizeof(struct ccp_priv_state));
    state = (struct ccp_priv_state*) conn->state;
    state->sent_create = false;
    state->implicit_time_zero = datapath->time_zero;
    return 0;
}

void free_ccp_priv_state(struct ccp_connection *conn) {
    struct ccp_priv_state *state = get_ccp_priv_state(conn);
    __FREE__(state);
}

__INLINE__ struct ccp_priv_state* get_ccp_priv_state(struct ccp_connection *conn) {
    return (struct ccp_priv_state*) conn->state;
}
