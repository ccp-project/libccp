#include "ccp_priv.h"

#ifdef __KERNEL__
#include <linux/slab.h> // kmalloc
#include <linux/string.h> // memcpy,memset
#else
#include <stdlib.h>
#include <string.h>
#endif

int init_ccp_priv_state(struct ccp_datapath *datapath, struct ccp_connection *conn) {
    struct ccp_priv_state *state;

    conn->state = __CALLOC__(1, sizeof(struct ccp_priv_state));
    state = (struct ccp_priv_state*) conn->state;

    state->sent_create = false;
    state->implicit_time_zero = datapath->time_zero;
    state->program_index = 0;
    state->staged_program_index = -1;

    conn->datapath = datapath;

    return 0;
}

void free_ccp_priv_state(struct ccp_connection *conn) {
    struct ccp_priv_state *state = get_ccp_priv_state(conn);
    __FREE__(state);
}

__INLINE__ struct ccp_priv_state* get_ccp_priv_state(struct ccp_connection *conn) {
    return (struct ccp_priv_state*) conn->state;
}

// lookup datapath program using program ID
// returns  NULL on error
struct DatapathProgram* datapath_program_lookup(struct ccp_datapath *datapath, u16 pid) {
    struct DatapathProgram *prog;
    struct DatapathProgram *programs = (struct DatapathProgram*) datapath->programs;

    // bounds check
    if (pid == 0) {
        libccp_warn("no datapath program set\n");
        return NULL;
    } else if (pid > datapath->max_programs) {
        libccp_warn("program index out of bounds: %d\n", pid);
        return NULL;
    }

    prog = &programs[pid-1];
    if (prog->index != pid) {
        libccp_warn("index mismatch: pid %d, index %d", pid, prog->index);
        return NULL;
    }

    return prog;

}
