/* CCP Datapath Connection Map
 *
 * When we receive a message from userspace CCP, we are not
 * in the flow context and need to access state (e.g. primitives) for
 * the appropriate connection.
 *
 * So, we maintain a map of ccp sock_id -> flow state information.
 * This flow state information is the API that datapaths must implement to support CCP.
 */
#ifndef CCP_H
#define CCP_H

#include "serialize.h"
#include "send_machine.h"
#include "measurement_machine.h"

#include <linux/types.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define MAX_INSTRUCTIONS 20

struct ccp_primitives {
    u64 ack;
    u64 rtt;
    u64 loss;
    u64 rin;
    u64 rout;
};

// CCP connection lookup
struct ccp_connection {
    // the index of this array element
    u16 index;

    // control primitives
    void (*set_cwnd)(struct ccp_connection *ccp, u32 cwnd);
    void (*set_rate_abs)(struct ccp_connection *ccp, u32 rate);
    void (*set_rate_rel)(struct ccp_connection *ccp, u32 rate);

    // measurement primitives
    struct ccp_primitives* (*get_ccp_primitives)(struct ccp_connection *ccp);

    // IPC communication
    int (*send_msg)(char *msg, int msg_size);

    // time management functions
    u32 (*now)(void); // the current time in datapath time units
    u32 (*after_usecs)(u32 usecs); // <usecs> microseconds from now in datapath time units

    // send machine state
    u8 num_pattern_states; // 1 B
    struct PatternState pattern[MAX_INSTRUCTIONS];
    u8 curr_pattern_state; // 1 B
    u32 next_event_time; // 4 B

    // measure machine state
    // number of instructions
    int num_instructions;
    // array of instructions
    struct Instruction64 fold_instructions[MAX_INSTRUCTIONS];
    // state registers
    u64 state_registers[MAX_STATE_REG];
    // tmp registers
    u64 tmp_registers[MAX_TMP_REG];

    // 88 bytes of datapath-specific state
    u8 impl[88];
};

/* Allocate a map for ccp connections upon module load.
 *
 * initialize the ccp active connections list
 * return -1 on allocation failure, should abort loading module
 */
int ccp_init_connection_map(void);

/* Free the map for ccp connections upon module unload.
 */
void ccp_free_connection_map(void);

/* Upon a new flow starting,
 * put a new connection into the active connections list
 *
 * returns the index at which the connection was placed; this index shall be used as the CCP socket id
 * return 0 on error
 */
struct ccp_connection *ccp_connection_start(struct ccp_connection *sk);

/* Upon a connection ending,
 * free its slot in the connection map.
 */
void ccp_connection_free(u16 sid);

/* While a flow is active, look up its CCP connection information.
 */
struct ccp_connection *ccp_connection_lookup(u16 sid);

/* Get the implementation-specific state of the ccp_connection.
 */
inline void *ccp_get_impl(struct ccp_connection *dp) {
    return (void*) &dp->impl;
}

inline int ccp_set_impl(
    struct ccp_connection *dp, 
    void *impl, 
    int impl_size
);

/* Callback to pass to IPC for incoming messages.
 * Cannot take ccp_connection as an argument, since it's a callback.
 * Must look up ccp_connction from socket_id.
 * buf: the received message, of size bufsize.
 */
void ccp_read_msg(
    char *buf
);

int send_conn_create(struct ccp_connection *dp, u32 startSeq);
int send_measurement(struct ccp_connection *dp, u64 *fields, u8 num_fields);
int send_drop_notif(struct ccp_connection *dp, enum drop_type dtype);

/* Should be called along with the ACK clock.
 *
 * Will invoke the send and measurement machines.
 */
int ccp_invoke(struct ccp_connection *dp);

//int ccp_init_fold_map(void);
//void ccp_free_fold_map(void);
//struct ccp_instruction_list *ccp_instruction_list_lookup(u16 sid);

#endif
