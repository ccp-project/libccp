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

#include <linux/types.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/* Datapaths must support these measurement primitives.
 * Each value is reported *per invocation*. 
 *
 * n.b. Ideally, an invocation is every packet, but datapaths might choose to call
 * ccp_invoke() less often.
 */
struct ccp_primitives {
    // newly acked, in-order bytes
    u32 bytes_acked;
    // newly acked, in-order packets
    u32 packets_acked;
    // out-of-order bytes
    u32 bytes_misordered;
    // out-of-order packets
    u32 packets_misordered;
    // bytes corresponding to ecn-marked packets
    u32 ecn_bytes;
    // ecn-marked packets
    u32 ecn_packets;

    // an estimate of the number of packets lost
    u32 lost_pkts_sample;
    // whether a timeout was observed
    bool was_timeout;

    // a recent sample of the round-trip time
    u64 rtt_sample_us;
    // sample of the sending rate, bytes / s
    u64 rate_outgoing;
    // sample of the receiving rate, bytes / s
    u64 rate_incoming;
    // the number of actual bytes in flight
    u32 bytes_in_flight;
    // the number of actual packets in flight
    u32 packets_in_flight;
    // the target congestion window to maintain, in bytes
    u32 snd_cwnd;
};

/* The CCP state for each connection.
 * The datapath is reponsible for supplying congestion control functions:
 * 1. the congestion window
 * 2. the rate
 * 3. a multiplicative modifier to the rate
 * as well as measurement primitives, with
 * 4. get_ccp_primitives()
 *
 * The datapath is also resonsible for providing utility functions to libccp,
 * so libccp can communicate with userspace CCP and have a notion of the ACK clock.
 * 5. send_msg(): send a message from datapath -> userspace CCP.
 * 6. now(): return a notion of time the send machine can use.
 * 7. after_usecs(u32 usecs): return a time <usecs> microseconds in the future.
 *
 * This struct also contains state for the send machine and measurement machine, and
 * impl: 88 bytes the datapath can use for storing state.
 * For example, the linux kernel datapath uses this space to store a pointer to struct sock*.
 */
struct ccp_connection {
    // the index of this array element
    u16 index;

    // struct ccp_primitives is large; as a result, we store it inside ccp_connection to avoid
    // potential limitations in the datapath
    // datapath should update this before calling ccp_invoke()
    struct ccp_primitives prims;

    // control primitives
    void (*set_cwnd)(struct ccp_connection *ccp, u32 cwnd); // TODO(eventually): consider setting cwnd in packets, not bytes
    void (*set_rate_abs)(struct ccp_connection *ccp, u32 rate);
    void (*set_rate_rel)(struct ccp_connection *ccp, u32 rate);

    // IPC communication
    int (*send_msg)(char *msg, int msg_size);

    // time management functions
    u32 (*now)(void); // the current time in datapath time units
    u32 (*after_usecs)(u32 usecs); // <usecs> microseconds from now in datapath time units

    // private libccp state for the send machine and measurement machine
    void *state;

    // datapath-specific state
    void *impl;
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

void load_dummy_instruction(struct ccp_connection *ccp);

/* Upon a new flow starting,
 * put a new connection into the active connections list
 *
 * returns the index at which the connection was placed; this index shall be used as the CCP socket id
 * return 0 on error
 */
struct ccp_connection *ccp_connection_start(struct ccp_connection *dp);

/* Upon a connection ending,
 * free its slot in the connection map.
 */
void ccp_connection_free(u16 sid);

/* While a flow is active, look up its CCP connection information.
 */
struct ccp_connection *ccp_connection_lookup(u16 sid);

/* Get the implementation-specific state of the ccp_connection.
 */
inline void *ccp_get_impl(struct ccp_connection *dp);

inline int ccp_set_impl(
    struct ccp_connection *dp, 
    void *ptr
);

/* Callback to pass to IPC for incoming messages.
 * Cannot take ccp_connection as an argument, since it's a callback.
 * Therefore, must look up ccp_connction from socket_id.
 * buf: the received message, of size bufsize.
 */
int ccp_read_msg(
    char *buf,
    int bufsize
);

/* Should be called along with the ACK clock.
 *
 * Will invoke the send and measurement machines.
 */
int ccp_invoke(struct ccp_connection *dp);

#endif
