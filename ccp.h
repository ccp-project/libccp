#ifndef CCP_H
#define CCP_H

#ifdef __KERNEL__
    #include <linux/types.h>
    #include <linux/module.h>
#else
    #include <stdbool.h>
    #include <pthread.h> // for mutex
#endif

#include "types.h"

#ifdef __CPLUSPLUS__
extern "C" {
#endif

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
    // target rate to maintain, in bytes/s
    u64 snd_rate;

    // amount of data available to be sent
    // NOT per-packet - an absolute measurement
    u32 bytes_pending;
};

// maximum string length for congAlg
#define  MAX_CONG_ALG_SIZE   64
/* Datapaths provide connection information to ccp_connection_start
 */
struct ccp_datapath_info {
    u32 init_cwnd;
    u32 mss;
    u32 src_ip;
    u32 src_port;
    u32 dst_ip;
    u32 dst_port;
    char congAlg[MAX_CONG_ALG_SIZE];
};

/* 
 * CCP state per connection. 
 * impl is datapath-specific, the rest are internal to libccp
 * for example, the linux kernel datapath uses impl to store a pointer to struct sock
 */
struct ccp_connection {
    // the index of this array element
    u16 index;

    u32 last_create_msg_sent;

    // struct ccp_primitives is large; as a result, we store it inside ccp_connection to avoid
    // potential limitations in the datapath
    // datapath should update this before calling ccp_invoke()
    struct ccp_primitives prims;
    
    // constant flow-level information
    struct ccp_datapath_info flow_info;

    // private libccp state for the send machine and measurement machine
    void *state;

    // datapath-specific per-connection state
    void *impl;

    // pointer back to parent datapath that owns this connection
    struct ccp_datapath *datapath;
};

enum ccp_log_level {
    TRACE,
    DEBUG,
    INFO,
    WARN,
    ERROR,
};

/*
 * Global CCP state provided by the datapath
 *
 * Callbacks:
 * 1. set_cwnd(): set the congestion window
 * 2. set_rate_abs(): set the rate
 *
 * Time functions 
 * 3. now(): return a notion of time.
 * 4. since_usecs(u32 then): elapsed microseconds since <then>.
 * 5. after_usecs(u32 usecs): return a time <usecs> microseconds in the future.
 *
 * Utility functions
 * 6.  send_msg(): send a message from datapath -> userspace CCP.
 * 7.  log(): (optional)
 */
struct ccp_datapath {
    // control primitives
    void (*set_cwnd)(struct ccp_connection *conn, u32 cwnd); 
    void (*set_rate_abs)(struct ccp_connection *conn, u32 rate);

    // IPC communication
    int (*send_msg)(struct ccp_connection *conn, char *msg, int msg_size);

    // logging
    void (*log)(struct ccp_datapath *dp, enum ccp_log_level level, const char* msg, int msg_size);

    // time management
    u64 time_zero;
    u64 (*now)(void); // the current time in datapath time units
    u64 (*since_usecs)(u64 then); // elapsed microseconds since <then>
    u64 (*after_usecs)(u64 usecs); // <usecs> microseconds from now in datapath time units

    size_t max_connections;
    // list of active connections this datapath is handling
    struct ccp_connection* ccp_active_connections;

    size_t max_programs;
    // list of datapath programs
    void *programs;
    
    // datapath-specific global state
    void *impl;
};

/* 
 * Initialize gloal state and allocate a map for ccp connections upon module load.
 *
 * return -1 on allocation failure, should abort loading module
 */
int ccp_init(struct ccp_datapath *dp);

/* Free the global struct and map for ccp connections upon module unload.
 */
void ccp_free(struct ccp_datapath *datapath);

/* Upon a new flow starting,
 * put a new connection into the active connections list
 *
 * returns the index at which the connection was placed; this index shall be used as the CCP socket id
 * return 0 on error
 */
struct ccp_connection *ccp_connection_start(struct ccp_datapath *datapath, void *impl, struct ccp_datapath_info *flow_info);

/* Upon a connection ending,
 * free its slot in the connection map.
 */
void ccp_connection_free(struct ccp_datapath *datapath, u16 sid);

/* While a flow is active, look up its CCP connection information.
 */
struct ccp_connection *ccp_connection_lookup(struct ccp_datapath *datapath, u16 sid);

/* Get the implementation-specific state of the ccp_connection.
 */
void *ccp_get_impl(struct ccp_connection *conn);

int ccp_set_impl(
    struct ccp_connection *conn, 
    void *ptr
);

/* Callback to pass to IPC for incoming messages.
 * Cannot take ccp_connection as an argument, since it's a callback.
 * Therefore, must look up ccp_connction from socket_id.
 * buf: the received message, of size bufsize.
 */
int ccp_read_msg(
    struct ccp_datapath *datapath, 
    char *buf,
    int bufsize
);

/* Should be called along with the ACK clock.
 *
 * Will invoke the send and measurement machines.
 */
int ccp_invoke(struct ccp_connection *conn);

#ifdef __CPLUSPLUS__
} // extern "C"
#endif

#endif
