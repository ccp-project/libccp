#include "ccp.h"
#include "stdio.h"

u32 now_us; // emulated time in microseconds

struct test_conn {
    u32 curr_cwnd;
    u32 curr_rate;
};

static void test_ccp_set_cwnd(struct ccp_datapath *dp, struct ccp_connection *conn, u32 cwnd) {
    struct test_conn *c = (struct test_conn*) ccp_get_impl(conn);
    c->curr_cwnd = cwnd;
}

static void test_ccp_set_rate(struct ccp_datapath *dp, struct ccp_connection *conn, u32 rate) {
    struct test_conn *c = (struct test_conn*) ccp_get_impl(conn);
    c->curr_rate = rate;
}

static void test_ccp_set_rate_rel(struct ccp_datapath *dp, struct ccp_connection *conn, u32 cwnd) {
    return;
}

static int test_ccp_send_msg(struct ccp_datapath *dp, struct ccp_connection *conn, char *msg, int msg_size) {
    printf("CCP sent message: [");
    for (int i = 0; i < msg_size; i++) {
        printf("%02x, ", msg[i]);
    }
    printf("]\n");
    return 0;
}

static u32 test_ccp_time_now(void) {
    return now_us;
}

static u32 test_ccp_since_usecs(u32 then) {
    return then - now_us;
}

static u32 test_ccp_after_usecs(u32 usecs) {
    return now_us + usecs;
}

int main(int argc, char **argv) {
    int ok = 0;
    now_us = 0;
    struct ccp_datapath dp = {
        .set_cwnd = test_ccp_set_cwnd,
        .set_rate_abs = test_ccp_set_rate,
        .set_rate_rel = test_ccp_set_rate_rel,
        .send_msg = test_ccp_send_msg,
        .now = test_ccp_time_now,
        .since_usecs = test_ccp_since_usecs,
        .after_usecs = test_ccp_after_usecs,
    };

    struct test_conn my_conn = {
        .curr_cwnd = 0,
        .curr_rate = 0,
    };

    printf("starting libccp test...\n");

    ok = ccp_init(&dp);
    if (ok < 0) {
        printf("ccp_init error: %d\n", ok);
        goto ret;
    }

    // a fake flow arrives!
    struct ccp_datapath_info info = {
        .init_cwnd = 100,
        .mss = 10,
        .src_ip = 1,
        .src_port = 2,
        .dst_ip = 3, 
        .dst_port = 4,
        .congAlg = "test",
    };

    struct ccp_connection *conn = ccp_connection_start((void*) &my_conn, &info);

    printf("start ok\n");

    char fold[360] = {
        4,
        180,
        1,    0,    0,    0,
        35,   0,    0,    0,
        14,   200,  8,    0,  0,  192,  255,  255,  255,  63,
        14,   197,  5,    0,  0,  192,  0,    0,    0,    0,
        14,   194,  2,    0,  0,  192,  0,    0,    0,    0,
        14,   198,  6,    0,  0,  192,  0,    0,    0,    0,
        14,   195,  3,    0,  0,  192,  0,    0,    0,    0,
        14,   202,  10,   0,  0,  192,  0,    0,    0,    0,
        14,   201,  9,    0,  0,  192,  0,    0,    0,    0,
        14,   196,  4,    0,  0,  192,  0,    0,    0,    0,
        14,   199,  7,    0,  0,  192,  0,    0,    0,    0,
        1,    197,  5,    0,  0,  192,  12,   0,    0,    64,
        1,    199,  7,    0,  0,  192,  8,    0,    0,    64,
        10,   128,  8,    0,  0,  192,  8,    0,    0,    64,
        1,    200,  8,    0,  0,  192,  0,    0,    0,    128,
        10,   128,  8,    0,  0,  192,  255,  255,  255,  63,
        1,    200,  8,    0,  0,  192,  0,    0,    0,    128,
        0,    128,  2,    0,  0,  192,  0,    0,    0,    64,
        1,    194,  2,    0,  0,  192,  0,    0,    0,    128,
        0,    128,  3,    0,  0,  192,  3,    0,    0,    64,
        1,    195,  3,    0,  0,  192,  0,    0,    0,    128,
        1,    196,  4,    0,  0,  192,  6,    0,    0,    64,
        1,    198,  6,    0,  0,  192,  7,    0,    0,    64,
        1,    192,  0,    0,  0,  192,  7,    0,    0,    64,
        5,    128,  4,    0,  0,  192,  0,    0,    0,    0,
        6,    192,  0,    0,  0,  192,  0,    0,    0,    128,
        13,   128,  8,    0,  0,  64,   8,    0,    0,    192,
        2,    129,  0,    0,  0,  128,  2,    0,    0,    0,
        1,    203,  11,   0,  0,  192,  1,    0,    0,    128,
        11,   128,  180,  5,  0,  0,    8,    0,    0,    64,
        2,    129,  0,    0,  0,  128,  144,  56,   0,    0,
        5,    130,  1,    0,  0,  128,  11,   0,    0,    192,
        1,    204,  12,   0,  0,  192,  2,    0,    0,    128,
        0,    128,  9,    0,  0,  192,  1,    0,    0,    0,
        6,    201,  12,   0,  0,  192,  0,    0,    0,    128,
        0,    128,  10,   0,  0,  192,  1,    0,    0,    0,
        6,    202,  12,   0,  0,  192,  0,    0,    0,    128
    };

    char pattern[24] = {
        0x03,                               // INSTALL_PATTERN
        0x0c,                               // length = 12 * 2
        0x01, 0x00, 0x00, 0x00,             // sock_id = 1
        0x03, 0x00, 0x00, 0x00,             // num_states = 3
        0x01, 0x06, 0x90, 0x38, 0x00, 0x00, // set cwnd = 14480 bytes
        0x04, 0x06, 0xe8, 0x03, 0x00, 0x00, // waitrel 1000/1000 = 1 RTT
        0x05, 0x02,                         // report
    };

    // fake a fold function and pattern message arriving
    ok = ccp_read_msg(fold, 380);
    if (ok < 0) {
        printf("read fold error: %d\n", ok);
        goto ret;
    }

    printf("fold ok\n");

    ok = ccp_read_msg(pattern, 48);
    if (ok < 0) {
        printf("read pattern error: %d\n", ok);
        goto ret;
    }

    printf("pattern ok\n");

    // advance time
    now_us++;

    conn->prims.rtt_sample_us = 4242; // prevent minrtt = 0
    ok = ccp_invoke(conn);
    if (ok < 0) {
        printf("ccp_invoke error on divide by zero: %d\n", ok);
        goto ret;
    }
    
    printf("invoke1 ok\n");

    conn->prims.snd_cwnd = my_conn.curr_cwnd * info.mss;
    conn->prims.rtt_sample_us = 4242;
    conn->prims.bytes_acked = 100;
    conn->prims.packets_acked = 10;

    now_us++;

  ret:
    ccp_free();
    return 0;
}
