// SPDX-License-Identifier: GPL-2.0-only OR MIT
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/types.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#define AF_INET 2
#define AF_INET6 10
#define TUNLESS_PROTOCOL_CONNECTED 0x80
#define TUNLESS_PROTOCOL_MASK 0x7f

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)BPF_FUNC_map_update_elem;
static __u64 (*bpf_get_socket_cookie)(void *ctx) = (void *)BPF_FUNC_get_socket_cookie;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)BPF_FUNC_get_current_cgroup_id;

struct config_value {
    __u32 listen_ip4;
    __u8 listen_ip6[16];
    __u16 listen_port;
    __u8 has_include4;
    __u8 has_include6;
};

struct lpm4_key { __u32 prefixlen; __u32 addr; };
struct lpm6_key { __u32 prefixlen; __u8 addr[16]; };

struct original_value {
    __u8 addr[16];
    __u16 port;
    __u8 family;
    __u8 protocol;
    __u32 pid;
    __u64 cgroup_id;
};

struct tuple_key {
    __u8 addr[16];
    __u16 port;
    __u8 family;
    __u8 protocol;
    __u8 pad[4];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config_value);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct original_value);
} original_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct tuple_key);
    __type(value, __u64);
} tuple_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} udp_relay_map SEC(".maps");

#define LPM_MAP(name, key_type) struct { __uint(type, BPF_MAP_TYPE_LPM_TRIE); __uint(max_entries, 1024); __uint(map_flags, BPF_F_NO_PREALLOC); __type(key, key_type); __type(value, __u8); } name SEC(".maps")
LPM_MAP(include4, struct lpm4_key);
LPM_MAP(exclude4, struct lpm4_key);
LPM_MAP(include6, struct lpm6_key);
LPM_MAP(exclude6, struct lpm6_key);

static __always_inline struct config_value *config(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&config_map, &key);
}

static __always_inline int capture4(struct config_value *cfg, __u32 addr) {
    struct lpm4_key key = { .prefixlen = 32, .addr = addr };
    if (bpf_map_lookup_elem(&exclude4, &key)) return 0;
    return !cfg->has_include4 || bpf_map_lookup_elem(&include4, &key);
}

static __always_inline int capture6(struct config_value *cfg, __u32 *addr) {
    struct lpm6_key key = { .prefixlen = 128 };
    key.addr[0] = ((__u8 *)addr)[0]; key.addr[1] = ((__u8 *)addr)[1]; key.addr[2] = ((__u8 *)addr)[2]; key.addr[3] = ((__u8 *)addr)[3];
    key.addr[4] = ((__u8 *)addr)[4]; key.addr[5] = ((__u8 *)addr)[5]; key.addr[6] = ((__u8 *)addr)[6]; key.addr[7] = ((__u8 *)addr)[7];
    key.addr[8] = ((__u8 *)addr)[8]; key.addr[9] = ((__u8 *)addr)[9]; key.addr[10] = ((__u8 *)addr)[10]; key.addr[11] = ((__u8 *)addr)[11];
    key.addr[12] = ((__u8 *)addr)[12]; key.addr[13] = ((__u8 *)addr)[13]; key.addr[14] = ((__u8 *)addr)[14]; key.addr[15] = ((__u8 *)addr)[15];
    if (bpf_map_lookup_elem(&exclude6, &key)) return 0;
    return !cfg->has_include6 || bpf_map_lookup_elem(&include6, &key);
}

static __always_inline int mapped_loopback6(__u32 *addr) {
    return addr[0] == 0 && addr[1] == 0 &&
        addr[2] == __builtin_bswap32(0x0000ffff) &&
        (__builtin_bswap32(addr[3]) >> 24) == 127;
}

static __always_inline int reserve_udp_relay(__u64 cookie, __u32 *relay_ip) {
    // The loopback address carries only 24 cookie bits. Never overwrite an
    // active collision: leaving this socket direct is the safe fallback.
    *relay_ip = __builtin_bswap32(0x7f000000 | ((__u32)cookie & 0x00ffffff));
    __u64 *existing = bpf_map_lookup_elem(&udp_relay_map, relay_ip);
    if (existing && *existing != cookie)
        return 0;
    return bpf_map_update_elem(&udp_relay_map, relay_ip, &cookie, BPF_ANY) == 0;
}

static __always_inline int redirect_udp6(struct bpf_sock_addr *ctx, struct config_value *cfg, __u64 cookie) {
    __u32 relay_ip;
    if (!reserve_udp_relay(cookie, &relay_ip))
        return 0;
    ctx->user_ip6[0] = 0;
    ctx->user_ip6[1] = 0;
    ctx->user_ip6[2] = __builtin_bswap32(0x0000ffff);
    ctx->user_ip6[3] = relay_ip;
    ctx->user_port = cfg->listen_port;
    return 1;
}

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx) {
    if (ctx->protocol != IPPROTO_TCP && ctx->protocol != IPPROTO_UDP)
        return 1;
    if ((__builtin_bswap32(ctx->user_ip4) >> 24) == 127)
        return 1;
    struct config_value *cfg = config();
    if (!cfg)
        return 1;
    if (!capture4(cfg, ctx->user_ip4))
        return 1;
    __u64 cookie = bpf_get_socket_cookie(ctx);
    if (!cookie)
        return 1;
    struct original_value orig = {};
    __builtin_memcpy(orig.addr, &ctx->user_ip4, sizeof(ctx->user_ip4));
    orig.port = ctx->user_port;
    orig.family = AF_INET;
    orig.protocol = ctx->protocol;
    if (ctx->protocol == IPPROTO_UDP)
        orig.protocol |= TUNLESS_PROTOCOL_CONNECTED;
    orig.pid = bpf_get_current_pid_tgid() >> 32;
    orig.cgroup_id = bpf_get_current_cgroup_id();
    if (bpf_map_update_elem(&original_map, &cookie, &orig, BPF_ANY))
        return 1;
    if (ctx->protocol == IPPROTO_UDP) {
        __u32 relay_ip;
        if (!reserve_udp_relay(cookie, &relay_ip))
            return 1;
        ctx->user_ip4 = relay_ip;
    } else {
        ctx->user_ip4 = cfg->listen_ip4;
    }
    ctx->user_port = cfg->listen_port;
    return 1;
}

SEC("cgroup/connect6")
int connect6(struct bpf_sock_addr *ctx) {
    if (ctx->protocol != IPPROTO_TCP && ctx->protocol != IPPROTO_UDP)
        return 1;
    if ((ctx->user_ip6[0] == 0 && ctx->user_ip6[1] == 0 && ctx->user_ip6[2] == 0 && ctx->user_ip6[3] == __builtin_bswap32(1)) || mapped_loopback6(ctx->user_ip6))
        return 1;
    struct config_value *cfg = config();
    if (!cfg)
        return 1;
    if (!capture6(cfg, ctx->user_ip6))
        return 1;
    __u64 cookie = bpf_get_socket_cookie(ctx);
    if (!cookie)
        return 1;
    struct original_value orig = {};
    *(__u32 *)&orig.addr[0] = ctx->user_ip6[0];
    *(__u32 *)&orig.addr[4] = ctx->user_ip6[1];
    *(__u32 *)&orig.addr[8] = ctx->user_ip6[2];
    *(__u32 *)&orig.addr[12] = ctx->user_ip6[3];
    orig.port = ctx->user_port;
    orig.family = AF_INET6;
    orig.protocol = ctx->protocol;
    if (ctx->protocol == IPPROTO_UDP)
        orig.protocol |= TUNLESS_PROTOCOL_CONNECTED;
    orig.pid = bpf_get_current_pid_tgid() >> 32;
    orig.cgroup_id = bpf_get_current_cgroup_id();
    if (bpf_map_update_elem(&original_map, &cookie, &orig, BPF_ANY))
        return 1;
    if (ctx->protocol == IPPROTO_UDP) {
        if (!redirect_udp6(ctx, cfg, cookie))
            return 1;
    } else {
        ctx->user_ip6[0] = *(__u32 *)&cfg->listen_ip6[0];
        ctx->user_ip6[1] = *(__u32 *)&cfg->listen_ip6[4];
        ctx->user_ip6[2] = *(__u32 *)&cfg->listen_ip6[8];
        ctx->user_ip6[3] = *(__u32 *)&cfg->listen_ip6[12];
        ctx->user_port = cfg->listen_port;
    }
    return 1;
}

SEC("sockops")
int established(struct bpf_sock_ops *ctx) {
    if (ctx->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
        return 1;
    __u64 cookie = bpf_get_socket_cookie(ctx);
    if (!cookie || !bpf_map_lookup_elem(&original_map, &cookie))
        return 1;
    struct tuple_key tuple = {};
    if (ctx->family == AF_INET) {
        __builtin_memcpy(tuple.addr, &ctx->local_ip4, sizeof(ctx->local_ip4));
        tuple.family = AF_INET;
    } else if (ctx->family == AF_INET6) {
        __builtin_memcpy(tuple.addr, ctx->local_ip6, sizeof(tuple.addr));
        tuple.family = AF_INET6;
    } else {
        return 1;
    }
    tuple.port = __builtin_bswap16((__u16)ctx->local_port);
    tuple.protocol = IPPROTO_TCP;
    bpf_map_update_elem(&tuple_map, &tuple, &cookie, BPF_ANY);
    return 1;
}

static __always_inline int sendmsg4(struct bpf_sock_addr *ctx) {
    if (ctx->protocol != IPPROTO_UDP)
        return 1;
    struct config_value *cfg = config();
    if (!cfg)
        return 1;
    __u64 cookie = bpf_get_socket_cookie(ctx);
    if (!cookie)
        return 1;
    struct original_value *existing = bpf_map_lookup_elem(&original_map, &cookie);
    if (existing && existing->protocol == (IPPROTO_UDP | TUNLESS_PROTOCOL_CONNECTED))
        return 1;
    if (existing && (existing->protocol != IPPROTO_UDP || existing->family != AF_INET ||
        existing->port != ctx->user_port || *(__u32 *)&existing->addr[0] != ctx->user_ip4))
        return 0;
    if (!existing) {
        if ((__builtin_bswap32(ctx->user_ip4) >> 24) == 127 || !capture4(cfg, ctx->user_ip4))
            return 1;
        struct original_value orig = {};
        __builtin_memcpy(orig.addr, &ctx->user_ip4, sizeof(ctx->user_ip4));
        orig.port = ctx->user_port;
        orig.family = AF_INET;
        orig.protocol = IPPROTO_UDP;
        orig.pid = bpf_get_current_pid_tgid() >> 32;
        orig.cgroup_id = bpf_get_current_cgroup_id();
        if (bpf_map_update_elem(&original_map, &cookie, &orig, BPF_ANY))
            return 1;
    }
    __u32 relay_ip;
    if (!reserve_udp_relay(cookie, &relay_ip))
        return 1;
    ctx->user_ip4 = relay_ip;
    ctx->user_port = cfg->listen_port;
    return 1;
}

SEC("cgroup/sendmsg4")
int udp_sendmsg4(struct bpf_sock_addr *ctx) { return sendmsg4(ctx); }

SEC("cgroup/sendmsg6")
int udp_sendmsg6(struct bpf_sock_addr *ctx) {
    if (ctx->protocol != IPPROTO_UDP)
        return 1;
    struct config_value *cfg = config();
    if (!cfg)
        return 1;
    __u64 cookie = bpf_get_socket_cookie(ctx);
    if (!cookie)
        return 1;
    struct original_value *existing = bpf_map_lookup_elem(&original_map, &cookie);
    if (existing && existing->protocol == (IPPROTO_UDP | TUNLESS_PROTOCOL_CONNECTED))
        return 1;
    if (existing && (existing->protocol != IPPROTO_UDP || existing->family != AF_INET6 ||
        existing->port != ctx->user_port || *(__u32 *)&existing->addr[0] != ctx->user_ip6[0] ||
        *(__u32 *)&existing->addr[4] != ctx->user_ip6[1] || *(__u32 *)&existing->addr[8] != ctx->user_ip6[2] ||
        *(__u32 *)&existing->addr[12] != ctx->user_ip6[3]))
        return 0;
    if (!existing) {
        if ((ctx->user_ip6[0] == 0 && ctx->user_ip6[1] == 0 && ctx->user_ip6[2] == 0 && ctx->user_ip6[3] == __builtin_bswap32(1)) ||
            mapped_loopback6(ctx->user_ip6) || !capture6(cfg, ctx->user_ip6))
            return 1;
        struct original_value orig = {};
        *(__u32 *)&orig.addr[0] = ctx->user_ip6[0];
        *(__u32 *)&orig.addr[4] = ctx->user_ip6[1];
        *(__u32 *)&orig.addr[8] = ctx->user_ip6[2];
        *(__u32 *)&orig.addr[12] = ctx->user_ip6[3];
        orig.port = ctx->user_port;
        orig.family = AF_INET6;
        orig.protocol = IPPROTO_UDP;
        orig.pid = bpf_get_current_pid_tgid() >> 32;
        orig.cgroup_id = bpf_get_current_cgroup_id();
        if (bpf_map_update_elem(&original_map, &cookie, &orig, BPF_ANY))
            return 1;
    }
    struct tuple_key tuple = {};
    tuple.family = AF_INET6;
    tuple.protocol = IPPROTO_UDP;
    tuple.port = __builtin_bswap16((__u16)ctx->sk->src_port);
    __builtin_memcpy(tuple.addr, ctx->sk->src_ip6, sizeof(tuple.addr));
    bpf_map_update_elem(&tuple_map, &tuple, &cookie, BPF_ANY);
    ctx->user_ip6[0] = *(__u32 *)&cfg->listen_ip6[0];
    ctx->user_ip6[1] = *(__u32 *)&cfg->listen_ip6[4];
    ctx->user_ip6[2] = *(__u32 *)&cfg->listen_ip6[8];
    ctx->user_ip6[3] = *(__u32 *)&cfg->listen_ip6[12];
    ctx->user_port = cfg->listen_port;
    return 1;
}

SEC("cgroup/recvmsg4")
int udp_recvmsg4(struct bpf_sock_addr *ctx) {
    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct original_value *orig = bpf_map_lookup_elem(&original_map, &cookie);
    if (orig && (orig->protocol & TUNLESS_PROTOCOL_MASK) == IPPROTO_UDP && orig->family == AF_INET) {
        __builtin_memcpy(&ctx->user_ip4, orig->addr, sizeof(ctx->user_ip4));
        ctx->user_port = orig->port;
    }
    return 1;
}

SEC("cgroup/recvmsg6")
int udp_recvmsg6(struct bpf_sock_addr *ctx) {
    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct original_value *orig = bpf_map_lookup_elem(&original_map, &cookie);
    if (orig && (orig->protocol & TUNLESS_PROTOCOL_MASK) == IPPROTO_UDP && orig->family == AF_INET6) {
        ctx->user_ip6[0] = *(__u32 *)&orig->addr[0];
        ctx->user_ip6[1] = *(__u32 *)&orig->addr[4];
        ctx->user_ip6[2] = *(__u32 *)&orig->addr[8];
        ctx->user_ip6[3] = *(__u32 *)&orig->addr[12];
        ctx->user_port = orig->port;
    }
    return 1;
}

char LICENSE[] SEC("license") = "GPL";
