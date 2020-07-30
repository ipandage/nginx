
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct ngx_http_upstream_rr_peer_s   ngx_http_upstream_rr_peer_t;

struct ngx_http_upstream_rr_peer_s {
    struct sockaddr                *sockaddr; //上游服务器socket地址
    socklen_t                       socklen;
    ngx_str_t                       name; // 域名
    ngx_str_t                       server; // server 主机

    ngx_int_t                       current_weight; // 当前权重
    ngx_int_t                       effective_weight; // 有效权重
    ngx_int_t                       weight; // 权重 配置的值

    ngx_uint_t                      conns; // 连接数
    ngx_uint_t                      max_conns; // 最大连接数

    ngx_uint_t                      fails; // 连接失败次数
    time_t                          accessed; // 访问的时间
    time_t                          checked; // 检查上游服务器时间点

    ngx_uint_t                      max_fails; // 最大失败次数
    time_t                          fail_timeout; // 连接上游服务器的失败超时时间
    ngx_msec_t                      slow_start;
    ngx_msec_t                      start_time; // 发起到上游服务器的开始时间

    ngx_uint_t                      down; // 标记下线

#if (NGX_HTTP_SSL || NGX_COMPAT)
    void                           *ssl_session;
    int                             ssl_session_len;
#endif

#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_atomic_t                    lock;
#endif

    ngx_http_upstream_rr_peer_t    *next; // 轮训发起的下一个上游server

    NGX_COMPAT_BEGIN(32)
    NGX_COMPAT_END
};


typedef struct ngx_http_upstream_rr_peers_s  ngx_http_upstream_rr_peers_t;

struct ngx_http_upstream_rr_peers_s {
    ngx_uint_t                      number; // peer server的数量

#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_slab_pool_t                *shpool; //peer信息的slab内存池
    ngx_atomic_t                    rwlock; //读写锁
    ngx_http_upstream_rr_peers_t   *zone_next; //配置了upstream zone之后才会生效
#endif

    ngx_uint_t                      total_weight;  //总的权重值 是经过加权计算得出

    unsigned                        single:1; //仅有一个peer server
    unsigned                        weighted:1;

    ngx_str_t                      *name; //配置的upstream 名称 轮询的upstream组可以配置多个

    ngx_http_upstream_rr_peers_t   *next; //下一个peer server

    ngx_http_upstream_rr_peer_t    *peer; //当前轮询的peer server
};


#if (NGX_HTTP_UPSTREAM_ZONE)

#define ngx_http_upstream_rr_peers_rlock(peers)                               \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_rlock(&peers->rwlock);                                     \
    }

#define ngx_http_upstream_rr_peers_wlock(peers)                               \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_wlock(&peers->rwlock);                                     \
    }

#define ngx_http_upstream_rr_peers_unlock(peers)                              \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_unlock(&peers->rwlock);                                    \
    }


#define ngx_http_upstream_rr_peer_lock(peers, peer)                           \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_wlock(&peer->lock);                                        \
    }

#define ngx_http_upstream_rr_peer_unlock(peers, peer)                         \
                                                                              \
    if (peers->shpool) {                                                      \
        ngx_rwlock_unlock(&peer->lock);                                       \
    }

#else

#define ngx_http_upstream_rr_peers_rlock(peers)
#define ngx_http_upstream_rr_peers_wlock(peers)
#define ngx_http_upstream_rr_peers_unlock(peers)
#define ngx_http_upstream_rr_peer_lock(peers, peer)
#define ngx_http_upstream_rr_peer_unlock(peers, peer)

#endif


typedef struct {
    ngx_uint_t                      config;
    ngx_http_upstream_rr_peers_t   *peers;
    ngx_http_upstream_rr_peer_t    *current;
    uintptr_t                      *tried;
    uintptr_t                       data;
} ngx_http_upstream_rr_peer_data_t;


ngx_int_t ngx_http_upstream_init_round_robin(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
ngx_int_t ngx_http_upstream_init_round_robin_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
ngx_int_t ngx_http_upstream_create_round_robin_peer(ngx_http_request_t *r,
    ngx_http_upstream_resolved_t *ur);
ngx_int_t ngx_http_upstream_get_round_robin_peer(ngx_peer_connection_t *pc,
    void *data);
void ngx_http_upstream_free_round_robin_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);

#if (NGX_HTTP_SSL)
ngx_int_t
    ngx_http_upstream_set_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data);
void ngx_http_upstream_save_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data);
#endif


#endif /* _NGX_HTTP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_ */
