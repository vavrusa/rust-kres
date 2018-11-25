#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wsign-compare"
#include "lib/resolve.h"
#include "lib/dnssec/ta.h"
#include "lib/cache/cdb_lmdb.h"
#include "contrib/ucw/mempool.c"
#pragma GCC diagnostic pop
#include "resolve.h"

struct lkr_context {
	struct kr_context resolver;
	module_array_t modules;
	knot_mm_t pool;
};

struct lkr_request {
	struct kr_request req;
};

int lkr_module_load(struct lkr_context *ctx, const char *name)
{
	struct kr_module *module = mm_alloc(&ctx->pool, sizeof(*module));
	if (!module) {
		return kr_error(ENOMEM);
	}
	module->data = ctx;

	int ret = kr_module_load(module, name, "");
	if (ret == 0) {
		array_push_mm(ctx->modules, module, kr_memreserve, &ctx->pool);
	}

	return ret;
}

int lkr_module_unload(struct lkr_context *ctx, const char *name)
{
	for (size_t i = 0; i < ctx->modules.len; ++i) {
		struct kr_module *module = ctx->modules.at[i];
		if (strcmp(module->name, name) == 0) {
			array_del(ctx->modules, i);
			kr_module_unload(module);
			return 0;

		}
	}
	return kr_error(ENOENT);
}

int lkr_root_hint(struct lkr_context *ctx, const uint8_t *data, size_t len)
{
	knot_rdata_t rdata[RDATA_ARR_MAX];
	knot_rdata_init(rdata, len, data);
	kr_zonecut_add(&ctx->resolver.root_hints, (const knot_dname_t *)"", rdata);
	return 0;
}

int lkr_trust_anchor(struct lkr_context *ctx, const uint8_t *data, size_t len)
{
	return kr_ta_add(&ctx->resolver.trust_anchors, (const knot_dname_t *)"", KNOT_RRTYPE_DS, 172800, data, len);
}

struct lkr_context *lkr_context_new()
{
	knot_mm_t pool = {
		.ctx = mp_new (4096),
		.alloc = (knot_mm_alloc_t) mp_alloc
	};

	struct lkr_context *ctx = mm_alloc(&pool, sizeof(*ctx));
	memset(ctx, 0, sizeof(*ctx));
	ctx->pool = pool;

	/* Open resolution context */
	struct kr_context *resolver = &ctx->resolver;
	resolver->trust_anchors = map_make(NULL);
	resolver->negative_anchors = map_make(NULL);
	resolver->pool = &ctx->pool;
	resolver->modules = &ctx->modules;
	resolver->cache_rtt_tout_retry_interval = 10;
	/* Create OPT RR */
	resolver->opt_rr = mm_alloc(&ctx->pool, sizeof(knot_rrset_t));
	if (!resolver->opt_rr) {
		return NULL;
	}
	knot_edns_init(resolver->opt_rr, 1452, 0, 0, &ctx->pool);
	/* Use default TLS padding */
	resolver->tls_padding = -1;
	/* Empty init; filled via ./lua/config.lua */
	kr_zonecut_init(&resolver->root_hints, (const uint8_t *)"", &ctx->pool);
	/* Open NS rtt + reputation cache */
	lru_create(&resolver->cache_rtt, 65535, &ctx->pool, NULL);
	lru_create(&resolver->cache_rep, 65535, &ctx->pool, NULL);
	/* Load built-in modules */
	lkr_module_load(ctx, "iterate");
	lkr_module_load(ctx, "validate");
	/* Set initial root hint */
	lkr_root_hint(ctx, (const uint8_t *) "\xc0\xcb\xe6\x0a", 4);
	/* Default options */
	resolver->options.NO_0X20 = true;
	resolver->options.NO_IPV6 = true;
	return ctx;
}

int lkr_cache_open(struct lkr_context *ctx, const char *path, size_t max_bytes)
{
	struct kr_cdb_opts opts = { path, max_bytes };
	return kr_cache_open(&ctx->resolver.cache, kr_cdb_lmdb(), &opts, &ctx->pool);
}

void lkr_context_free(struct lkr_context *ctx)
{
	for (size_t i = 0; i < ctx->modules.len; ++i) {
		struct kr_module *module = ctx->modules.at[i];
		kr_module_unload(module);
	}

	mp_delete((struct mempool *)ctx->pool.ctx);
}

void lkr_request_free(struct lkr_request *req)
{
	mp_delete((struct mempool *)req->req.pool.ctx);
}

struct lkr_request *lkr_request_new(struct lkr_context *ctx)
{
	knot_mm_t pool = {
		.ctx = mp_new (4096),
		.alloc = (knot_mm_alloc_t) mp_alloc
	};

	struct lkr_request *req = mm_alloc(&pool, sizeof(*req));
	memset(req, 0, sizeof(*req));
	req->req.pool = pool;
	req->req.answer = knot_pkt_new(NULL, 4096, &req->req.pool);
	if (!req->req.answer) {
		return NULL;
	}

	int ret = kr_resolve_begin(&req->req, &ctx->resolver, req->req.answer);
	if (ret == KR_STATE_FAIL) {
		lkr_request_free(req);
		return NULL;
	}

	return req;
}

enum lkr_state lkr_consume(struct lkr_request *req, const struct sockaddr *addr, const uint8_t *data, size_t len)
{
	knot_pkt_t *packet = knot_pkt_new((uint8_t *)data, len, &req->req.pool);
	int ret = knot_pkt_parse(packet, 0);
	if (ret != 0) {
		return FAIL;
	}
	return (enum lkr_state) kr_resolve_consume(&req->req, addr, packet);
}

enum lkr_state lkr_produce(struct lkr_request *req, struct sockaddr *addrs[], size_t addrs_len, uint8_t *data, size_t *len, _Bool is_stream)
{
	knot_pkt_t *packet = knot_pkt_new(data, *len, &req->req.pool);
	struct sockaddr *addr_list = NULL;
	int sock_type = is_stream ? SOCK_STREAM : SOCK_DGRAM;
	int res = kr_resolve_produce(&req->req, &addr_list, &sock_type, packet);

	/* Convert linear array into the array of struct sockaddr pointers */
	if (!addr_list) {
		*len = packet->size;
		return (enum lkr_state) res;
	}

	/* TODO: This will need to happen before each send when the destination address is known */
	int ret = kr_resolve_checkout(&req->req, NULL, addr_list, sock_type, packet);
	if (ret != 0) {
		*len = packet->size;
		return FAIL;
	}

	struct sockaddr_in6 *addr_list_entries = (struct sockaddr_in6 *)addr_list;
	for (uint16_t i = 0; i < MIN(addrs_len, KR_NSREP_MAXADDR); ++i) {
		struct sockaddr *choice = (struct sockaddr *)(&addr_list_entries[i]);
		if (choice->sa_family == AF_UNSPEC) {
			break;
		}
		addrs[i] = choice;
	}

	*len = packet->size;
	return (enum lkr_state) res;
}

size_t lkr_finish(struct lkr_request *req, enum lkr_state state)
{
	(void) kr_resolve_finish(&req->req, state);
	return req->req.answer->size;
}

size_t lkr_write_answer(struct lkr_request *req, uint8_t *dst, size_t max_bytes)
{
	knot_pkt_t *answer = req->req.answer;
	if (answer->size > max_bytes) {
		return 0;
	}

	memmove(dst, answer->wire, answer->size);
	return answer->size;
}

int lkr_sockaddr_len(struct sockaddr *sa)
{
	return kr_sockaddr_len(sa);
}
