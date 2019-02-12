#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wsign-compare"
#include "lib/resolve.h"
#include "lib/dnssec/ta.h"
#include "contrib/ucw/mempool.h"
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
	kr_zonecut_add(&ctx->resolver.root_hints, (const knot_dname_t *)"", data, len);
	return 0;
}

int lkr_trust_anchor(struct lkr_context *ctx, const uint8_t *data, size_t len)
{
	return kr_ta_add(&ctx->resolver.trust_anchors, (const knot_dname_t *)"", KNOT_RRTYPE_DS, 172800, data, len);
}

void lkr_verbose(struct lkr_context *ctx, bool val)
{
	if (ctx != NULL) {
		kr_verbose_set(val);
	}
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

int lkr_cache_open(struct lkr_context *ctx, void *cache_ptr)
{
	ctx->resolver.cache.db = (knot_db_t *)cache_ptr;
	return 0;
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

	/* Don't strictly match MSGID to allow cached answers */
	struct kr_query *query = kr_rplan_last(&req->req.rplan);
	if (query) {
		query->id = knot_wire_get_id(packet->wire);
	} else {
		/* The initial query message must be copied as it's accessed throughout the request lifetime. */
		size_t first_query_size = packet->size;
		if (knot_pkt_has_tsig(packet)) {
			first_query_size += packet->tsig_wire.len;
		}

		knot_pkt_t *first_query = knot_pkt_new(NULL, first_query_size, &req->req.pool);
		if (!first_query) {
			return FAIL;
		}

		int ret = knot_pkt_copy(first_query, packet);
		if (ret != KNOT_EOK && ret != KNOT_ETRAIL) {
			return kr_error(ENOMEM);
		}

		req->req.qsource.packet = first_query;
		req->req.qsource.size = first_query_size;
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

const uint8_t *lkr_current_zone_cut(struct lkr_request *req)
{
	if (kr_rplan_empty(&req->req.rplan)) {
		return NULL;
	}

	struct kr_query *current = array_tail(req->req.rplan.pending);
	if (current == NULL) {
		return NULL;
	}

	return (const uint8_t *)current->zone_cut.name;
}

/// Returns true if the type is an infrastructure type.
static bool is_infra_type(uint16_t rr_type) {
	switch (rr_type) {
	case KNOT_RRTYPE_NS:
	case KNOT_RRTYPE_DS:
	case KNOT_RRTYPE_DNSKEY:
	case KNOT_RRTYPE_A:
	case KNOT_RRTYPE_AAAA:
		return true;
	default:
		return false;
	}
}

// Select infrastructure records accepted from an upstream response
static size_t select_infra_records(ranked_rr_array_t *arr, const ranked_rr_array_entry_t *dst[], size_t off, size_t max_count)
{
	for (size_t i = 0; i < arr->len; ++i) {
		ranked_rr_array_entry_t *entry = arr->at[i];

		if (off >= max_count)
			break;

		if (entry->cached)
			continue;

		// Only accept infrastructure records
		if (!is_infra_type(entry->rr->type) || entry->to_wire) {
			continue;
		}

		// Accept any that's valid
		if (kr_rank_test(entry->rank, KR_RANK_INITIAL)
			|| kr_rank_test(entry->rank, KR_RANK_BOGUS)
			|| kr_rank_test(entry->rank, KR_RANK_MISMATCH)
			|| kr_rank_test(entry->rank, KR_RANK_MISSING)) {
			continue;
		}

		entry->cached = true;
		dst[off] = entry;
		off += 1;
	}

	return off;
}

size_t lkr_accepted_records(struct lkr_request *req, const ranked_rr_array_entry_t *dst[], size_t max_count) {

	size_t off = 0;
	off = select_infra_records(&req->req.answ_selected, dst, off, max_count);
	off = select_infra_records(&req->req.auth_selected, dst, off, max_count);
	off = select_infra_records(&req->req.add_selected, dst, off, max_count);

	return off;
}

int lkr_sockaddr_len(struct sockaddr *sa)
{
	return kr_sockaddr_len(sa);
}

int lkr_dname_len(const uint8_t *dname)
{
	return knot_dname_size((const knot_dname_t *)dname);
}

knot_rdata_t *lkr_rdata_next(knot_rdata_t *rdata)
{
	return knot_rdataset_next(rdata);
}
