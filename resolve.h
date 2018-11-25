#include <stdlib.h>
#include <stdbool.h>

/* Reexported layer state from libkres */
enum lkr_state {
	CONSUME = 1 << 0, /*!< Consume data. */
	PRODUCE = 1 << 1, /*!< Produce data. */
	DONE    = 1 << 2, /*!< Finished successfully. */
	FAIL    = 1 << 3, /*!< Error. */
	YIELD   = 1 << 4, /*!< Paused, waiting for a sub-query. */
};

/* Opaque types */
struct sockaddr;
struct lkr_context_t;
struct lkr_request;

/* High level interfaces abstracted from the engine */

struct lkr_context *lkr_context_new();
void lkr_context_free(struct lkr_context *ctx);
int lkr_module_load(struct lkr_context *ctx, const char *name);
int lkr_module_unload(struct lkr_context *ctx, const char *name);
int lkr_cache_open(struct lkr_context *ctx, const char *path, size_t max_bytes);
int lkr_root_hint(struct lkr_context *ctx, const uint8_t *data, size_t len);
int lkr_trust_anchor(struct lkr_context *ctx, const uint8_t *data, size_t len);

struct lkr_request *lkr_request_new(struct lkr_context *ctx);
void lkr_request_free(struct lkr_request *req);
enum lkr_state lkr_consume(struct lkr_request *req, const struct sockaddr *addr, const uint8_t *data, size_t len);
enum lkr_state lkr_produce(struct lkr_request *req, struct sockaddr *addrs[], size_t addrs_len, uint8_t *data, size_t *len, _Bool is_stream);
size_t lkr_finish(struct lkr_request *req, enum lkr_state state);
size_t lkr_write_answer(struct lkr_request *req, uint8_t *dst, size_t max_bytes);
int lkr_sockaddr_len(struct sockaddr *sa);