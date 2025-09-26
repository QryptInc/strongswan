/**
 * @defgroup redis redis
 * @{ @ingroup entropy_p
 */

#ifndef NONCE_NONCEG_H_
#define NONCE_NONCEG_H_

#ifndef NONCE_RNG_QUALITY
#define NONCE_RNG_QUALITY RNG_WEAK
#endif

typedef struct redis_t redis_t;

#include <library.h>

/**
 * entropy_gen_t implementation using an rng plugin
 */
struct redis_t {

	/**
	 * Implements entropy_gen_t.
	 */
	// entropy_gen_t entropy_gen;
    key_exchange_t key_exchange;
};

/**
 * Creates an redis_t instance.
 *
 * @return			created redis_t
 */
redis_t *redis_create();

#endif /** NONCE_NONCEG_H_ @} */
