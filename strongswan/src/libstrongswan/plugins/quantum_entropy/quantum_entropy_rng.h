/*
 * Copyright (C) 2012 Martin Willi
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * @defgroup quantum_entropy_rng quantum_entropy_rng
 * @{ @ingroup quantum_entropy_p
 */

#ifndef quantum_entropy_RNG_H_
#define quantum_entropy_RNG_H_

#include <crypto/rngs/rng.h>

typedef struct quantum_entropy_rng_t quantum_entropy_rng_t;

/**
 * RNG implemented with Intels quantum_entropy instructions, introduced in Ivy Bridge.
 */
struct quantum_entropy_rng_t {

	/**
	 * Implements rng_t interface.
	 */
	rng_t rng;
};

/**
 * Create a quantum_entropy_rng instance.
 *
 * @param quality		RNG quality
 * @return				RNG instance
 */
quantum_entropy_rng_t *quantum_entropy_rng_create(rng_quality_t quality);

#endif /** quantum_entropy_RNG_H_ @}*/
