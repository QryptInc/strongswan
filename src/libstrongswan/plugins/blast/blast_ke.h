/*
 * Copyright (C) 2016 Andreas Steffen
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
 * @defgroup blast_ke blast_ke
 * @{ @ingroup blast_p
 */

#ifndef BLAST_KE_H_
#define BLAST_KE_H_

typedef struct blast_ke_t blast_ke_t;

#include <library.h>

/**
 * Implementation of a key exchange algorithm using the BLAST algorithm
 */
struct blast_ke_t {

	/**
	 * Implements key_exchange_t interface.
	 */
	key_exchange_t ke;
};

/**
 * Creates a new blast_ke_t object.
 *
 * @param ke			BLAST key exchange number
 * @return				blast_ke_t object, NULL if not supported
 */
blast_ke_t *blast_ke_create(key_exchange_method_t ke);

#endif /** BLAST_KE_H_ @}*/