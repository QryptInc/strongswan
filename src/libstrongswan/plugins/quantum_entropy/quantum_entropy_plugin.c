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

#include "quantum_entropy_plugin.h"
#include "quantum_entropy_rng.h"

#include <stdio.h>

#include <library.h>
#include <utils/debug.h>
#include <utils/cpu_feature.h>

typedef struct private_quantum_entropy_plugin_t private_quantum_entropy_plugin_t;
typedef enum cpuid_feature_t cpuid_feature_t;

/**
 * private data of quantum_entropy_plugin
 */
struct private_quantum_entropy_plugin_t {

	/**
	 * public functions
	 */
	quantum_entropy_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_quantum_entropy_plugin_t *this)
{
	return "quantum_entropy";
}

METHOD(plugin_t, get_features, int,
	private_quantum_entropy_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_REGISTER(RNG, quantum_entropy_rng_create),
			PLUGIN_PROVIDE(RNG, RNG_WEAK),
			PLUGIN_PROVIDE(RNG, RNG_STRONG),
			PLUGIN_PROVIDE(RNG, RNG_TRUE),
				PLUGIN_DEPENDS(FETCHER, "https://"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_quantum_entropy_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *quantum_entropy_plugin_create()
{
	private_quantum_entropy_plugin_t *this;
	DBG2(DBG_LIB, "QUANTUM_ENTROPY PLUGIN");

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
	);

	return &this->public.plugin;
}
