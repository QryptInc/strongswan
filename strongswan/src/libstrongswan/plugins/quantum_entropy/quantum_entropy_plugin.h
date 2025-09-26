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
 * @defgroup quantum_entropy_p quantum_entropy
 * @ingroup plugins
 *
 * @defgroup quantum_entropy_plugin quantum_entropy_plugin
 * @{ @ingroup quantum_entropy_p
 */

#ifndef quantum_entropy_PLUGIN_H_
#define quantum_entropy_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct quantum_entropy_plugin_t quantum_entropy_plugin_t;

/**
 * Plugin providing entropy using the standard entropy API.
 */
struct quantum_entropy_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** quantum_entropy_PLUGIN_H_ @}*/
