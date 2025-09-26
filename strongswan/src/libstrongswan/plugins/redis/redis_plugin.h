/**
 * @defgroup redis_p nonce
 * @ingroup plugins
 *
 * @defgroup redis_plugin redis_plugin
 * @{ @ingroup redis_p
 */

#ifndef REDIS_PLUGIN_H_
#define REDIS_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct redis_plugin_t redis_plugin_t;

/**
 * Plugin implementing a nonce generator using an RNG.
 */
struct redis_plugin_t {

	/**
	 * Implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** redis_PLUGIN_H_ @}*/
