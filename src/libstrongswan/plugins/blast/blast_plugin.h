/**
 * @defgroup blast_p blast
 * @ingroup plugins
 *
 * @defgroup blast_plugin blast_plugin
 * @{ @ingroup ntru_p
 */

#ifndef BLAST_PLUGIN_H_
#define BLAST_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct blast_plugin_t blast_plugin_t;

/**
 * Plugin implementing BLAST-based key exchange
 */
struct blast_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** BLAST_PLUGIN_H_ @}*/