#ifndef DOCA_PLUGIN_H_
#define DOCA_PLUGIN_H_

#include <library.h>
#include <plugins/plugin.h>

typedef struct doca_plugin_t doca_plugin_t;

/**
 * DOCA interface plugin
 */
struct doca_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;

};

#endif /** DOCA_PLUGIN_H_ @}*/
