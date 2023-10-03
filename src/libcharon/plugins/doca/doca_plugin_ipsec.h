#ifndef DOCA_PLUGIN_IPSEC_H_
#define DOCA_PLUGIN_IPSEC_H_

#include <library.h>
#include <kernel/kernel_ipsec.h>

typedef struct doca_plugin_ipsec_t doca_plugin_ipsec_t;

/**
 * Implementation of the ipsec interface using DOCA
 */
struct doca_plugin_ipsec_t {

	/**
	 * Implements kernel_ipsec_t interface
	 */
	kernel_ipsec_t interface;
};

/**
 * Create a DOCA ipsec interface instance.
 *
 * @return			doca_plugin_ipsec_t instance
 */
doca_plugin_ipsec_t *doca_plugin_ipsec_create();

#endif /** DOCA_PLUGIN_IPSEC_H_ @}*/
