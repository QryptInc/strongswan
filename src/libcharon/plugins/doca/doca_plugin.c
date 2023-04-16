#include "doca_plugin.h"
#include "doca_plugin_ipsec.h"

#include <utils/debug.h>
#include <daemon.h>

typedef struct private_doca_plugin_t private_doca_plugin_t;

/**
 * private data of DOCA plugin
 */
struct private_doca_plugin_t {

	/**
	 * implements plugin interface
	 */
	doca_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_doca_plugin_t *this)
{
	return "doca";
}

METHOD(plugin_t, get_features, int,
	private_doca_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK(kernel_ipsec_register, doca_plugin_ipsec_create),
			PLUGIN_PROVIDE(CUSTOM, "kernel-ipsec"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_doca_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *doca_plugin_create()
{
	DBG1(DBG_LIB, "[DOCA][INFO] Enter doca_plugin_create()");
	private_doca_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	return &this->public.plugin;
}
