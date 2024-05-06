
#include "blast_plugin.h"
#include "blast_ke.h"
#include <library.h>

#include <plugins/plugin.h>
#define KE_BLAST 1072

typedef struct private_blast_plugin_t private_blast_plugin_t;

/**
 * private data of newhope_plugin
 */
struct private_blast_plugin_t {

	/**
	 * public functions
	 */
	blast_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_blast_plugin_t *this)
{
	return "blast";
}

METHOD(plugin_t, get_features, int,
	private_blast_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_REGISTER(KE, blast_ke_create),
			PLUGIN_PROVIDE(KE, KE_BLAST),
	};
	*features = f;

	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_blast_plugin_t *this)
{
	free(this);
}

/**
 * enum names for key_exchange_method_t (matching proposal keywords).
 */
extern enum_name_t * key_exchange_method_names;
extern enum_name_t * key_exchange_method_names_short;
enum_name_t *blast_method_names;
enum_name_t *blast_method_names_short;


ENUM_BEGIN(blast_method_names, KE_BLAST, KE_BLAST, "BLAST");
ENUM_END(blast_method_names, KE_BLAST);
ENUM_BEGIN(blast_method_names_short, KE_BLAST, KE_BLAST, "blast");
ENUM_END(blast_method_names_short, KE_BLAST);

/*
 * see header file
 */
plugin_t *blast_plugin_create()
{
	private_blast_plugin_t *this;

	lib->proposal->register_token(lib->proposal, "blast", KEY_EXCHANGE_METHOD, KE_BLAST, 0);
	// Is this the correct place??
    enum_add_enum_names(key_exchange_method_names,       blast_method_names);
    enum_add_enum_names(key_exchange_method_names_short, blast_method_names_short);

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
