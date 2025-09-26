#include "redis_plugin.h"
#include "redis.h"

#include <library.h>

#define KE_REDIS 1074

typedef struct private_redis_plugin_t private_redis_plugin_t;

/**
 * private data of redis_plugin
 */
struct private_redis_plugin_t {

	/**
	 * public functions
	 */
	redis_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_redis_plugin_t *this)
{
	return "redis";
}

METHOD(plugin_t, get_features, int,
	private_redis_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_REGISTER(KE, redis_create),
			PLUGIN_PROVIDE(KE, KE_REDIS),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_redis_plugin_t *this)
{
	free(this);
}


/**
 * enum names for key_exchange_method_t (matching proposal keywords).
 */
extern enum_name_t * key_exchange_method_names;
extern enum_name_t * key_exchange_method_names_short;
enum_name_t *redis_method_names;
enum_name_t *redis_method_names_short;

ENUM_BEGIN(redis_method_names, KE_REDIS, KE_REDIS, "REDIS");
ENUM_END(redis_method_names, KE_REDIS);
ENUM_BEGIN(redis_method_names_short, KE_REDIS, KE_REDIS, "redis");
ENUM_END(redis_method_names_short, KE_REDIS);

/*
 * see header file
 */
plugin_t *redis_plugin_create()
{
	private_redis_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);
	// the IKE id of the algorithm
	lib->proposal->register_token(lib->proposal, get_name(this), KEY_EXCHANGE_METHOD, KE_REDIS, 0);

	enum_add_enum_names(key_exchange_method_names,       redis_method_names);
	enum_add_enum_names(key_exchange_method_names_short, redis_method_names_short);
	return &this->public.plugin;
}
