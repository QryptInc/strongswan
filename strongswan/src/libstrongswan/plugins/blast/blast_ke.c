#include "blast_ke.h"
#include "qryptsecurity_c.h"
#include <library.h>
#include <utils/lexparser.h>
#include <utils/debug.h>
#include <config.h>

typedef struct private_blast_ke_t private_blast_ke_t;

typedef enum sa_endpoint_t sa_endpoint_t;

enum sa_endpoint_t {
	EP_TYPE_UNKNOWN = 0,
	EP_TYPE_INITIATOR = 1,
	EP_TYPE_RESPONDER = 2,
};

/**
 * Private data of an blast_t object.
 */
struct private_blast_ke_t {

	/**
	 * Public blast_t interface.
	 */
	blast_ke_t public;

	/**
	 * key exchange method
	 */
	key_exchange_method_t method;

	/**
	 * security association endpoint type
	 */
	sa_endpoint_t endpoint_type;

	/**
	 * Public Key
	 */
    chunk_t metadata;

	/**
	 * Shared secret
	 */
	chunk_t shared_secret;

	/**
	 * QryptSecurity key generation object
	 */
	qrypt_security_t qrypt_security;

};

#define CASERETURN_STR(id) case id: return #id
static const char *qs_error_str(int code)
{
	switch (code)
	{
    CASERETURN_STR(QS_GOOD);
    CASERETURN_STR(QS_UNKNOWN_ERROR);
    CASERETURN_STR(QS_INVALID_ARGUMENT);
    CASERETURN_STR(QS_SYSTEM_ERROR);
    CASERETURN_STR(QS_CANNOT_DOWNLOAD);
    CASERETURN_STR(QS_DATA_CORRUPTED);
    CASERETURN_STR(QS_INCOMPATIBLE_VERSION);
	default:
		break;
	}
	return "Invalid error code";
}
#undef CASERETURN_STR

/**
 * Gets the own public key to transmit.
 *
 * @param value		public key (allocated)
 * @return			TRUE if public key retrieved
 */
METHOD(key_exchange_t, get_public_key, bool, private_blast_ke_t *this, chunk_t *value)
{

    symmetric_key_data_t key_data;
	key_config_t key_config = {
		lib->settings->get_int(lib->settings, "%s.plugins.blast.ttl", 0, lib->ns)
	};

	DBG2(DBG_LIB, "[BLAST] Enter %s, %s (%d)", __func__, __FILE__, __LINE__ );

	if (this->endpoint_type == EP_TYPE_INITIATOR) {

		DBG1(DBG_LIB, "[BLAST] Error: unexpected endpoint_type %d", this->endpoint_type);
		return FALSE;

	} else if (this->endpoint_type == EP_TYPE_UNKNOWN) {

		this->endpoint_type = EP_TYPE_INITIATOR; // get_public_key is the first KE call by the initiator

		// Perform blast genInit
		DBG2(DBG_LIB, "[BLAST] (ALICE) %s: calling qrypt_security_gen_init_aes...", __func__);
		int ret_code = qrypt_security_gen_init_aes(&this->qrypt_security, &key_data, key_config);
		if (ret_code != QS_GOOD) {
			DBG1(DBG_LIB, "[BLAST] Error: qrypt_security_gen_init_aes returned %s", qs_error_str(ret_code));
			return FALSE;
		}

		// Save blast key
		DBG2(DBG_LIB, "[BLAST] (ALICE) %s: saving blast key...", __func__);
		this->shared_secret = chunk_clone(chunk_create(key_data.key, key_data.key_size));

		DBG2(DBG_LIB, "[BLAST] (ALICE) %s: returning metadata...", __func__);
		*value = chunk_clone(chunk_create(key_data.metadata, key_data.metadata_size));

		// Free key data structure
		ret_code = qrypt_security_symmetric_key_data_free(&key_data);
		if (ret_code != QS_GOOD) {
			DBG1(DBG_LIB, "[BLAST] Error: qrypt_security_symmetric_key_data_free returned %s", qs_error_str(ret_code));
			return FALSE;
		}

		DBG1(DBG_LIB, "[BLAST] (ALICE) Own public key successfully retrieved!");

	} else if (this->endpoint_type == EP_TYPE_RESPONDER ) {

		DBG2(DBG_LIB, "[BLAST] (BOB) %s: returning ack...", __func__);

        uint8_t ssecret[32] = "metadata_rcvd";
        *value = chunk_clone(chunk_from_thing(ssecret));

	}

	DBG2(DBG_LIB, "[BLAST] Exit %s, %s (%d)", __func__, __FILE__, __LINE__);
    return TRUE;

}

/**
 * Sets the public key received from the peer.
 *
 * @note This operation should be relatively quick. Costly public key
 * validation operations or key derivation should be implemented in
 * get_shared_secret().
 *
 * @param value		public key of peer
 * @return			TRUE if other public key verified and set
 */
METHOD(key_exchange_t, set_public_key, bool, private_blast_ke_t *this, chunk_t value)
{

	DBG2(DBG_LIB, "[BLAST] Enter %s, %s (%d)", __func__, __FILE__, __LINE__ );

	if (this->endpoint_type == EP_TYPE_RESPONDER) {

		DBG1(DBG_LIB, "[BLAST] Error: unexpected endpoint_type %d", this->endpoint_type);
		return FALSE;

	} else if (this->endpoint_type == EP_TYPE_UNKNOWN) {

		this->endpoint_type = EP_TYPE_RESPONDER;  // set_public_key is the first KE call by the responder

		if(value.len > 0) {
			DBG2(DBG_LIB, "[BLAST] (BOB) %s: saving metadata...", __func__);
			this->metadata = chunk_clone(value);
		} else {
			DBG1(DBG_LIB, "[BLAST] Error: Responder did not receive metadata");
			return FALSE;
		}

		DBG1(DBG_LIB, "[BLAST] (BOB) Peer's public key successfully verified and set!");

	} else if (this->endpoint_type == EP_TYPE_INITIATOR ) {

		DBG2(DBG_LIB, "[BLAST] (ALICE) %s: doing nothing with ack...", __func__);

	}

	DBG2(DBG_LIB, "[BLAST] Exit %s, %s (%d)", __func__, __FILE__, __LINE__);
    return TRUE;

}

/**
 * Returns the shared secret of this key exchange method.
 *
 * @param secret	shared secret (allocated)
 * @return			TRUE if shared secret computed successfully
 */
METHOD(key_exchange_t, get_shared_secret, bool, private_blast_ke_t *this, chunk_t *secret)
{

    DBG2(DBG_LIB, "[BLAST] Enter %s, %s (%d)", __func__, __FILE__, __LINE__);

	if (this->endpoint_type == EP_TYPE_RESPONDER) {

		if (this->metadata.ptr == NULL) {
			DBG1(DBG_LIB, "[BLAST] Error: metadata was not saved from a prior call");
			return FALSE;
		}

		// Initialize temporary key data structure
		symmetric_key_data_t key_data;
		key_data.metadata = this->metadata.ptr;
		key_data.metadata_size = this->metadata.len;

		// Perform blast genSync
		DBG2(DBG_LIB, "[BLAST] (BOB) %s: calling qrypt_security_gen_sync...", __func__);
		int ret_code = qrypt_security_gen_sync(&this->qrypt_security, &key_data);	// TODO: Update c wrapper to split key_data to metadata and key
		if (ret_code != QS_GOOD) {
			DBG1(DBG_LIB, "[BLAST] Error: qrypt_security_gen_sync returned %s", qs_error_str(ret_code));
			return FALSE;
		}

		// Copy blast key
		*secret = chunk_clone(chunk_create(key_data.key, key_data.key_size));

		// Only free blast key from temporary key data structure
		key_data.metadata = NULL;
		key_data.metadata_size = 0;
		ret_code = qrypt_security_symmetric_key_data_free(&key_data);
		if (ret_code != QS_GOOD) {
			DBG1(DBG_LIB, "[BLAST] Error: qrypt_security_symmetric_key_data_free returned %s", qs_error_str(ret_code));
			return FALSE;
		}

		DBG1(DBG_LIB, "[BLAST] (BOB) Shared secret successfully established!");

	} else if (this->endpoint_type == EP_TYPE_INITIATOR) {

		// Blast key should already be generated from the get_public_key call
		*secret = chunk_clone(this->shared_secret);

		DBG1(DBG_LIB, "[BLAST] (ALICE) Shared secret successfully established!");

	} else {

		DBG1(DBG_LIB, "[BLAST] Error: unexpected endpoint_type %d", this->endpoint_type);
		return FALSE;

	}

	DBG2(DBG_LIB, "[BLAST] Exit %s, %s (%d)", __func__, __FILE__, __LINE__);
	return TRUE;

}

METHOD(key_exchange_t, get_method, key_exchange_method_t, private_blast_ke_t *this)
{
	return this->method;
}

METHOD(key_exchange_t, destroy, void, private_blast_ke_t *this)
{
    DBG2(DBG_LIB, "[BLAST] Enter %s, %s (%d)", __func__, __FILE__, __LINE__ );
    int ret_code = qrypt_security_delete(&this->qrypt_security);
	if (ret_code != QS_GOOD) {
		DBG1(DBG_LIB, "[BLAST] Error: qrypt_security_delete returned %s", qs_error_str(ret_code));
		return;
	}

	chunk_free(&this->shared_secret);
	chunk_free(&this->metadata);
	free(this);
	DBG2(DBG_LIB, "[BLAST] Exit %s, %s (%d)", __func__, __FILE__, __LINE__);
}

/*
 * Described in header.
 */
blast_ke_t *blast_ke_create(key_exchange_method_t method)
{

	private_blast_ke_t *this;
	char *token = NULL;
	size_t token_length = 0;
    DBG2(DBG_LIB, "[BLAST] Enter %s, %s (%d)", __func__, __FILE__, __LINE__ );

	token = lib->settings->get_str(lib->settings, "%s.plugins.blast.token", NULL, lib->ns);
	if (token == NULL) {
		DBG1(DBG_LIB, "[BLAST] Error: BLAST token is not set");
		return NULL;
	}
	token_length = strlen(token) + 1;

	INIT(this,
		.public = {
			.ke = {
				.get_method = _get_method,
				.get_public_key = _get_public_key,
				.set_public_key = _set_public_key,
				.get_shared_secret = _get_shared_secret,
				.destroy = _destroy,
			},
		},
		.method = method,
		.endpoint_type = EP_TYPE_UNKNOWN,
		.metadata = chunk_empty,
		.shared_secret = chunk_empty,
	);

	int ret_code = qrypt_security_create(&this->qrypt_security);
	if ( ret_code != QS_GOOD ) {
		DBG1(DBG_LIB, "[BLAST] Error: qrypt_security_create returned %s", qs_error_str(ret_code));
		return NULL;
	}

	/* Parse server list */
	int count = 0;
	char *serverlist[20] = {0};
	char *servers_buf = NULL;
	char *servers_str = lib->settings->get_str(lib->settings, "%s.plugins.blast.servers", NULL, lib->ns);

	if (servers_str != NULL) {
		servers_buf = strdup(servers_str);
		char *saveptr = NULL;
		char *entry = strtok_r(servers_buf, ",", &saveptr);
		while (entry != NULL && count < 20) {
			while (*entry == ' ' || *entry == '\t') {
				entry++;
			}
			if (*entry != '\0') {
				DBG2(DBG_LIB, "[BLAST] server %s loaded", entry);
				serverlist[count++] = entry;
			}
			entry = strtok_r(NULL, ",", &saveptr);
		}
	} else {
		DBG2(DBG_LIB, "[BLAST] no servers configured, will query directory service");
	}

	/* Read auth header type (omitted/zero = BEARER_AUTH, the SDK default) */
	enum qrypt_auth_header_type auth_type = 0;
	char *auth_str = lib->settings->get_str(lib->settings, "%s.plugins.blast.auth_header_type", NULL, lib->ns);
	if (auth_str != NULL && strcasecmp(auth_str, "xapi") == 0) {
		auth_type = XAPI_AUTH;
	}

	/* Read remaining config */
	char *ca_cert_path = lib->settings->get_str(lib->settings, "%s.plugins.blast.ca_cert_path", NULL, lib->ns);
	char *user_agent = lib->settings->get_str(lib->settings, "%s.plugins.blast.user_agent", NULL, lib->ns);

	client_config_t client_config = {
		.ca_cert_path = ca_cert_path,
		.static_servers = serverlist,
		.static_servers_count = count,
		.static_servers_tg = lib->settings->get_int(lib->settings, "%s.plugins.blast.tg", 0, lib->ns),
		.static_servers_tf = lib->settings->get_int(lib->settings, "%s.plugins.blast.tf", 0, lib->ns),
		.static_servers_ta = lib->settings->get_int(lib->settings, "%s.plugins.blast.ta", 0, lib->ns),
		.static_servers_tp = lib->settings->get_int(lib->settings, "%s.plugins.blast.tp", 0, lib->ns),
		.auth_header_type = auth_type,
		.user_agent = user_agent,
	};

	ret_code = qrypt_security_initialize_client_config(&this->qrypt_security, token, token_length, client_config);
	if (ret_code != QS_GOOD) {
		DBG1(DBG_LIB, "[BLAST] Error: qrypt_security_initialize returned %s", qs_error_str(ret_code));
		free(servers_buf);
		return NULL;
	}

	qrypt_security_set_log_level(QRYPTSECURITY_LOG_LEVEL_DEBUG);

	free(servers_buf);

	DBG2(DBG_LIB, "[BLAST] Exit %s, %s (%d)", __func__, __FILE__, __LINE__);
	return &this->public;

}
