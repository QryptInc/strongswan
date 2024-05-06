#include "blast_ke.h"
#include "qryptsecurity_c.h"
#include <library.h>
#include <utils/debug.h>

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

/**
 * Gets the own public key to transmit.
 *
 * @param value		public key (allocated)
 * @return			TRUE if public key retrieved
 */
METHOD(key_exchange_t, get_public_key, bool, private_blast_ke_t *this, chunk_t *value)
{

    symmetric_key_data_t key_data;
	key_config_t key_config = { 300 };

	DBG2(DBG_LIB, "Enter %s, %s (%d)", __func__, __FILE__, __LINE__ );

	if (this->endpoint_type == EP_TYPE_INITIATOR) {

		DBG1(DBG_LIB, "Error: unexpected endpoint_type %d", this->endpoint_type);
		return FALSE;

	} else if (this->endpoint_type == EP_TYPE_UNKNOWN) {

		this->endpoint_type = EP_TYPE_INITIATOR; // get_public_key is the first KE call by the initiator

		// Perform blast genInit
		DBG1(DBG_LIB, "%s: EP_TYPE_INITIATOR call qrypt_security_gen_init_aes", __func__);
		int ret_code = qrypt_security_gen_init_aes(&this->qrypt_security, &key_data, key_config);
		if (ret_code != QS_GOOD) {
			DBG1(DBG_LIB, "Error: qrypt_security_gen_init_aes returned %d", ret_code);
			return FALSE;
		}

		// Save blast key
		DBG1(DBG_LIB, "%s: EP_TYPE_INITIATOR save blast key", __func__);
		this->shared_secret = chunk_clone(chunk_create(key_data.key, key_data.key_size));

		DBG1(DBG_LIB, "%s: EP_TYPE_INITIATOR return metadata", __func__);
		*value = chunk_clone(chunk_create(key_data.metadata, key_data.metadata_size));

		// Free key data structure
		ret_code = qrypt_security_symmetric_key_data_free(&key_data);
		if (ret_code != QS_GOOD) {
			DBG1(DBG_LIB, "Error: qrypt_security_symmetric_key_data_free returned %d", ret_code);
			return FALSE;
		}

	} else if (this->endpoint_type == EP_TYPE_RESPONDER ) {

		//DBG1(DBG_LIB, "%s: EP_TYPE_RESPONDER return ack", __func__);

        uint8_t ssecret[32] = "metadata_rcvd\n";
        *value = chunk_clone(chunk_from_thing(ssecret));

	}

	DBG2(DBG_LIB, "Exit %s, %s (%d)", __func__, __FILE__, __LINE__);
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

	DBG2(DBG_LIB, "Enter %s, %s (%d)", __func__, __FILE__, __LINE__ );

	if (this->endpoint_type == EP_TYPE_RESPONDER) {

		DBG1(DBG_LIB, "Error: unexpected endpoint_type %d", this->endpoint_type);
		return FALSE;

	} else if (this->endpoint_type == EP_TYPE_UNKNOWN) {

		this->endpoint_type = EP_TYPE_RESPONDER;  // set_public_key is the first KE call by the responder
		
		if(value.len > 0) { 
			DBG1(DBG_LIB, "%s: EP_TYPE_RESPONDER save metadata", __func__);
			this->metadata = chunk_clone(value);
		} else {
			DBG1(DBG_LIB, "Error: Responder did not receive metadata");
			return FALSE;
		}

	} else if (this->endpoint_type == EP_TYPE_INITIATOR ) {

		//DBG1(DBG_LIB, "%s: EP_TYPE_INITIATOR do nothing with ack", __func__);

	}

	DBG2(DBG_LIB, "Exit %s, %s (%d)", __func__, __FILE__, __LINE__);
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
	
    DBG2(DBG_LIB, "Enter %s, %s (%d)", __func__, __FILE__, __LINE__);

	if (this->endpoint_type == EP_TYPE_RESPONDER) {
		
		if (this->metadata.ptr == NULL) {
			DBG1(DBG_LIB, "Error: metadata was not saved from a prior call");
			return FALSE;
		}

		// Initialize temporary key data structure
		symmetric_key_data_t key_data;
		key_data.metadata = this->metadata.ptr;
		key_data.metadata_size = this->metadata.len;

		// Perform blast genSync
		DBG1(DBG_LIB, "%s: EP_TYPE_RESPONDER call qrypt_security_gen_sync", __func__);
		int ret_code = qrypt_security_gen_sync(&this->qrypt_security, &key_data);	// TODO: Update c wrapper to split key_data to metadata and key
		if (ret_code != QS_GOOD) {
			DBG1(DBG_LIB, "Error: qrypt_security_gen_sync returned %d", ret_code);
			return FALSE;
		}

		// Copy blast key
		*secret = chunk_clone(chunk_create(key_data.key, key_data.key_size));

		// Only free blast key from temporary key data structure
		key_data.metadata = NULL;
		key_data.metadata_size = 0;
		ret_code = qrypt_security_symmetric_key_data_free(&key_data);
		if (ret_code != QS_GOOD) {
			DBG1(DBG_LIB, "Error: qrypt_security_symmetric_key_data_free returned %d", ret_code);
			return FALSE;
		}

		DBG1(DBG_LIB, "%s: EP_TYPE_RESPONDER BLAST shared secret %B", __func__, secret);	// TODO: Drop log level to 4

	} else if (this->endpoint_type == EP_TYPE_INITIATOR) {

		// Blast key should already be generated from the get_public_key call
		*secret = chunk_clone(this->shared_secret);
		DBG1(DBG_LIB, "%s: EP_TYPE_INITIATOR BLAST shared secret %B", __func__, secret);	// TODO: Drop log level to 4

	} else {

		DBG1(DBG_LIB, "Error: unexpected endpoint_type %d", this->endpoint_type);
		return FALSE;

	}

	DBG2(DBG_LIB, "Exit %s, %s (%d)", __func__, __FILE__, __LINE__);
	return TRUE;

}

METHOD(key_exchange_t, get_method, key_exchange_method_t, private_blast_ke_t *this)
{
	return this->method;
}

METHOD(key_exchange_t, destroy, void, private_blast_ke_t *this)
{
    DBG2(DBG_LIB, "Enter %s, %s (%d)", __func__, __FILE__, __LINE__ );
    int ret_code = qrypt_security_delete(&this->qrypt_security);
	if (ret_code != QS_GOOD) {
		DBG1(DBG_LIB, "Error: qrypt_security_delete returned %d", ret_code);
		return FALSE;
	}

	chunk_free(&this->shared_secret);
	chunk_free(&this->metadata);
	free(this);
	DBG2(DBG_LIB, "Exit %s, %s (%d)", __func__, __FILE__, __LINE__);
}

/*
 * Described in header.
 */
blast_ke_t *blast_ke_create(key_exchange_method_t method)
{
	
	private_blast_ke_t *this;
	char *token = NULL;
	size_t token_length = 0;
    DBG2(DBG_LIB, "Enter %s, %s (%d)", __func__, __FILE__, __LINE__ );

	token = lib->settings->get_str(lib->settings, "%s.plugins.blast.jwt", NULL, lib->ns);
	if (token == NULL) {
		DBG1(DBG_LIB, "JMP Blast JWT token is not set\n");
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

    //DBG1(DBG_LIB, "EJF %s\n", token);

	int ret_code = qrypt_security_create(&this->qrypt_security);
	if ( ret_code != QS_GOOD ) {
		DBG1(DBG_LIB, "Error: qrypt_security_create returned %d", ret_code);
		return NULL;
	}

	ret_code = qrypt_security_initialize(&this->qrypt_security, token, token_length);
	if ( ret_code != QS_GOOD ) {
		DBG1(DBG_LIB, "Error: qrypt_security_initialize returned %d", ret_code);
		return NULL;
	}

	DBG2(DBG_LIB, "Exit %s, %s (%d)", __func__, __FILE__, __LINE__);
	return &this->public;

}