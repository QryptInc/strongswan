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

#include "quantum_entropy_rng.h"
#include "curl_base64.h"

#include <jansson.h>
#include <unistd.h>
#include <fcntl.h>

#ifndef DEV_RANDOM
# define DEV_RANDOM "/dev/random"
#endif

#define BUFFER_SIZE 1024
#define STRINGIFY(x) #x
#define EXPAND_AND_STRINGIFY(x) STRINGIFY(x)

typedef struct private_quantum_entropy_rng_t private_quantum_entropy_rng_t;

/**
 * Private data of an quantum_entropy_rng_t object.
 */
struct private_quantum_entropy_rng_t {

	/**
	 * Public quantum_entropy_rng_t interface.
	 */
	quantum_entropy_rng_t public;

	/**
	 * Quality we produce RNG data
	 */
	rng_quality_t quality;
};

/**
 * XOR arrays of entropy and return resulting array
 */
void xor_arrays(const uint8_t *quantum_entropy_array, const uint8_t *local_entropy_array, uint8_t* result, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        result[i] = quantum_entropy_array[i] ^ local_entropy_array[i];
    }
}

/**
 * Fill a buffer with entropy from dev/random
 */
static bool read_random_from_file(size_t bytes, uint8_t* buffer)
{
	char *random_file;
	random_file = lib->settings->get_str(lib->settings,
						"%s.plugins.quantum_entropy.random", DEV_RANDOM, lib->ns);

    int fd = open(random_file, O_RDONLY);
    if (fd == -1) {
		DBG1(DBG_LIB, "Error opening %s", random_file);
        return FALSE;
    }

    ssize_t bytes_read = read(fd, buffer, bytes);
    if (bytes_read == -1) {
		DBG1(DBG_LIB, "Error reading from %s", random_file);
        close(fd);
        return FALSE;
    }

    close(fd);
	return TRUE;
}

/**
 * Fill a preallocated chunk of data with entropy bytes
 */
static bool quantum_entropy_chunk(private_quantum_entropy_rng_t *this, chunk_t chunk)
{
	char *token;
	char *fqdn;
	chunk_t response_chunk;
	uint8_t *binary_quantum_entropy;
	size_t bin_size; 

	json_t *root;

	json_t *entropy_array;
	json_t *entropy_json_base64;
	char *entropy_base64;
	json_error_t error;
	
	const char *post_data = "{\"block_size\": "EXPAND_AND_STRINGIFY(BUFFER_SIZE)"}";
    chunk_t request_data = chunk_create(post_data, strlen(post_data));

    char url[] = "https://%s/api/v1/entropy";
	char auth_header[] = "Authorization: Bearer %s";

	fqdn = lib->settings->get_str(lib->settings, "%s.plugins.quantum_entropy.fqdn",
									 NULL, lib->ns);

	token = lib->settings->get_str(lib->settings, "%s.plugins.quantum_entropy.jwt",
									 NULL, lib->ns);

	int endpoint_length = snprintf(NULL, 0, url, fqdn) + 1;
	int header_length = snprintf(NULL, 0, auth_header, token) + 1;
	char entropy_endpoint[endpoint_length];
    char header_string[header_length];

    int entropy_result = sprintf(entropy_endpoint, url, fqdn);
	int header_result = sprintf(header_string, auth_header, token);

	if (entropy_result < 0 || header_result < 0) 
	{
		DBG1(DBG_LIB, "Error While Formatting Strings For Entropy Request");
        return FALSE;
	}
	
	if (lib->fetcher->fetch(lib->fetcher, entropy_endpoint, &response_chunk,
							FETCH_REQUEST_DATA, request_data,
							FETCH_REQUEST_TYPE, "application/json",
							FETCH_REQUEST_HEADER, header_string,
							FETCH_REQUEST_HEADER, "Accept: application/json",
							FETCH_END) == SUCCESS) {
								DBG2(DBG_LIB, "Successfully Received Entropy");
	}
	else {
		DBG1(DBG_LIB, "Failed to Receive Entropy");
		return FALSE;
    }

	char json_text[response_chunk.len + 1];
	memcpy(json_text, response_chunk.ptr, response_chunk.len);

	json_text[response_chunk.len] = '\0';

	DBG2(DBG_LIB, "%s", json_text);

	root = json_loads(json_text, 0, &error);

    if (!root) {
		DBG1(DBG_LIB, "Error Loading JSON: %s", error.text);
        return FALSE;
    }

	entropy_array = json_object_get(root, "entropy");
	if (!json_is_array(entropy_array)) {
		json_decref(root);
		DBG1(DBG_LIB, "Error Parsing Entropy Array from JSON");
		return FALSE;
	}

	entropy_json_base64 = json_array_get(entropy_array, 0);

	if(!json_is_string(entropy_json_base64)) {
		json_decref(entropy_array);
		json_decref(root);
		DBG1(DBG_LIB, "Error Parsing Entropy String from JSON");
		return FALSE;
	}
	DBG3(DBG_LIB, "Parsing JSON");
	entropy_base64 = json_string_value(entropy_json_base64);

	bin_size = Curl_base64_decode(entropy_base64, &binary_quantum_entropy);

	json_decref(entropy_array);
	json_decref(entropy_json_base64);
	json_decref(root);

	DBG3(DBG_LIB, "Parsed JSON");

	if (bin_size < chunk.len) {
		return FALSE;
	}

	uint8_t binary_local_entropy[BUFFER_SIZE] = {0};
	bool read_success = read_random_from_file(BUFFER_SIZE, binary_local_entropy);

	uint8_t xor_entropy[BUFFER_SIZE];
	if (read_success) {
    	xor_arrays(binary_quantum_entropy, binary_local_entropy, xor_entropy, BUFFER_SIZE);
		memcpy(chunk.ptr, xor_entropy, chunk.len);
		DBG3(DBG_LIB, "Entropy API XOR'd with Local Random");
	}
	else
	{
		memcpy(chunk.ptr, binary_quantum_entropy, chunk.len);
		DBG3(DBG_LIB, "Only Using Entropy API");
	}

	return TRUE;
}


METHOD(rng_t, get_bytes, bool,
	private_quantum_entropy_rng_t *this, size_t bytes, uint8_t *buffer)
{
	switch (this->quality)
	{
		case RNG_WEAK:
		case RNG_STRONG:
		case RNG_TRUE:
			return quantum_entropy_chunk(this, chunk_create(buffer, bytes));
		default:
			return FALSE;
	}
}

METHOD(rng_t, allocate_bytes, bool,
	private_quantum_entropy_rng_t *this, size_t bytes, chunk_t *chunk)
{
	*chunk = chunk_alloc(bytes);
	if (get_bytes(this, bytes, chunk->ptr))
	{
		return TRUE;
	}
	free(chunk->ptr);
	return FALSE;
}

METHOD(rng_t, destroy, void,
	private_quantum_entropy_rng_t *this)
{
	free(this);
}


/*
 * Described in header.
 */
quantum_entropy_rng_t *quantum_entropy_rng_create(rng_quality_t quality)
{
    DBG2(DBG_LIB, "QUANTUM_ENTROPY CREATE");

	private_quantum_entropy_rng_t *this;

	char *token;
	char *fqdn;

	token = lib->settings->get_str(lib->settings, "%s.plugins.quantum_entropy.jwt",
									 NULL, lib->ns);					 

	fqdn = lib->settings->get_str(lib->settings, "%s.plugins.quantum_entropy.fqdn",
									 NULL, lib->ns);

	if (!token)
	{
		DBG1(DBG_LIB, "Quantum Entropy API JWT Not Configured");
		return FALSE;
	}

	if (!fqdn)
	{
		DBG1(DBG_LIB, "Quantum Entropy API FQDN Not Configured");
		return FALSE;
	}

	switch (quality)
	{
		case RNG_WEAK:
		case RNG_STRONG:
		case RNG_TRUE:
			break;
		default:
			return NULL;
	}

	INIT(this,
		.public = {
			.rng = {
				.get_bytes = _get_bytes,
				.allocate_bytes = _allocate_bytes,
				.destroy = _destroy,
			},
		},
		.quality = quality,
	);

	return &this->public;
}
