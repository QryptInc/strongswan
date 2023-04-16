#include "doca_plugin_ipsec.h"

#include <library.h>
#include <daemon.h>
#include <utils/debug.h>
#include <collections/hashtable.h>
#include <threading/mutex.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>

typedef struct private_doca_plugin_ipsec_t private_doca_plugin_ipsec_t;
typedef struct private_ipsec_sa_attrs private_ipsec_sa_attrs;
typedef struct doca_ipsec_policy doca_ipsec_policy;

#define MAX_KEY_LEN 32							/* Maximal GCM key size is 256bit==32B */
#define SALT_LENGTH 4							/* Salt length in bytes */
#define DOCA_PLUGIN_DEFAULT_SOCKET_PATH "/tmp/strongswan_doca_socket"	/* Default socket path */

struct private_doca_plugin_ipsec_t {

        /**
	 * Public doca_ipsec interface
	 */
	doca_plugin_ipsec_t public;

	/**
	 * Installed SAs
	 */
	linked_list_t *sas;

	/**
	 * SPIs allocated using get_spi()
	 */
	hashtable_t *allocated_spis;

	/**
	 * Mutex used to synchronize access to the SA manager
	 */
	mutex_t *mutex;

	/**
	 * Random number generators used to generate SPIs
	 */
	rng_t *rng;

	/*
	 * Connection file descriptor
	 */
	int fd;
};

/* DOCA defined policy structure */
struct doca_ipsec_policy {
	uint32_t msg_length;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t l3_protocol;
	uint8_t l4_protocol;
	uint8_t outer_l3_protocol;
	uint8_t policy_direction;
	uint8_t policy_mode;
	uint8_t esn;
	uint8_t icv_length;
	uint8_t key_type;
	uint32_t spi;
	uint32_t salt;
	char src_ip_addr[INET6_ADDRSTRLEN + 1];
	char dst_ip_addr[INET6_ADDRSTRLEN + 1];
	char outer_src_ip[INET6_ADDRSTRLEN + 1];
	char outer_dst_ip[INET6_ADDRSTRLEN + 1];
	uint8_t enc_key_data[MAX_KEY_LEN];
} __attribute__((packed));

/* Private IPSEC SA attributes */
struct private_ipsec_sa_attrs {
	uint32_t spi;		/* SA SPI */
	uint16_t enc_alg;	/* Encryption Algorithm */
	chunk_t enc_key;	/* Encryption key chunk */
	ipsec_mode_t mode;	/* IPSEC mode */
	bool esn;		/* if ESN enabled */
};

/* Compare function for SPI map */
CALLBACK(sa_entry_equals, bool,
	private_ipsec_sa_attrs *a, va_list args)
{
	uint32_t *spi;

	VA_ARGS_VGET(args, spi);

	return a->spi == *spi;
}

/* Helper function for printing the encryption key */
static void
print_enc_key(u_char *ptr, size_t len)
{
	char buffer[MAX_KEY_LEN + 1] = {0};
	int idx = 0;

	for (idx = 0; idx < len; idx ++) {

		if (' ' <= ptr[idx] && ptr[idx] <= '~')
			buffer[idx] = ptr[idx];
		else
			buffer[idx] = '.';
	}
	DBG2(DBG_KNL, "%s", buffer);
}

/* For printing the policy struct after setting the attributes */
static void
print_policy_attrs(struct doca_ipsec_policy *doca_policy, private_ipsec_sa_attrs *sa_attr)
{
	DBG2(DBG_KNL, "[DOCA][INFO] doca_policy->msg_length %u", ntohl(doca_policy->msg_length));
	DBG2(DBG_KNL, "[DOCA][INFO] doca_policy->l3_protocol %u == %s", doca_policy->l3_protocol, (doca_policy->l3_protocol == 6) ? "IPV6" : "IPV4");
	DBG2(DBG_KNL, "[DOCA][INFO] doca_policy->l4_protocol %u == %s", doca_policy->l4_protocol, (doca_policy->l4_protocol == IPPROTO_UDP) ? "UDP" : "TCP");
	DBG2(DBG_KNL, "[DOCA][INFO] doca_policy->src_ip_addr %s", doca_policy->src_ip_addr);
	DBG2(DBG_KNL, "[DOCA][INFO] doca_policy->dst_ip_addr %s", doca_policy->dst_ip_addr);
	DBG2(DBG_KNL, "[DOCA][INFO] doca_policy->src_port %u", ntohs(doca_policy->src_port));
	DBG2(DBG_KNL, "[DOCA][INFO] doca_policy->dst_port %u", ntohs(doca_policy->dst_port));
	DBG2(DBG_KNL, "[DOCA][INFO] doca_policy->policy_direction %u == %s", doca_policy->policy_direction, (doca_policy->policy_direction == 1) ? "OUT" : "IN");
	DBG2(DBG_KNL, "[DOCA][INFO] doca_policy->policy_mode %u == %s", doca_policy->policy_mode, (doca_policy->policy_mode == 1) ? "TUNNEL" : "TRANSPORT");
	DBG2(DBG_KNL, "[DOCA][INFO] doca_policy->spi %u", ntohl(doca_policy->spi));
	DBG2(DBG_KNL, "[DOCA][INFO] key length %u", (doca_policy->key_type + 1 ) * 16);
	DBG2(DBG_KNL, "[DOCA][INFO] doca_policy->enc_key_data:");
	print_enc_key(doca_policy->enc_key_data, sa_attr->enc_key.len - SALT_LENGTH);
	DBG2(DBG_KNL, "[DOCA][INFO] sa_attr->enc_key:");
	print_enc_key(sa_attr->enc_key.ptr, sa_attr->enc_key.len - SALT_LENGTH);
	DBG2(DBG_KNL, "[DOCA][INFO] doca_policy->salt %u", ntohl(doca_policy->salt));
	DBG2(DBG_KNL, "[DOCA][INFO] doca_policy->key_type %u", doca_policy->key_type == 1 ? 256 : 128);
	DBG2(DBG_KNL, "[DOCA][INFO] doca_policy->esn %u", doca_policy->esn);
	DBG2(DBG_KNL, "[DOCA][INFO] doca_policy->icv_length %u", doca_policy->icv_length);
	DBG2(DBG_KNL, "[DOCA][INFO] doca_policy->outer_src_ip %s", doca_policy->outer_src_ip);
	DBG2(DBG_KNL, "[DOCA][INFO] doca_policy->outer_dst_ip %s", doca_policy->outer_dst_ip);
	DBG2(DBG_KNL, "[DOCA][INFO] doca_policy->outer_l3_protocol %s", (doca_policy->outer_l3_protocol == 4) ? "IPV4" : "IPV6" );
}

/*
 * Used for the hash table of allocated SPIs
 */
static bool spi_equals(uint32_t *spi, uint32_t *other_spi)
{
	return *spi == *other_spi;
}

static u_int spi_hash(uint32_t *spi)
{
	return chunk_hash(chunk_from_thing(*spi));
}

/* List entry destroy callback  */
static void
sa_entry_destroy(private_ipsec_sa_attrs *this)
{
	chunk_clear(&this->enc_key);
}

/* Parsing traffic selector address, address format: <IP_ADDR>/<NETMASK>[<L4_PROTO>/<PORT>] */
static bool
parse_ts_addr(char *ip_addr, char *addr, uint16_t *port)
{
	int i = 0;
	char *array[5] = {0};
	char delim[] = {'/','[', ']'};
	char *ptr = strtok(ip_addr, delim);

	array[i++] = ptr;
	while(ptr != NULL)
	{
		ptr = strtok(NULL, delim);
		array[i++] = ptr;
	}
	if (array[0] == NULL || array[3] == NULL)
		return false;
	strcpy(addr, array[0]);
	*port = htons(atoi(array[3]));
	return true;
}

/* Convert enc algorithm to ICV length  */
static int get_icv_length(uint16_t enc_alg, uint8_t *icv_len)
{
	switch (enc_alg) {
	case ENCR_AES_GCM_ICV8:
		*icv_len = 8;
		return 0;
	case ENCR_AES_GCM_ICV12:
		*icv_len = 12;
		return 0;
	case ENCR_AES_GCM_ICV16:
		*icv_len = 16;
		return 0;
	default:
		DBG1(DBG_KNL,"[DOCA][ERR] the encryption algorithm isn't supported, should use AES GCM algorithms only");
		return -1;
	}
}

/**
 * Pre-allocate an SPI for an inbound SA
 */
static bool allocate_spi(private_doca_plugin_ipsec_t *this, uint32_t spi)
{
	uint32_t *spi_alloc;

	if (this->allocated_spis->get(this->allocated_spis, &spi))
	{
		return FALSE;
	}
	spi_alloc = malloc_thing(uint32_t);
	*spi_alloc = spi;
	this->allocated_spis->put(this->allocated_spis, spi_alloc, spi_alloc);
	return TRUE;
}

METHOD(kernel_ipsec_t, get_features, kernel_feature_t,
	private_doca_plugin_ipsec_t *this)
{
	DBG2(DBG_KNL, "[DOCA][INFO] Enter doca_plugin_ipsec get_features");
	return 0;
}

METHOD(kernel_ipsec_t, get_spi, status_t,
	private_doca_plugin_ipsec_t *this, host_t *src, host_t *dst,
	uint8_t protocol, uint32_t *spi)
{
	DBG2(DBG_KNL, "[DOCA][INFO] Enter doca_plugin_ipsec get_spi");

	uint32_t spi_min, spi_max, spi_new;

	spi_min = lib->settings->get_int(lib->settings, "%s.spi_min",
									 0x00000100, lib->ns);
	spi_max = lib->settings->get_int(lib->settings, "%s.spi_max",
									 0xffffffff, lib->ns);
	if (spi_min > spi_max)
	{
		spi_new = spi_min;
		spi_min = spi_max;
		spi_max = spi_new;
	}
	/* make sure the SPI is valid (not in range 0-255) */
	spi_min = max(spi_min, 0x00000100);
	spi_max = max(spi_max, 0x00000100);

	this->mutex->lock(this->mutex);
	if (!this->rng)
	{
		this->rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
		if (!this->rng)
		{
			this->mutex->unlock(this->mutex);
			DBG1(DBG_KNL, "[DOCA][ERR] failed to create random number generators for SPI generation");
			return FAILED;
		}
	}

	do
	{
		if (!this->rng->get_bytes(this->rng, sizeof(spi_new),
								 (uint8_t*)&spi_new))
		{
			this->mutex->unlock(this->mutex);
			DBG1(DBG_KNL, "[DOCA][ERR] failed to allocate SPI");
			return FAILED;
		}
		spi_new = spi_min + spi_new % (spi_max - spi_min + 1);
		spi_new = htonl(spi_new);
	}
	while (!allocate_spi(this, spi_new));
	this->mutex->unlock(this->mutex);

	*spi = spi_new;

	DBG3(DBG_KNL, "[DOCA][INFO] allocated SPI %.8x", ntohl(*spi));
	return SUCCESS;
}

METHOD(kernel_ipsec_t, get_cpi, status_t,
	private_doca_plugin_ipsec_t *this, host_t *src, host_t *dst,
	uint16_t *cpi)
{
	DBG2(DBG_KNL, "[DOCA][INFO] Enter doca_plugin_ipsec get_cpi");
	return SUCCESS;
}

METHOD(kernel_ipsec_t, add_sa, status_t,
	private_doca_plugin_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_add_sa_t *data)
{
	DBG2(DBG_KNL, "[DOCA][INFO] Enter doca_plugin_ipsec add_sa");

	private_ipsec_sa_attrs *sa_attr;

	INIT(sa_attr,
		.spi = id->spi,
		.enc_alg = data->enc_alg,
		.enc_key = chunk_clone(data->enc_key),
		.mode = data->mode,
		.esn = data->esn,
	);

	this->mutex->lock(this->mutex);
	this->sas->insert_last(this->sas, sa_attr);
	this->mutex->unlock(this->mutex);

	return SUCCESS;
}

METHOD(kernel_ipsec_t, update_sa, status_t,
	private_doca_plugin_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_update_sa_t *data)
{
	DBG2(DBG_KNL, "[DOCA][INFO] Enter doca_plugin_ipsec update_sa");
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, query_sa, status_t,
	private_doca_plugin_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_query_sa_t *data, uint64_t *bytes, uint64_t *packets,
	time_t *time)
{
	DBG2(DBG_KNL, "[DOCA][INFO] Enter doca_plugin_ipsec query_sa");
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_sa, status_t,
	private_doca_plugin_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_del_sa_t *data)
{
	DBG2(DBG_KNL, "[DOCA][INFO] Enter doca_plugin_ipsec del_sa");
	private_ipsec_sa_attrs *sa_attr = NULL;

	this->mutex->lock(this->mutex);
	if (this->sas->find_first(this->sas, sa_entry_equals, (void**)&sa_attr, &id->spi))
	{
		chunk_free(&sa_attr->enc_key);
		free(sa_attr);
	}
	this->mutex->unlock(this->mutex);
	return SUCCESS;
}

METHOD(kernel_ipsec_t, flush_sas, status_t,
	private_doca_plugin_ipsec_t *this)
{
	DBG2(DBG_KNL, "[DOCA][INFO] Enter doca_plugin_ipsec flush_sas");
	return SUCCESS;
}

METHOD(kernel_ipsec_t, add_policy, status_t,
	private_doca_plugin_ipsec_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_manage_policy_t *data)
{
	DBG2(DBG_KNL, "[DOCA][INFO] Enter doca_plugin_ipsec add_policy");
	struct doca_ipsec_policy doca_policy = {0};
	char ts_src[INET6_ADDRSTRLEN] = "";
	char ts_dst[INET6_ADDRSTRLEN] = "";
	char host_src[INET6_ADDRSTRLEN] = "";
	char host_dst[INET6_ADDRSTRLEN] = "";
	private_ipsec_sa_attrs *sa_attr = NULL;
	uint16_t port = 0;
	uint8_t icv_len;

	this->mutex->lock(this->mutex);
	if (!this->sas->find_first(this->sas, sa_entry_equals, (void**)&sa_attr, &data->sa->esp.spi)) {
		DBG1(DBG_KNL, "[DOCA][ERR] failed to find the policy SA in the table");
		this->mutex->unlock(this->mutex);
		return FAILED;
	}
	this->mutex->unlock(this->mutex);

	/* Set policy message length, msg length is not included in policy record size */
	doca_policy.msg_length = htonl(sizeof(struct doca_ipsec_policy) - sizeof(doca_policy.msg_length));

	/* Ports and IP addresses extraction */
	snprintf(ts_src, INET6_ADDRSTRLEN, "%R", id->src_ts);
	snprintf(ts_dst, INET6_ADDRSTRLEN, "%R", id->dst_ts);

	if (!parse_ts_addr(ts_src, doca_policy.src_ip_addr, &port)) {
		DBG1(DBG_KNL, "[DOCA][ERR] Failed to parse inner source ip address");
		return FAILED;
	}
	doca_policy.src_port = port;
	if (!parse_ts_addr(ts_dst, doca_policy.dst_ip_addr, &port)) {
		DBG1(DBG_KNL, "[DOCA][ERR] Failed to parse inner destination ip address");
		return FAILED;
	}
	doca_policy.dst_port = port;

	snprintf(doca_policy.outer_src_ip, INET6_ADDRSTRLEN, "%H", data->src);
	snprintf(doca_policy.outer_dst_ip, INET6_ADDRSTRLEN, "%H", data->dst);

	/* Protocols extraction */
	doca_policy.l3_protocol = (id->src_ts->get_type(id->src_ts) == TS_IPV4_ADDR_RANGE)? 4 : 6;
	doca_policy.l4_protocol = id->src_ts->get_protocol(id->src_ts);
	doca_policy.outer_l3_protocol = data->src->get_family(data->src) == AF_INET6 ? 6 : 4;

	/* Policy attributes */
	doca_policy.policy_direction = (uint8_t) id->dir;
	doca_policy.policy_mode = (uint8_t) (data->sa->mode - 1);

	/* SA attributes */
	if (get_icv_length(sa_attr->enc_alg, &icv_len) < 0)
		return FAILED;
	doca_policy.esn = sa_attr->esn ? 1 : 0;
	doca_policy.icv_length = icv_len;
	doca_policy.key_type = ((sa_attr->enc_key.len - SALT_LENGTH) * 8 == 128) ? 0 : 1;
	doca_policy.spi = htonl(sa_attr->spi);
	doca_policy.salt = htonl(*((uint32_t *) (sa_attr->enc_key.ptr + (sa_attr->enc_key.len - SALT_LENGTH))));	/* SALT placed at the last 32bits in enc_key */
	memcpy(doca_policy.enc_key_data, sa_attr->enc_key.ptr, sa_attr->enc_key.len - SALT_LENGTH);

	print_policy_attrs(&doca_policy, sa_attr);

	ssize_t num = 0;

	while(1) {
		this->mutex->lock(this->mutex);
		num += send(this->fd, (char *) (&doca_policy + num), sizeof(doca_policy) - num, 0);
		this->mutex->unlock(this->mutex);
		if (num == sizeof(doca_policy)) {
			DBG2(DBG_KNL, "[DOCA][INFO] Message was sent successfully");
			break;
		} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
			DBG2(DBG_KNL, "[DOCA][INFO] Failed to send the message, trying again");
			continue;
		} else {
			return FAILED;
		}
	}

	return SUCCESS;
}

METHOD(kernel_ipsec_t, query_policy, status_t,
	private_doca_plugin_ipsec_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_query_policy_t *data, time_t *use_time)
{
	DBG2(DBG_KNL, "[DOCA][INFO] Enter doca_plugin_ipsec query_policy");
	return NOT_SUPPORTED;
}


METHOD(kernel_ipsec_t, del_policy, status_t,
	private_doca_plugin_ipsec_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_manage_policy_t *data)
{
	DBG2(DBG_KNL, "[DOCA][INFO] Enter doca_plugin_ipsec del_policy");
	return SUCCESS;
}

METHOD(kernel_ipsec_t, flush_policies, status_t,
	private_doca_plugin_ipsec_t *this)
{
	DBG2(DBG_KNL, "[DOCA][INFO] Enter doca_plugin_ipsec flush_policies");
	return SUCCESS;
}


METHOD(kernel_ipsec_t, bypass_socket, bool,
	private_doca_plugin_ipsec_t *this, int fd, int family)
{
	DBG2(DBG_KNL, "[DOCA][INFO] Enter doca_plugin_ipsec bypass_socket");

	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, enable_udp_decap, bool,
	private_doca_plugin_ipsec_t *this, int fd, int family, uint16_t port)
{
	DBG2(DBG_KNL, "[DOCA][INFO] Enter doca_plugin_ipsec enable_udp_decap");

	return NOT_SUPPORTED;
}


METHOD(kernel_ipsec_t, destroy, void,
	private_doca_plugin_ipsec_t *this)
{
	DBG2(DBG_KNL, "[DOCA][INFO] Enter doca_plugin_ipsec destroy");
	this->mutex->destroy(this->mutex);
	DESTROY_IF(this->rng);
	this->sas->destroy_function(this->sas, (void*)sa_entry_destroy);
	this->allocated_spis->destroy(this->allocated_spis);
	/* Close the connection */
	close(this->fd);
	free(this);
}

/*
 * Described in header.
 */
doca_plugin_ipsec_t *doca_plugin_ipsec_create()
{
	DBG2(DBG_LIB, "[DOCA][INFO] Enter doca_plugin_ipsec_create()");
	private_doca_plugin_ipsec_t *this;
	struct sockaddr_un addr;
	char* socket_path;
	int result;

	INIT(this,
		.public = {
			.interface = {
				.get_features = _get_features,
				.get_spi = _get_spi,
				.get_cpi = _get_cpi,
				.add_sa  = _add_sa,
				.update_sa = _update_sa,
				.query_sa = _query_sa,
				.del_sa = _del_sa,
				.flush_sas = _flush_sas,
				.add_policy = _add_policy,
				.query_policy = _query_policy,
				.del_policy = _del_policy,
				.flush_policies = _flush_policies,
				.bypass_socket = _bypass_socket,
				.enable_udp_decap = _enable_udp_decap,
				.destroy = _destroy,
			},
		},
		.sas = linked_list_create(),
		.allocated_spis = hashtable_create((hashtable_hash_t)spi_hash, (hashtable_equals_t)spi_equals, 16),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	/* Get socket path from doca opt file */
	socket_path = lib->settings->get_str(lib->settings, "%s.plugins.doca.socket_path", NULL, lib->ns);
	if (socket_path == NULL) {
		DBG1(DBG_KNL, "[DOCA][WARN] Failed to get socket path from the .opt file, using %s instead", DOCA_PLUGIN_DEFAULT_SOCKET_PATH);
		socket_path = DOCA_PLUGIN_DEFAULT_SOCKET_PATH;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

	/* Create a Unix domain socket */
	this->fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (this->fd == -1) {
		DBG1(DBG_KNL, "[DOCA][ERR] Failed to create a socket");
		return NULL;
	}

	/* Connect to the server */
	result = connect(this->fd, (struct sockaddr*)&addr, sizeof(addr));
	if (result == -1) {
		DBG1(DBG_KNL, "[DOCA][ERR] Failed connecting to the socket");
		return NULL;
	}

	return &this->public;
}
