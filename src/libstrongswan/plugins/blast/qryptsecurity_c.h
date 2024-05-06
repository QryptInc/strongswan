#ifdef __cplusplus
extern "C" {    
#endif
#include <inttypes.h>

/// <summary>
/// Describes the severity of a log
/// </summary>
enum qrypt_security_log_level {
    QRYPTSECURITY_LOG_LEVEL_DISABLE,
    QRYPTSECURITY_LOG_LEVEL_ERROR,
    QRYPTSECURITY_LOG_LEVEL_WARNING,
    QRYPTSECURITY_LOG_LEVEL_INFO,
    QRYPTSECURITY_LOG_LEVEL_DEBUG,
    QRYPTSECURITY_LOG_LEVEL_TRACE
};

/// <summary>
/// Set QryptSecurity logging level
/// </summary>
/// <param name="logLevel"> The highest log level to pipe to stdout </param>
void qrypt_security_set_log_level(enum qrypt_security_log_level logLevel);


enum qrypt_security_error_code {
    QS_GOOD                  =  0,
    QS_UNKNOWN_ERROR         = -1,
    QS_INVALID_ARGUMENT      = -2,
    QS_SYSTEM_ERROR          = -3,
    QS_CANNOT_DOWNLOAD       = -4,
    QS_DATA_CORRUPTED        = -5,
    QS_INCOMPATIBLE_VERSION  = -6,
};

typedef void* qrypt_security_t;

typedef struct {

    char* key;
    size_t key_size;

    uint8_t * metadata;
    size_t metadata_size;

} symmetric_key_data_t;

/// <summary>
/// Key configuration struct to store additional key configuration parameters
/// </summary>
typedef struct {

    /// <summary>
    /// Time for key samples to live in seconds. A value of 0 indicates to use the default.
    /// </summary>
    uint32_t ttl;
} key_config_t;

/// <summary>
/// Structure to store additional client configuration parameters
/// </summary>
typedef struct {

    /// <summary>
    /// Custom HTTP client
    /// </summary>
    void* custom_http_client;

    /// <summary>
    /// Absolute path to a CA Root Certificate for use with libCurl
    /// </summary>
    char* ca_cert_path;
} client_config_t;

/// <summary>
/// Initializes the client
/// </summary>
///
/// <param name="t">this qrypt security class initalized by this function</param>
int qrypt_security_create(qrypt_security_t * t);

/// <summary>
/// Deletes the client
/// </summary>
///
/// <param name="t">this qrypt security class deleted by this function</param>
int qrypt_security_delete(qrypt_security_t * t);

/// <summary>
/// Initializes the client with the qrypt token
/// </summary>
///
/// <param name="t">this qrypt security class</param>
/// <param name="token">qrypt token</param>
/// <param name="t">qrypt token size</param>
int qrypt_security_initialize(qrypt_security_t * t, char * token, size_t token_size);

/// <summary>
/// Initializes the client with the qrypt token and cert
/// </summary>
///
/// <param name="t">this qrypt security class</param>
/// <param name="token">qrypt token</param>
/// <param name="token_size">qrypt token size</param>
/// <param name="client_config">client configuration parameters</param>
/// <param name="caCertPath_size">Size if the cert path array</param>
int qrypt_security_initialize_client_config(qrypt_security_t * t, char * token, size_t token_size, const client_config_t client_config);

/// <summary>
/// Generates AES Key. Initalizes memory for the symmetric_key_data_t internal arrays.
/// </summary>
///
/// <param name="t">this qrypt security class</param>
/// <param name="key_data">symmetric_key_data_t return data</param>
int qrypt_security_gen_init_aes(qrypt_security_t * t,  symmetric_key_data_t * key_data, const key_config_t key_config);

/// <summary>
/// Generates OTP Key. Initalizes memory for the symmetric_key_data_t internal arrays.
/// Uses keysize to determine size of the OTP to generate
/// </summary>
///
/// <param name="t">this qrypt security class</param>
/// <param name="key_data">symmetric_key_data_t return data</param>
/// <param name="key_size">Size of otp data to generate</param>
/// <param name="key_config">key configuration parameters</param>
int qrypt_security_gen_init_otp(qrypt_security_t * t, symmetric_key_data_t * key_data, const size_t key_size, const key_config_t key_config);

/// <summary>
/// Generates symmetric key data from metadata.
/// Assumes the symmetric_key_data_t has metadata populated
/// Populates the key field of symmetric_key_data_t.
/// </summary>
///
/// <param name="t">this qrypt security class</param>
/// <param name="key_data">symmetric_key_data_t input/return data</param>
int qrypt_security_gen_sync(qrypt_security_t * t, symmetric_key_data_t * key_data);

/// <summary>
/// Frees children of the symmetric_key_data_t. Must be called to release memory.
/// </summary>
///
/// <param name="key_data">symmetric_key_data_t to free</param>

int qrypt_security_symmetric_key_data_free(symmetric_key_data_t * key_data);

#ifdef __cplusplus
}
#endif