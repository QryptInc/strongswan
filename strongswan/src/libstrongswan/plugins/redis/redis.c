#include "redis.h"

#include <utils/debug.h>
#include <hiredis/hiredis.h>
#define KE_REDIS 1074
typedef struct private_redis_t private_redis_t;

/**
 * Private data of a redis_t object.
 */
struct private_redis_t {

    /**
     * Public redis_t interface.
     */
    redis_t public;

    redisContext *redis;

    chunk_t key_id;
    chunk_t secret;
};

bool redis_move_successful_result(redisReply *reply, chunk_t *output)
{
    bool success = false;
    if (reply && REDIS_REPLY_ERROR != reply->type)
    {
        chunk_t result = chunk_alloc(reply->len);
        if (result.ptr)
        {
            memcpy(result.ptr, reply->str, reply->len);
            *output = result;
            success = true;
        }
    }

    freeReplyObject(reply);
    return success;
}
bool redis_random_id(redisContext *c, chunk_t *key_id)
{
    // Try to get a random key ID
    redisReply *reply = redisCommand(c, "RANDOMKEY");
    return redis_move_successful_result(reply, key_id);
}

bool redis_secret_from_id(redisContext *c, chunk_t key_id, chunk_t *secret)
{
    // Try to get the key_id at this index
    redisReply *reply = redisCommand(c, "GET %b", key_id.ptr, key_id.len);
    return redis_move_successful_result(reply, secret);
}

METHOD(key_exchange_t, get_shared_secret, bool,
    private_redis_t *this, chunk_t *secret)
{
    // Pull key of that ID from the Redis
    bool result = redis_secret_from_id(this->redis, this->key_id, &this->secret);
    if(result)
    {
        *secret = chunk_clone(this->secret);
    }
    return result;
}

METHOD(key_exchange_t, get_public_key, bool,
    private_redis_t *this, chunk_t *key_id)
{
    // Returns the key ID, instead of a public key, randomly chosen from our Redis
    //   value is allocated
    bool result = redis_random_id(this->redis, &this->key_id);
    if(result)
    {
        *key_id = chunk_clone(this->key_id);
    }
    return result;
}

METHOD(key_exchange_t, set_public_key, bool,
    private_redis_t *this, chunk_t key_id)
{
    // Gets called with key ID, check our Redis for this key ID
    // A call to get_public_key that returned the same ID means we alreaedy have it
    bool success = false;
    if (0 == chunk_equals(key_id, this->key_id))
    {
        success = true;
    }
    else
    {
        // We got the ID as an arg, we just need to assign it *if* we have it
        if (redis_secret_from_id(this->redis, key_id, &this->secret))
        {
            this->key_id = key_id;
            success = true;
        }
    }
    return success;
}

METHOD(key_exchange_t, get_method, key_exchange_method_t,
    private_redis_t *this)
{
    return KE_REDIS;
}

METHOD(key_exchange_t, destroy, void,
    private_redis_t *this)
{
    chunk_clear(&this->key_id);
    chunk_clear(&this->secret);
    redisFree(this->redis);

    free(this);
}

/*
 * Described in header.
 */
redis_t *redis_create()
{
    private_redis_t *this;

    INIT(this,
        .public = {
            .key_exchange = {
                .get_public_key = _get_public_key,
                .set_public_key = _set_public_key,
                .get_shared_secret = _get_shared_secret,
                .get_method = _get_method,
                .destroy = _destroy
            }
        },
    );

#define REDIS_ADDRESS "127.0.0.1"
#define REDIS_PORT 6379
    this->redis = redisConnect(REDIS_ADDRESS, REDIS_PORT);
    if (!this->redis || this->redis->err)
    {
        char *err = this->redis ? this->redis->errstr : "";
        DBG1(DBG_LIB, "could not connect to redis at addresss %s:%hu %s",
             REDIS_ADDRESS, REDIS_PORT, err);
        destroy(this);
        return NULL;
    }
    DBG1(DBG_IKE, "REDIS redis_create successful");

    return &this->public;
}
