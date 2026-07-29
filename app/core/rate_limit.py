import time
import logging
import redis
from app.core.config import settings

logger = logging.getLogger(__name__)

_redis_client: redis.Redis | None = None


def get_redis() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis_client


def check_rate_limit(key_id: str, limit_rpm: int) -> bool:
    """
    Sliding window rate limiter.
    Key format: rate:{key_id}:{unix_minute}
    Returns True if request is allowed, False if limit exceeded.
    """
    unix_minute = int(time.time() // 60)
    redis_key = f"rate:{key_id}:{unix_minute}"

    try:
        r = get_redis()
        pipe = r.pipeline()
        pipe.incr(redis_key)
        pipe.expire(redis_key, 120)  # 2 min TTL — covers current + previous minute
        results = pipe.execute()
        current_count = results[0]
        return current_count <= limit_rpm
    except redis.RedisError as e:
        logger.warning("Rate limit check failed (Redis error), allowing request: %s", e)
        return True
