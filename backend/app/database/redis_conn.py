import logging
from typing import Optional
import redis
from app.config import settings

logger = logging.getLogger(__name__)

class MockRedisCache:
    """Fallback in-memory cache if Redis is unavailable."""
    def __init__(self):
        self._store = {}
        self._expires = {}
        logger.warning("Redis not available. Falling back to In-Memory Cache.")

    def get(self, key: str) -> Optional[str]:
        # Simple expiration check could be added, but for basic mock, get/set is enough
        return self._store.get(key)

    def set(self, key: str, value: str, ex: int = None) -> bool:
        self._store[key] = value
        # ex represents seconds, ignoring for mock simplifications or basic storage
        return True

    def delete(self, key: str) -> int:
        if key in self._store:
            del self._store[key]
            return 1
        return 0

    def incr(self, key: str) -> int:
        val = self._store.get(key, "0")
        try:
            new_val = int(val) + 1
        except ValueError:
            new_val = 1
        self._store[key] = str(new_val)
        return new_val

    def expire(self, key: str, seconds: int) -> bool:
        return True

    def keys(self, pattern: str) -> list:
        # Simple matching for tests
        import fnmatch
        return [k for k in self._store.keys() if fnmatch.fnmatch(k, pattern)]

    def flushall(self):
        self._store.clear()

# Try to initialize Redis
try:
    # Set a short socket connection timeout so it fails fast if not running
    redis_client = redis.Redis.from_url(
        settings.REDIS_URL, 
        decode_responses=True,
        socket_connect_timeout=2
    )
    # Ping to check if Redis server is alive
    redis_client.ping()
    logger.info("Connected to Redis successfully.")
except Exception as e:
    logger.error(f"Failed to connect to Redis: {e}")
    redis_client = MockRedisCache()
