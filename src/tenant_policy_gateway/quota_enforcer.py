from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
import logging
import time
from typing import Protocol
from uuid import uuid4

from .config import AppSettings, QuotaMode
from .tenant_registry import TenantLimits

LOG = logging.getLogger("tenant_policy_gateway.quota")


@dataclass(frozen=True)
class QuotaDecision:
    allowed: bool
    status_code: int
    reason: str
    retry_after_seconds: int | None = None


@dataclass(frozen=True)
class UsageRecord:
    timestamp: float
    input_tokens: int
    output_tokens: int = 0


class QuotaEnforcer(Protocol):
    def check_and_record(
        self,
        *,
        tenant_id: str,
        user_id: str,
        limits: TenantLimits,
        estimated_input_tokens: int | None,
        request_id: str | None = None,
        now: float | None = None,
    ) -> QuotaDecision: ...

    def finish_request(self, *, tenant_id: str, user_id: str, request_id: str | None = None) -> None: ...


class InMemoryQuotaEnforcer:
    """Small per-process sliding-window enforcer for local/reference use."""

    def __init__(self, *, window_seconds: int = 60, concurrency_ttl_seconds: int = 900) -> None:
        self.window_seconds = window_seconds
        self.concurrency_ttl_seconds = concurrency_ttl_seconds
        self._user_records: dict[tuple[str, str], deque[UsageRecord]] = defaultdict(deque)
        self._tenant_records: dict[str, deque[UsageRecord]] = defaultdict(deque)
        self._active_user: dict[tuple[str, str], dict[str, float]] = defaultdict(dict)
        self._active_tenant: dict[str, dict[str, float]] = defaultdict(dict)

    def check_and_record(
        self,
        *,
        tenant_id: str,
        user_id: str,
        limits: TenantLimits,
        estimated_input_tokens: int | None,
        request_id: str | None = None,
        now: float | None = None,
    ) -> QuotaDecision:
        now = now if now is not None else time.time()
        request_id = request_id or str(uuid4())
        user_key = (tenant_id, user_id)
        user_records = self._user_records[user_key]
        tenant_records = self._tenant_records[tenant_id]
        self._drop_expired_records(user_records, now)
        self._drop_expired_records(tenant_records, now)
        self._drop_stale_concurrency(self._active_user[user_key], now)
        self._drop_stale_concurrency(self._active_tenant[tenant_id], now)

        candidate_input_tokens = max(0, estimated_input_tokens or 0)
        user_request_count = len(user_records)
        tenant_request_count = len(tenant_records)
        user_input_tokens = sum(record.input_tokens for record in user_records)
        tenant_input_tokens = sum(record.input_tokens for record in tenant_records)

        if limits.concurrent_requests is not None and len(self._active_user[user_key]) >= limits.concurrent_requests:
            return QuotaDecision(False, 429, "concurrency_quota_exceeded", 1)
        if limits.concurrent_requests is not None and len(self._active_tenant[tenant_id]) >= limits.concurrent_requests:
            return QuotaDecision(False, 429, "tenant_concurrency_quota_exceeded", 1)
        if limits.requests_per_minute is not None and user_request_count + 1 > limits.requests_per_minute:
            return QuotaDecision(False, 429, "request_quota_exceeded", self._retry_after(user_records, now))
        if limits.requests_per_minute is not None and tenant_request_count + 1 > limits.requests_per_minute:
            return QuotaDecision(False, 429, "tenant_request_quota_exceeded", self._retry_after(tenant_records, now))
        if limits.input_tokens_per_minute is not None and user_input_tokens + candidate_input_tokens > limits.input_tokens_per_minute:
            return QuotaDecision(False, 429, "input_token_quota_exceeded", self._retry_after(user_records, now))
        if limits.input_tokens_per_minute is not None and tenant_input_tokens + candidate_input_tokens > limits.input_tokens_per_minute:
            return QuotaDecision(False, 429, "tenant_input_token_quota_exceeded", self._retry_after(tenant_records, now))

        record = UsageRecord(timestamp=now, input_tokens=candidate_input_tokens)
        user_records.append(record)
        tenant_records.append(record)
        self._active_user[user_key][request_id] = now
        self._active_tenant[tenant_id][request_id] = now
        return QuotaDecision(True, 200, "quota_allowed")

    def finish_request(self, *, tenant_id: str, user_id: str, request_id: str | None = None) -> None:
        if request_id is None:
            # Backward-compatible safety: remove one arbitrary active item rather
            # than leaking indefinitely when older call sites do not pass IDs.
            self._pop_one(self._active_user[(tenant_id, user_id)])
            self._pop_one(self._active_tenant[tenant_id])
            return
        self._active_user[(tenant_id, user_id)].pop(request_id, None)
        self._active_tenant[tenant_id].pop(request_id, None)

    def _drop_expired_records(self, records: deque[UsageRecord], now: float) -> None:
        cutoff = now - self.window_seconds
        while records and records[0].timestamp <= cutoff:
            records.popleft()

    def _drop_stale_concurrency(self, active: dict[str, float], now: float) -> None:
        cutoff = now - self.concurrency_ttl_seconds
        stale = [request_id for request_id, timestamp in active.items() if timestamp <= cutoff]
        for request_id in stale:
            active.pop(request_id, None)

    def _retry_after(self, records: deque[UsageRecord], now: float) -> int:
        if not records:
            return self.window_seconds
        age = now - records[0].timestamp
        return max(1, int(self.window_seconds - age))

    @staticmethod
    def _pop_one(active: dict[str, float]) -> None:
        if active:
            active.pop(next(iter(active)))


_REDIS_CHECK_AND_RECORD_LUA = r"""
local user_requests_key = KEYS[1]
local user_input_key = KEYS[2]
local tenant_requests_key = KEYS[3]
local tenant_input_key = KEYS[4]
local user_concurrency_key = KEYS[5]
local tenant_concurrency_key = KEYS[6]

local now_ms = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local concurrency_ttl_ms = tonumber(ARGV[3])
local request_id = ARGV[4]
local candidate_input_tokens = tonumber(ARGV[5])
local user_request_limit = tonumber(ARGV[6])
local user_input_limit = tonumber(ARGV[7])
local user_concurrency_limit = tonumber(ARGV[8])
local tenant_request_limit = tonumber(ARGV[9])
local tenant_input_limit = tonumber(ARGV[10])
local tenant_concurrency_limit = tonumber(ARGV[11])
local key_ttl_seconds = tonumber(ARGV[12])

local cutoff = now_ms - window_ms
local stale_concurrency_cutoff = now_ms - concurrency_ttl_ms

redis.call('ZREMRANGEBYSCORE', user_requests_key, 0, cutoff)
redis.call('ZREMRANGEBYSCORE', user_input_key, 0, cutoff)
redis.call('ZREMRANGEBYSCORE', tenant_requests_key, 0, cutoff)
redis.call('ZREMRANGEBYSCORE', tenant_input_key, 0, cutoff)
redis.call('ZREMRANGEBYSCORE', user_concurrency_key, 0, stale_concurrency_cutoff)
redis.call('ZREMRANGEBYSCORE', tenant_concurrency_key, 0, stale_concurrency_cutoff)

local function zset_sum_tokens(key)
  local members = redis.call('ZRANGEBYSCORE', key, cutoff + 1, now_ms)
  local total = 0
  for _, member in ipairs(members) do
    local token_text = string.match(member, '|(%d+)$')
    if token_text ~= nil then
      total = total + tonumber(token_text)
    end
  end
  return total
end

local user_requests = redis.call('ZCARD', user_requests_key)
local tenant_requests = redis.call('ZCARD', tenant_requests_key)
local user_input = zset_sum_tokens(user_input_key)
local tenant_input = zset_sum_tokens(tenant_input_key)
local user_concurrency = redis.call('ZCARD', user_concurrency_key)
local tenant_concurrency = redis.call('ZCARD', tenant_concurrency_key)

local oldest_ms = now_ms
local function retry_after_for(key)
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  if oldest[2] ~= nil then
    local retry_ms = window_ms - (now_ms - tonumber(oldest[2]))
    if retry_ms < 1 then retry_ms = 1 end
    return math.ceil(retry_ms / 1000)
  end
  return math.ceil(window_ms / 1000)
end

if user_concurrency_limit >= 0 and user_concurrency >= user_concurrency_limit then
  return {0, 'concurrency_quota_exceeded', math.ceil(concurrency_ttl_ms / 1000)}
end
if tenant_concurrency_limit >= 0 and tenant_concurrency >= tenant_concurrency_limit then
  return {0, 'tenant_concurrency_quota_exceeded', math.ceil(concurrency_ttl_ms / 1000)}
end
if user_request_limit >= 0 and user_requests + 1 > user_request_limit then
  return {0, 'request_quota_exceeded', retry_after_for(user_requests_key)}
end
if tenant_request_limit >= 0 and tenant_requests + 1 > tenant_request_limit then
  return {0, 'tenant_request_quota_exceeded', retry_after_for(tenant_requests_key)}
end
if user_input_limit >= 0 and user_input + candidate_input_tokens > user_input_limit then
  return {0, 'input_token_quota_exceeded', retry_after_for(user_input_key)}
end
if tenant_input_limit >= 0 and tenant_input + candidate_input_tokens > tenant_input_limit then
  return {0, 'tenant_input_token_quota_exceeded', retry_after_for(tenant_input_key)}
end

local member = request_id
local input_member = request_id .. '|' .. tostring(candidate_input_tokens)
redis.call('ZADD', user_requests_key, now_ms, member)
redis.call('ZADD', tenant_requests_key, now_ms, member)
redis.call('ZADD', user_input_key, now_ms, input_member)
redis.call('ZADD', tenant_input_key, now_ms, input_member)
redis.call('ZADD', user_concurrency_key, now_ms, member)
redis.call('ZADD', tenant_concurrency_key, now_ms, member)

redis.call('EXPIRE', user_requests_key, key_ttl_seconds)
redis.call('EXPIRE', user_input_key, key_ttl_seconds)
redis.call('EXPIRE', tenant_requests_key, key_ttl_seconds)
redis.call('EXPIRE', tenant_input_key, key_ttl_seconds)
redis.call('EXPIRE', user_concurrency_key, key_ttl_seconds)
redis.call('EXPIRE', tenant_concurrency_key, key_ttl_seconds)
return {1, 'quota_allowed', 0}
"""

_REDIS_FINISH_LUA = r"""
local user_concurrency_key = KEYS[1]
local tenant_concurrency_key = KEYS[2]
local request_id = ARGV[1]
local key_ttl_seconds = tonumber(ARGV[2])
if request_id == '' then
  local user_oldest = redis.call('ZRANGE', user_concurrency_key, 0, 0)
  local tenant_oldest = redis.call('ZRANGE', tenant_concurrency_key, 0, 0)
  if user_oldest[1] ~= nil then redis.call('ZREM', user_concurrency_key, user_oldest[1]) end
  if tenant_oldest[1] ~= nil then redis.call('ZREM', tenant_concurrency_key, tenant_oldest[1]) end
else
  redis.call('ZREM', user_concurrency_key, request_id)
  redis.call('ZREM', tenant_concurrency_key, request_id)
end
redis.call('EXPIRE', user_concurrency_key, key_ttl_seconds)
redis.call('EXPIRE', tenant_concurrency_key, key_ttl_seconds)
return {redis.call('ZCARD', user_concurrency_key), redis.call('ZCARD', tenant_concurrency_key)}
"""

_REDIS_HEARTBEAT_LUA = r"""
local user_concurrency_key = KEYS[1]
local tenant_concurrency_key = KEYS[2]
local now_ms = tonumber(ARGV[1])
local request_id = ARGV[2]
local key_ttl_seconds = tonumber(ARGV[3])
redis.call('ZADD', user_concurrency_key, 'XX', now_ms, request_id)
redis.call('ZADD', tenant_concurrency_key, 'XX', now_ms, request_id)
redis.call('EXPIRE', user_concurrency_key, key_ttl_seconds)
redis.call('EXPIRE', tenant_concurrency_key, key_ttl_seconds)
return {redis.call('ZSCORE', user_concurrency_key, request_id), redis.call('ZSCORE', tenant_concurrency_key, request_id)}
"""


class RedisQuotaEnforcer:
    """Redis-backed quota implementation using sliding-window ZSETs.

    Request and input-token limits use millisecond-scored sorted sets, avoiding
    fixed-window boundary bursts. Concurrency is tracked by request_id in ZSETs
    with stale-entry cleanup and TTLs, so a crashed pod cannot leak an anonymous
    counter forever.
    """

    def __init__(
        self,
        *,
        redis_url: str,
        window_seconds: int = 60,
        key_prefix: str = "aibrix-gateway",
        concurrency_ttl_seconds: int = 900,
    ) -> None:
        try:
            import redis  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("APP_QUOTA_MODE=redis requires redis>=5 to be installed") from exc
        self.window_seconds = window_seconds
        self.window_ms = window_seconds * 1000
        self.concurrency_ttl_seconds = concurrency_ttl_seconds
        self.concurrency_ttl_ms = concurrency_ttl_seconds * 1000
        self.key_ttl_seconds = max(window_seconds, concurrency_ttl_seconds) + 60
        self.key_prefix = key_prefix.rstrip(":")
        self.client = redis.Redis.from_url(redis_url, decode_responses=True)
        self._check_sha = self.client.script_load(_REDIS_CHECK_AND_RECORD_LUA)
        self._finish_sha = self.client.script_load(_REDIS_FINISH_LUA)
        self._heartbeat_sha = self.client.script_load(_REDIS_HEARTBEAT_LUA)

    def check_and_record(
        self,
        *,
        tenant_id: str,
        user_id: str,
        limits: TenantLimits,
        estimated_input_tokens: int | None,
        request_id: str | None = None,
        now: float | None = None,
    ) -> QuotaDecision:
        now_ms = int((now if now is not None else time.time()) * 1000)
        request_id = request_id or str(uuid4())
        candidate_input_tokens = max(0, estimated_input_tokens or 0)
        keys = self._keys(tenant_id=tenant_id, user_id=user_id)
        args = [
            now_ms,
            self.window_ms,
            self.concurrency_ttl_ms,
            request_id,
            candidate_input_tokens,
            _limit_arg(limits.requests_per_minute),
            _limit_arg(limits.input_tokens_per_minute),
            _limit_arg(limits.concurrent_requests),
            _limit_arg(limits.requests_per_minute),
            _limit_arg(limits.input_tokens_per_minute),
            _limit_arg(limits.concurrent_requests),
            self.key_ttl_seconds,
        ]
        try:
            allowed, reason, retry_after = self.client.evalsha(self._check_sha, len(keys), *keys, *args)
        except Exception:
            LOG.exception("Redis quota check failed")
            return QuotaDecision(False, 503, "quota_backend_unavailable", 1)
        if int(allowed) == 1:
            return QuotaDecision(True, 200, str(reason))
        return QuotaDecision(False, 429, str(reason), int(retry_after))

    def finish_request(self, *, tenant_id: str, user_id: str, request_id: str | None = None) -> None:
        keys = self._concurrency_keys(tenant_id=tenant_id, user_id=user_id)
        try:
            self.client.evalsha(self._finish_sha, len(keys), *keys, request_id or "", self.key_ttl_seconds)
        except Exception:
            LOG.exception("Redis quota finish_request failed")

    def heartbeat_request(self, *, tenant_id: str, user_id: str, request_id: str) -> None:
        keys = self._concurrency_keys(tenant_id=tenant_id, user_id=user_id)
        now_ms = int(time.time() * 1000)
        try:
            self.client.evalsha(self._heartbeat_sha, len(keys), *keys, now_ms, request_id, self.key_ttl_seconds)
        except Exception:
            LOG.exception("Redis quota heartbeat failed")

    def _keys(self, *, tenant_id: str, user_id: str) -> list[str]:
        user_base = f"{self.key_prefix}:quota:user:{tenant_id}:{user_id}"
        tenant_base = f"{self.key_prefix}:quota:tenant:{tenant_id}"
        return [
            f"{user_base}:requests",
            f"{user_base}:input_tokens",
            f"{tenant_base}:requests",
            f"{tenant_base}:input_tokens",
            *self._concurrency_keys(tenant_id=tenant_id, user_id=user_id),
        ]

    def _concurrency_keys(self, *, tenant_id: str, user_id: str) -> list[str]:
        concurrency_base = f"{self.key_prefix}:concurrency"
        return [
            f"{concurrency_base}:user:{tenant_id}:{user_id}",
            f"{concurrency_base}:tenant:{tenant_id}",
        ]


def _limit_arg(value: int | None) -> int:
    return int(value) if value is not None else -1


def create_quota_enforcer(settings: AppSettings) -> QuotaEnforcer | None:
    if settings.quota_mode == QuotaMode.DISABLED:
        return None
    if settings.quota_mode == QuotaMode.IN_MEMORY:
        return InMemoryQuotaEnforcer(
            window_seconds=settings.quota_window_seconds,
            concurrency_ttl_seconds=settings.redis_quota_concurrency_ttl_seconds,
        )
    if settings.quota_mode == QuotaMode.REDIS:
        return RedisQuotaEnforcer(
            redis_url=settings.redis_quota_url,
            window_seconds=settings.quota_window_seconds,
            key_prefix=settings.redis_quota_key_prefix,
            concurrency_ttl_seconds=settings.redis_quota_concurrency_ttl_seconds,
        )
    raise ValueError(f"Unsupported quota mode: {settings.quota_mode}")
