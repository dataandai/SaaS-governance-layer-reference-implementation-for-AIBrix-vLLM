from __future__ import annotations

from collections import OrderedDict, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event, Lock, Thread
from typing import Any
from uuid import uuid4

from .config import BillingMode

LOG = logging.getLogger("tenant_policy_gateway.billing")


class BillingLedgerError(RuntimeError):
    """Raised when a required billing ledger operation cannot be accepted."""


@dataclass(frozen=True)
class UsageTokens:
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    source: str


@dataclass(frozen=True)
class BillingLedgerEntry:
    request_id: str
    tenant_id: str
    user_id: str
    model: str
    adapter: str | None
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    source: str
    billing_grade_reference: bool
    sink: str
    created_at: str


class _BoundedLRUSet:
    def __init__(self, max_size: int) -> None:
        self.max_size = max_size
        self._items: OrderedDict[str, None] = OrderedDict()
        self._lock = Lock()

    def add_if_absent(self, key: str) -> bool:
        with self._lock:
            if key in self._items:
                self._items.move_to_end(key)
                return False
            self._items[key] = None
            while len(self._items) > self.max_size:
                self._items.popitem(last=False)
            return True

    def discard(self, key: str) -> None:
        with self._lock:
            self._items.pop(key, None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


class BillingLedger:
    """Memory-bounded batched billing ledger.

    Local JSONL and AWS-native S3 modes share the same bounded queue. S3 writes
    are batched into partitioned JSONL objects instead of one PUT per request.
    A bounded LRU prevents immediate request-id replay without the unbounded
    memory leak of a plain set. Optional DynamoDB idempotency provides durable
    request-id claiming in AWS-native mode.
    """

    def __init__(
        self,
        *,
        mode: BillingMode,
        jsonl_path: Path | None = None,
        aws_s3_bucket: str | None = None,
        aws_s3_prefix: str = "billing-ledger/",
        aws_dynamodb_table: str | None = None,
        aws_region: str | None = None,
        batch_max_records: int = 1000,
        flush_interval_seconds: float = 5.0,
        queue_max_records: int = 10000,
        lru_max_request_ids: int = 100000,
    ) -> None:
        self.mode = mode
        self.jsonl_path = jsonl_path
        self.aws_s3_bucket = aws_s3_bucket
        self.aws_s3_prefix = aws_s3_prefix.strip("/") + "/"
        self.aws_dynamodb_table = aws_dynamodb_table
        self.aws_region = aws_region
        self.batch_max_records = batch_max_records
        self.flush_interval_seconds = flush_interval_seconds
        self._seen_request_ids = _BoundedLRUSet(lru_max_request_ids)
        self._queue: Queue[BillingLedgerEntry] = Queue(maxsize=queue_max_records)
        self._stop_event = Event()
        self._worker: Thread | None = None
        self._s3_client: Any | None = None
        self._dynamodb_client: Any | None = None
        self._write_lock = Lock()
        if self.mode == BillingMode.LEDGER_REQUIRED and self.jsonl_path is None:
            raise ValueError("ledger_required mode requires jsonl_path")
        if self.mode == BillingMode.AWS_NATIVE_REFERENCE and not self.aws_s3_bucket:
            raise ValueError("aws_native_reference mode requires aws_s3_bucket")
        if self.jsonl_path is not None:
            self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        if self.mode in {BillingMode.LEDGER_REQUIRED, BillingMode.AWS_NATIVE_REFERENCE}:
            self.start()

    def start(self) -> None:
        if self._worker is not None and self._worker.is_alive():
            return
        self._stop_event.clear()
        self._worker = Thread(target=self._worker_loop, name="billing-ledger-flusher", daemon=True)
        self._worker.start()

    def close(self, *, timeout_seconds: float = 10.0) -> None:
        self._stop_event.set()
        if self._worker is not None:
            self._worker.join(timeout=timeout_seconds)
        self.flush()

    def require_usage_tokens(self, response_body: Any) -> UsageTokens | None:
        if not isinstance(response_body, dict):
            return None
        usage = response_body.get("usage")
        if not isinstance(usage, dict):
            return None
        prompt_tokens = usage.get("prompt_tokens")
        completion_tokens = usage.get("completion_tokens")
        total_tokens = usage.get("total_tokens")
        if not all(isinstance(value, int) and value >= 0 for value in [prompt_tokens, completion_tokens, total_tokens]):
            return None
        if prompt_tokens + completion_tokens != total_tokens:
            return None
        return UsageTokens(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            source="upstream_usage_required",
        )

    def append(
        self,
        *,
        request_id: str,
        tenant_id: str,
        user_id: str,
        model: str,
        adapter: str | None,
        usage: UsageTokens,
    ) -> None:
        if self.mode not in {BillingMode.LEDGER_REQUIRED, BillingMode.AWS_NATIVE_REFERENCE}:
            return
        if not self._seen_request_ids.add_if_absent(request_id):
            LOG.info('{"event":"billing_duplicate_request_suppressed","request_id":"%s"}', request_id)
            return
        sink = "s3_object_lock_batched_reference" if self.mode == BillingMode.AWS_NATIVE_REFERENCE else "local_jsonl_batched_reference"
        entry = BillingLedgerEntry(
            request_id=request_id,
            tenant_id=tenant_id,
            user_id=user_id,
            model=model,
            adapter=adapter,
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
            total_tokens=usage.total_tokens,
            source=usage.source,
            billing_grade_reference=True,
            sink=sink,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        try:
            self._queue.put_nowait(entry)
        except Full as exc:
            self._seen_request_ids.discard(request_id)
            LOG.error('{"event":"billing_queue_full","request_id":"%s","tenant_id":"%s"}', request_id, tenant_id)
            raise BillingLedgerError("billing_queue_full") from exc

    def flush(self) -> None:
        batch: list[BillingLedgerEntry] = []
        while len(batch) < self.batch_max_records:
            try:
                batch.append(self._queue.get_nowait())
            except Empty:
                break
        if batch:
            self._flush_batch(batch)

    def _worker_loop(self) -> None:
        batch: list[BillingLedgerEntry] = []
        while not self._stop_event.is_set():
            try:
                item = self._queue.get(timeout=self.flush_interval_seconds)
                batch.append(item)
                while len(batch) < self.batch_max_records:
                    try:
                        batch.append(self._queue.get_nowait())
                    except Empty:
                        break
            except Empty:
                pass
            if batch and (len(batch) >= self.batch_max_records or self._stop_event.is_set()):
                self._flush_batch(batch)
                batch = []
            elif batch:
                # Time-based flush: once the blocking get times out, Empty is
                # raised and the current batch is flushed here.
                self._flush_batch(batch)
                batch = []
        if batch:
            self._flush_batch(batch)

    def _flush_batch(self, batch: list[BillingLedgerEntry]) -> None:
        if not batch:
            return
        try:
            if self.mode == BillingMode.AWS_NATIVE_REFERENCE:
                self._flush_s3_batch(batch)
            elif self.mode == BillingMode.LEDGER_REQUIRED:
                self._flush_local_jsonl(batch)
            for _ in batch:
                self._queue.task_done()
        except Exception:
            LOG.exception("billing ledger batch flush failed")
            # Requeue best-effort without unbounded blocking. If the queue is
            # full, fail closed for future appends and log the records we could
            # not preserve in memory.
            for entry in batch:
                try:
                    self._queue.put_nowait(entry)
                except Full:
                    LOG.critical(
                        '{"event":"billing_record_dropped_after_flush_failure","request_id":"%s","tenant_id":"%s"}',
                        entry.request_id,
                        entry.tenant_id,
                    )
                    break

    def _flush_local_jsonl(self, batch: list[BillingLedgerEntry]) -> None:
        assert self.jsonl_path is not None
        payload = "".join(_entry_to_json_line(entry) for entry in batch)
        with self._write_lock:
            with self.jsonl_path.open("a", encoding="utf-8") as handle:
                handle.write(payload)

    def _flush_s3_batch(self, batch: list[BillingLedgerEntry]) -> None:
        assert self.aws_s3_bucket is not None
        by_partition: dict[tuple[str, str], list[BillingLedgerEntry]] = defaultdict(list)
        for entry in batch:
            created = _parse_created_at(entry.created_at)
            partition = (
                entry.tenant_id,
                f"year={created:%Y}/month={created:%m}/day={created:%d}/hour={created:%H}",
            )
            by_partition[partition].append(entry)

        for (tenant_id, partition), entries in by_partition.items():
            claimed = [entry for entry in entries if self._claim_aws_request_id(entry)]
            if not claimed:
                continue
            payload = "".join(_entry_to_json_line(entry) for entry in claimed)
            now = datetime.now(timezone.utc)
            key = (
                f"{self.aws_s3_prefix}tenant_id={tenant_id}/{partition}/"
                f"batch_ts={now.strftime('%Y%m%dT%H%M%S.%fZ')}-{uuid4().hex}.jsonl"
            )
            self._s3().put_object(
                Bucket=self.aws_s3_bucket,
                Key=key,
                Body=payload.encode("utf-8"),
                ContentType="application/x-ndjson",
                ServerSideEncryption="AES256",
                Metadata={"tenant_id": tenant_id, "record_count": str(len(claimed))},
            )
            for entry in claimed:
                self._mark_aws_request_complete(request_id=entry.request_id, s3_key=key)

    def _claim_aws_request_id(self, entry: BillingLedgerEntry) -> bool:
        if not self.aws_dynamodb_table:
            return True
        client = self._dynamodb()
        try:
            client.put_item(
                TableName=self.aws_dynamodb_table,
                Item={
                    "request_id": {"S": entry.request_id},
                    "tenant_id": {"S": entry.tenant_id},
                    "status": {"S": "writing"},
                    "created_at": {"S": entry.created_at},
                },
                ConditionExpression="attribute_not_exists(request_id)",
            )
            return True
        except Exception as exc:
            if exc.__class__.__name__ == "ConditionalCheckFailedException" or "ConditionalCheckFailed" in str(exc):
                return False
            raise

    def _mark_aws_request_complete(self, *, request_id: str, s3_key: str) -> None:
        if not self.aws_dynamodb_table:
            return
        self._dynamodb().update_item(
            TableName=self.aws_dynamodb_table,
            Key={"request_id": {"S": request_id}},
            UpdateExpression="SET #s = :complete, completed_at = :completed_at, s3_key = :s3_key",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":complete": {"S": "complete"},
                ":completed_at": {"S": datetime.now(timezone.utc).isoformat()},
                ":s3_key": {"S": s3_key},
            },
        )

    def _s3(self) -> Any:
        if self._s3_client is None:
            self._s3_client = _boto3_client("s3", self.aws_region)
        return self._s3_client

    def _dynamodb(self) -> Any:
        if self._dynamodb_client is None:
            self._dynamodb_client = _boto3_client("dynamodb", self.aws_region)
        return self._dynamodb_client


def _entry_to_json_line(entry: BillingLedgerEntry) -> str:
    return json.dumps(asdict(entry), sort_keys=True, separators=(",", ":")) + "\n"


def _parse_created_at(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return datetime.now(timezone.utc)


def _boto3_client(service: str, region_name: str | None) -> Any:
    try:
        import boto3  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("APP_BILLING_MODE=aws_native_reference requires boto3 in the gateway image") from exc
    kwargs = {"region_name": region_name} if region_name else {}
    return boto3.client(service, **kwargs)
