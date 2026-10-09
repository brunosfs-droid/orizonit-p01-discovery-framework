#!/usr/bin/env python3
"""Ephemeral, one-use review receipt for trusted R02 scan-intent previews.

This records ONLY an in-process acknowledgement; it NEVER grants permission to
run AUTH, FULL, scans, or credentials. It is not a durable approval ledger.
"""
import hashlib
import hmac
import re
import secrets
import threading
import time

import P01_Workspace_Coordinator as runtime
import P01_Workspace_Live_Intent as live

pg = runtime.pg
VERSION = "0.6.42"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
RECEIPT_ID = re.compile(r"[0-9a-f]{48}\Z")


def _digest(value):
    pg.require(type(value) is str and SHA256.fullmatch(value) is not None,
               "workspace_input_invalid")
    return value


def _receipt_id(value):
    pg.require(type(value) is str and RECEIPT_ID.fullmatch(value) is not None,
               "workspace_input_invalid")
    return hashlib.sha256(value.encode("ascii")).digest()


class ReviewReceipts:
    """Bounded, volatile acknowledgement book; all entries are non-executable."""
    def __init__(self, *, ttl_seconds=60, max_entries=64, clock=None):
        pg.require(type(ttl_seconds) is int and 1 <= ttl_seconds <= 300
                   and type(max_entries) is int and 1 <= max_entries <= 256,
                   "workspace_input_invalid")
        pg.require(clock is None or callable(clock), "workspace_input_invalid")
        self._ttl = ttl_seconds
        self._capacity = max_entries
        self._clock = clock or time.monotonic
        self._lock = threading.RLock()
        self._records = {}

    @staticmethod
    def _scope(operation, approved, scope_id, mode, expected_digest):
        pg.require(type(operation) is runtime.Operation and
                   isinstance(approved, live.ApprovedScopes),
                   "workspace_input_invalid")
        expected = _digest(expected_digest)
        operation.check()
        preview = live.preview(operation, approved, scope_id, mode,
                               ack_authorized_access=True)
        pg.require(hmac.compare_digest(preview["scope_digest_sha256"], expected),
                   "workspace_generation_stale")
        operation.check()
        # The lease identity is never printed or returned to the operator.
        return (operation.token.workspace_id, operation.token.generation,
                operation.token.lease_id, scope_id, mode, expected)

    def _purge(self, now):
        for key, (_, expiry) in list(self._records.items()):
            if now >= expiry:
                del self._records[key]

    def issue(self, operation, approved, scope_id, mode, expected_digest,
              *, ack_authorized_access=False):
        pg.require(type(ack_authorized_access) is bool and ack_authorized_access,
                   "workspace_input_invalid")
        scope = self._scope(operation, approved, scope_id, mode, expected_digest)
        with self._lock:
            now = self._clock()
            self._purge(now)
            pg.require(len(self._records) < self._capacity,
                       "workspace_jobs_full")
            receipt = secrets.token_hex(24)
            key = _receipt_id(receipt)
            self._records[key] = (scope, now + self._ttl)
        try:
            operation.check()
        except BaseException:
            with self._lock:
                self._records.pop(key, None)
            raise
        return dict(status="review_recorded_only", version=VERSION,
                    review_receipt=receipt, expires_in_seconds=self._ttl,
                    workspace_id=scope[0], generation=scope[1],
                    execution_authorized=False, authentication_performed=False,
                    network_activity_performed=False)

    def consume(self, operation, approved, scope_id, mode, expected_digest,
                review_receipt):
        """Consume proof of a historical review; no scan may be launched here."""
        key = _receipt_id(review_receipt)
        scope = self._scope(operation, approved, scope_id, mode, expected_digest)
        with self._lock:
            now = self._clock()
            self._purge(now)
            item = self._records.get(key)
            pg.require(item is not None and item[0] == scope,
                       "workspace_generation_stale")
            del self._records[key]
        operation.check()
        return dict(status="review_consumed_only", version=VERSION,
                    workspace_id=scope[0], generation=scope[1],
                    execution_authorized=False, authentication_performed=False,
                    network_activity_performed=False)

    def outstanding(self):
        with self._lock:
            self._purge(self._clock())
            return len(self._records)
