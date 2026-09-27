"""Firmware image shard-acceptance API.

Endpoints
---------
POST   /images                         create an acceptance task
PUT    /images/{id}/chunks?offset=N    upload one raw chunk (unordered OK)
GET    /images/{id}                    covered / missing half-open intervals
POST   /images/{id}/finalize           seal when complete and hash matches
GET    /images/{id}/content            download the assembled, sealed image
POST   /images/cleanup                 reap unsealed tasks idle for at least
                                       idle_seconds (at most limit per call)
GET    /images/{base_id}/delta/{target_id}
                                       block-wise delta between two sealed
                                       images for incremental distribution
POST   /images/{id}/attestations       submit an Ed25519 attestation for a
                                       sealed image (one per key_id)
GET    /images/{id}/trust              re-verify stored attestations against
                                       the currently configured public keys
GET    /images/{id}/merkle             Merkle commitment (total size, leaf
                                       count, root hash) of a sealed image
POST   /images/{id}/proof              shared Merkle multi-proof for 1..64
                                       chosen leaves of a sealed image
PUT    /channels/{name}                create/update a gray-release channel
                                       (stable + candidate + percent) guarded
                                       by an optimistic expected_revision
GET    /channels/{name}/resolve?device_id=...
                                       deterministic per-device resolution;
                                       trust is re-verified live and an
                                       untrusted candidate falls back to the
                                       trusted stable image
POST   /channels/{name}/receipts       accept a device installation receipt
                                       for the channel's current revision;
                                       the expected image is resolved and
                                       frozen in the same write transaction
GET    /channels/{name}/installation-audit
                                       per-device counts (success matched /
                                       success deviated / failed) over the
                                       receipts of the current revision
PUT    /channels/{name}/safety         arm/replace the canary risk
                                       circuit-breaker rule for the current
                                       revision (min sample, max bad %),
                                       guarded by an optimistic
                                       expected_revision; identical rules
                                       resubmitted at the same revision are
                                       idempotent, changed rules conflict
GET    /channels/{name}/safety         the armed rule with current sample /
                                       anomaly counts and the tripped latch
GET    /health                         liveness probe
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException, Path, Query, Request
from fastapi.responses import StreamingResponse
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field, field_validator, model_validator

from .db import (
    MAX_CHUNK,
    MAX_SIZE,
    MIN_CHUNK,
    MIN_SIZE,
    SHA256_LEN,
    connect,
    db_path,
    init_db,
    new_id,
    task_lock,
)

_HEX = set("0123456789abcdefABCDEF")

#: Merkle leaf size: a sealed image is committed to as a sequence of
#: 65536-byte leaves; the last leaf keeps its actual (possibly short) length.
MERKLE_LEAF_SIZE = 65536

#: A single multi-proof request may ask for at most this many leaves.
MERKLE_MAX_PROOF_INDICES = 64


@asynccontextmanager
async def lifespan(app: FastAPI):
    parent = os.path.dirname(db_path())
    if parent:
        os.makedirs(parent, exist_ok=True)
    init_db()
    yield


app = FastAPI(
    title="Firmware Image Shard Acceptance API",
    version="1.0.0",
    lifespan=lifespan,
)


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #


class CreateImageRequest(BaseModel):
    total_size: int = Field(..., description="Total image length in bytes")
    sha256: str = Field(..., description="Expected SHA-256, 64 hex characters")

    @field_validator("total_size")
    @classmethod
    def _check_size(cls, v: int) -> int:
        if not MIN_SIZE <= v <= MAX_SIZE:
            raise ValueError(f"total_size must be in [{MIN_SIZE}, {MAX_SIZE}]")
        return v

    @field_validator("sha256")
    @classmethod
    def _check_sha(cls, v: str) -> str:
        if len(v) != SHA256_LEN or any(c not in _HEX for c in v):
            raise ValueError("sha256 must be exactly 64 hexadecimal characters")
        return v.lower()


class AttestationRequest(BaseModel):
    key_id: str = Field(..., min_length=1, max_length=256)
    signature: str = Field(
        ..., min_length=1, description="Base64-encoded Ed25519 signature"
    )


class CleanupRequest(BaseModel):
    idle_seconds: int = Field(
        ..., ge=1, description="Reap unsealed tasks idle for at least this long"
    )
    limit: int = Field(..., ge=1, le=100, description="Max tasks reaped per call")


class ProofRequest(BaseModel):
    indices: list[int] = Field(
        ...,
        min_length=1,
        max_length=MERKLE_MAX_PROOF_INDICES,
        description="Distinct 0-based leaf indices to prove",
    )

    @field_validator("indices")
    @classmethod
    def _check_indices(cls, v: list[int]) -> list[int]:
        if any(i < 0 for i in v):
            raise ValueError("indices must be non-negative")
        if len(set(v)) != len(v):
            raise ValueError("indices must be distinct")
        return v


class ChannelRequest(BaseModel):
    stable_id: str = Field(..., min_length=1, max_length=64)
    candidate_id: str = Field(..., min_length=1, max_length=64)
    percent: int = Field(
        ..., ge=0, le=100, description="Canary percentage, integer 0..100"
    )
    expected_revision: int = Field(
        ...,
        ge=0,
        description="0 to create, else the channel's current revision",
    )


class ReceiptRequest(BaseModel):
    device_id: str = Field(..., min_length=1, max_length=256)
    revision: int = Field(
        ..., ge=1, description="The channel's current revision"
    )
    seq: int = Field(
        ...,
        ge=1,
        description="Per-device sequence number, monotonic across revisions",
    )
    status: Literal["success", "failed"]
    installed_id: str | None = Field(
        None,
        min_length=1,
        max_length=64,
        description="Image the device installed; required on success, "
        "must be null on failure",
    )

    @model_validator(mode="after")
    def _check_installed_id(self) -> "ReceiptRequest":
        if self.status == "success" and self.installed_id is None:
            raise ValueError("installed_id is required when status is success")
        if self.status == "failed" and self.installed_id is not None:
            raise ValueError("installed_id must be null when status is failed")
        return self


class SafetyRequest(BaseModel):
    expected_revision: int = Field(
        ...,
        ge=1,
        description="The channel's current revision; must match exactly",
    )
    min_reports: int = Field(
        ...,
        ge=1,
        le=1000,
        description="Minimum distinct-device sample before tripping",
    )
    max_bad_percent: int = Field(
        ...,
        ge=0,
        le=100,
        description="Strict upper bound on the anomaly percentage",
    )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

#: Incremental-delta block size. The target image is read on a fixed 64 KiB
#: grid, so every emitted block is 65536 bytes except possibly the last one.
#: Consumers can therefore rebuild the target by truncating/zero-padding the
#: base to the target length and overwriting each [offset, offset+len) range.
DELTA_BLOCK_SIZE = 65536

#: Fixed slice size for _ShardReader's SQLite reads.  No single query ever
#: materializes more than this many bytes of a stored blob, no matter how
#: large the merged row (a sealed image is one whole-image BLOB) or the
#: requested window is — the read buffer never grows with the image length.
#: 1 MiB also bounds the reader's look-ahead buffer, which amortizes the
#: overflow-page walk of sequential substr() reads over 16 delta blocks.
SHARD_READ_SLICE = 1024 * 1024

#: Minimum number of *distinct* key_ids with currently-valid signatures
#: required for an image to be reported as trusted.
TRUST_THRESHOLD = 2


def trusted_keys() -> dict[str, bytes]:
    """Parse ``TRUSTED_KEYS_JSON`` into ``{key_id: 32-byte Ed25519 pubkey}``.

    Read fresh from the environment on every call so that a key rotation
    (new env + container restart) is picked up exactly.  The service must
    start and serve with no/invalid configuration — any malformed input
    (bad JSON, non-object, undecodable or wrong-length keys) simply
    degrades to "no such key", i.e. everything judges as untrusted.
    """
    raw = os.environ.get("TRUSTED_KEYS_JSON")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    keys: dict[str, bytes] = {}
    for key_id, b64 in data.items():
        if not isinstance(key_id, str) or not isinstance(b64, str):
            continue
        try:
            pk = base64.b64decode(b64, validate=True)
        except ValueError:  # binascii.Error subclasses ValueError
            continue
        if len(pk) == 32:  # Ed25519 public keys are exactly 32 bytes
            keys[key_id] = pk
    return keys


def attestation_message(image_id: str, sha256: str, total_size: int) -> bytes:
    """Canonical ASCII string that attestations sign.

    Always built from the *server-side* image record, never from client
    input, so a signature is bound to the sealed image exactly as stored.
    """
    return f"FWIMGv1|{image_id}|{sha256}|{total_size}".encode("ascii")


def _signature_valid(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != 64:  # Ed25519 signatures are exactly 64 bytes
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except InvalidSignature:
        return False
    return True


def _valid_attestation_key_ids(
    conn: sqlite3.Connection, image_row: sqlite3.Row, keys: dict[str, bytes]
) -> list[str]:
    """key_ids whose stored signature verifies under the *current* keys.

    Trust is never cached: a signature only counts if its key_id is still
    configured AND the signature verifies under the currently configured
    public key, so rotating a key immediately invalidates old signatures.
    """
    attestations = conn.execute(
        "SELECT key_id, signature FROM attestations "
        "WHERE image_id = ? ORDER BY key_id",
        (image_row["id"],),
    ).fetchall()
    message = attestation_message(
        image_row["id"], image_row["sha256"], image_row["total_size"]
    )
    valid: list[str] = []
    for att in attestations:
        public_key = keys.get(att["key_id"])
        if public_key is None:
            continue  # key removed or rotated out: never counts
        try:
            signature = base64.b64decode(att["signature"], validate=True)
        except ValueError:
            continue
        if _signature_valid(public_key, message, signature):
            valid.append(att["key_id"])
    return valid


def _image_currently_trusted(
    conn: sqlite3.Connection, image_row: sqlite3.Row, keys: dict[str, bytes]
) -> bool:
    """Sealed AND at least TRUST_THRESHOLD currently-valid attestations."""
    if not image_row["finalized"]:
        return False
    return (
        len(_valid_attestation_key_ids(conn, image_row, keys)) >= TRUST_THRESHOLD
    )


def _get_image(conn: sqlite3.Connection, task_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT id, total_size, sha256, finalized, created_at "
        "FROM images WHERE id = ?",
        (task_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="image task not found")
    return row


def _runs(conn: sqlite3.Connection, task_id: str) -> list[sqlite3.Row]:
    return conn.execute(
        'SELECT "offset", end_offset, data FROM chunks '
        'WHERE image_id = ? ORDER BY "offset"',
        (task_id,),
    ).fetchall()


def _intervals(
    total_size: int, runs: list[sqlite3.Row]
) -> tuple[list[list[int]], list[list[int]], int]:
    """Return (covered, missing, bytes_received); half-open [lo, hi)."""
    covered: list[list[int]] = []
    missing: list[list[int]] = []
    cursor = 0
    received = 0
    for r in runs:
        lo, hi = r["offset"], r["end_offset"]
        if lo > cursor:
            missing.append([cursor, lo])
        covered.append([lo, hi])
        received += hi - lo
        cursor = hi
    if cursor < total_size:
        missing.append([cursor, total_size])
    return covered, missing, received


def _image_payload(conn: sqlite3.Connection, row: sqlite3.Row) -> dict:
    runs = _runs(conn, row["id"])
    covered, missing, received = _intervals(row["total_size"], runs)
    return {
        "id": row["id"],
        "total_size": row["total_size"],
        "sha256": row["sha256"],
        "finalized": bool(row["finalized"]),
        "created_at": row["created_at"],
        "bytes_received": received,
        "complete": not missing,
        "covered_intervals": covered,
        "missing_intervals": missing,
    }


class _ShardReader:
    """Sequential byte reader over a sealed image's stored shard rows.

    ``chunks`` may hold several disjoint/merged rows whose boundaries are
    unrelated to the 64 KiB delta grid — after adjacent uploads merge, a
    sealed image is in fact ONE row whose BLOB is the entire image.  This
    reader therefore never selects the ``data`` column itself: it first
    loads only the ``(offset, end_offset)`` interval map (a handful of
    small rows), then fetches bytes with bounded ``substr(data, ?, ?)``
    queries of at most ``SHARD_READ_SLICE`` bytes each, stitching slices
    across row boundaries into the requested window.  SQLite serves
    ``substr()`` on a blob column without materializing the whole column,
    so peak memory stays proportional to the slice/window size and never
    grows with the image length — two large images are never resident at
    once.  The current slice is kept as a small look-ahead buffer: the
    delta grid's 64 KiB windows are served from it, so sequential windows
    cost one SQLite fetch per slice instead of one per window.  Reads past
    the image end return ``b""``; the image is assumed sealed, i.e. its
    rows cover ``[0, total_size)`` without gaps.
    """

    def __init__(self, conn: sqlite3.Connection, image_id: str):
        self._conn = conn
        self._image_id = image_id
        self._runs = conn.execute(
            'SELECT "offset", end_offset FROM chunks '
            'WHERE image_id = ? ORDER BY "offset"',
            (image_id,),
        ).fetchall()
        self._pos = 0      # absolute byte position of the next unread byte
        self._idx = 0      # index of the run currently being consumed
        self._buf = b""    # unread tail of the last fetched slice
        self._buf_pos = 0  # absolute byte position of _buf[0]

    def _fill(self, run: sqlite3.Row) -> None:
        """Replace the buffer with the next fixed-size slice of ``run``."""
        local = self._pos - run["offset"]
        take = min(run["end_offset"] - self._pos, SHARD_READ_SLICE)
        # Bounded fetch: substr() is 1-based; the primary key guarantees at
        # most one matching row.  Only `take` bytes cross into Python.
        self._buf = self._conn.execute(
            'SELECT substr(data, ?, ?) FROM chunks '
            'WHERE image_id = ? AND "offset" = ?',
            (local + 1, take, self._image_id, run["offset"]),
        ).fetchone()[0] or b""
        self._buf_pos = self._pos

    def read(self, size: int) -> bytes:
        out = bytearray()
        while size > 0 and self._idx < len(self._runs):
            run = self._runs[self._idx]
            if self._pos >= run["end_offset"]:
                self._idx += 1  # run exhausted; move to the next one
                continue
            if self._buf_pos + len(self._buf) <= self._pos:
                self._fill(run)
                if not self._buf:
                    break  # defensive: sealed rows always hold the bytes
            start = self._pos - self._buf_pos
            take = min(size, len(self._buf) - start)
            out += self._buf[start : start + take]
            self._pos += take
            size -= take
        return bytes(out)


def _leaf_hash(block: bytes) -> bytes:
    """SHA-256 over the single-byte 0x00 domain prefix and the raw block."""
    return hashlib.sha256(b"\x00" + block).digest()


def _parent_hash(left: bytes, right: bytes) -> bytes:
    """SHA-256 over 0x01 and the two raw child hashes, left then right."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _merkle_scan(
    conn: sqlite3.Connection,
    image_id: str,
    total_size: int,
    keep: set[int] | None = None,
) -> tuple[list[list[bytes]], dict[int, bytes]]:
    """Build every level of a sealed image's Merkle tree in one bounded pass.

    Returns ``(levels, kept)``: ``levels[0]`` holds the leaf hashes in
    order, ``levels[-1]`` the single root hash; ``kept`` maps each leaf
    index in ``keep`` to its raw block bytes (at most
    ``MERKLE_MAX_PROOF_INDICES`` blocks of ``MERKLE_LEAF_SIZE`` bytes).

    The image is streamed through ``_ShardReader`` — never more than
    ``SHARD_READ_SLICE`` bytes of it are resident — so memory grows with
    the *leaf count* (32 bytes per hash) and the bounded number of kept
    blocks, never with the image length.
    """
    reader = _ShardReader(conn, image_id)
    kept: dict[int, bytes] = {}
    leaves: list[bytes] = []
    offset = 0
    index = 0
    while offset < total_size:
        length = min(MERKLE_LEAF_SIZE, total_size - offset)
        block = reader.read(length)
        if len(block) != length:
            # Defensive: a sealed image always covers its full length.
            raise RuntimeError("sealed image has unexpected gap")
        leaves.append(_leaf_hash(block))
        if keep is not None and index in keep:
            kept[index] = block
        offset += length
        index += 1

    levels = [leaves]
    while len(levels[-1]) > 1:
        nodes = levels[-1]
        if len(nodes) % 2 == 1:
            # Odd level: the last node is paired with a copy of itself.
            nodes = nodes + [nodes[-1]]
        levels.append(
            [_parent_hash(nodes[i], nodes[i + 1]) for i in range(0, len(nodes), 2)]
        )
    return levels, kept


def _merkle_proof_plan(
    levels: list[list[bytes]], indices: set[int]
) -> list[tuple[int, int]]:
    """(level, node_index) pairs of the shared multi-proof for ``indices``.

    A sibling hash is listed only when it cannot be recomputed from the
    selected leaves themselves; the duplicated tail node of an odd level is
    its own sibling and is therefore never listed.  Levels are processed
    leaf-up and each level's nodes are emitted in index order, so the plan
    comes out sorted by (level, index).
    """
    plan: list[tuple[int, int]] = []
    known = set(indices)
    for level, nodes in enumerate(levels[:-1]):
        n = len(nodes)
        needed: set[int] = set()
        for i in known:
            sibling = i ^ 1
            if sibling < n and sibling not in known:
                needed.add(sibling)
            # sibling >= n: odd-level tail paired with a copy of itself.
        plan.extend((level, s) for s in sorted(needed))
        known = {i // 2 for i in known}
    return plan


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/images", status_code=201)
def create_image(req: CreateImageRequest) -> dict:
    task_id = new_id()
    created_at = datetime.now(timezone.utc).isoformat()
    conn = connect()
    try:
        with conn:  # autocommit-style single statement transaction
            conn.execute(
                "INSERT INTO images "
                "(id, total_size, sha256, finalized, created_at, "
                " last_activity_at) "
                "VALUES (?, ?, ?, 0, ?, ?)",
                (task_id, req.total_size, req.sha256, created_at, created_at),
            )
    finally:
        conn.close()
    return {
        "id": task_id,
        "total_size": req.total_size,
        "sha256": req.sha256,
        "finalized": False,
        "created_at": created_at,
        "covered_intervals": [],
        "missing_intervals": [[0, req.total_size]],
    }


def _do_upload(task_id: str, offset: int, body: bytes) -> dict:
    """Locked, transactional validate-and-write. Runs in a worker thread."""
    length = len(body)

    # Same-task writers serialize in-process; BEGIN IMMEDIATE below gives the
    # same guarantee across processes. Everything between the first read and
    # the commit is therefore one atomic validate-and-write step.
    with task_lock(task_id):
        conn = connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = _get_image(conn, task_id)
                if row["finalized"]:
                    raise HTTPException(
                        status_code=409,
                        detail="image is already finalized; no further writes allowed",
                    )
                total_size = row["total_size"]
                end = offset + length
                if end > total_size:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            f"chunk [{offset}, {end}) exceeds image "
                            f"total_size {total_size}"
                        ),
                    )

                # All stored intervals that overlap OR are exactly adjacent
                # to this chunk. Strict inequalities on both sides would only
                # catch true overlap and leave touching runs unmerged.
                neighbors = conn.execute(
                    'SELECT "offset", end_offset, data FROM chunks '
                    'WHERE image_id = ? AND "offset" <= ? AND end_offset >= ? '
                    'ORDER BY "offset"',
                    (task_id, end, offset),
                ).fetchall()

                # 1) verify every overlapping byte matches
                for r in neighbors:
                    ov_lo = max(offset, r["offset"])
                    ov_hi = min(end, r["end_offset"])
                    if ov_hi > ov_lo:
                        incoming = body[ov_lo - offset : ov_hi - offset]
                        existing = r["data"][ov_lo - r["offset"] : ov_hi - r["offset"]]
                        if incoming != existing:
                            raise HTTPException(
                                status_code=409,
                                detail=(
                                    "overlapping bytes do not match at "
                                    f"[{ov_lo}, {ov_hi}); write rolled back"
                                ),
                            )

                # 2) build the union interval (existing runs are disjoint).
                # The merged range must span both the new chunk and every
                # neighbor — the new chunk may extend beyond them on either
                # side (e.g. prepend before the first stored run).
                lo = min(offset, neighbors[0]["offset"]) if neighbors else offset
                hi = max(end, neighbors[-1]["end_offset"]) if neighbors else end
                union = bytearray(hi - lo)
                union[offset - lo : end - lo] = body
                for r in neighbors:
                    union[r["offset"] - lo : r["end_offset"] - lo] = r["data"]

                # 3) replace absorbed runs with the single merged run
                conn.executemany(
                    'DELETE FROM chunks WHERE image_id = ? AND "offset" = ?',
                    [(task_id, r["offset"]) for r in neighbors],
                )
                conn.execute(
                    'INSERT INTO chunks (image_id, "offset", end_offset, data) '
                    "VALUES (?, ?, ?, ?)",
                    (task_id, lo, hi, bytes(union)),
                )
                # 4) refresh idle-reaping activity in the SAME transaction,
                # so a successful upload (duplicate included) and its
                # heartbeat commit atomically together.  Rejected writes
                # (finalized 409, out-of-range 400, byte conflict 409) raise
                # before this point and roll back without a refresh.
                conn.execute(
                    "UPDATE images SET last_activity_at = ? WHERE id = ?",
                    (datetime.now(timezone.utc).isoformat(), task_id),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise

            row = _get_image(conn, task_id)
            payload = _image_payload(conn, row)
            payload["merged_interval"] = [lo, hi]
            return payload
        finally:
            conn.close()


@app.put("/images/{task_id}/chunks")
async def upload_chunk(
    request: Request,
    task_id: str,
    offset: int = Query(..., ge=0, description="Byte offset of this chunk"),
) -> dict:
    """Accept one raw chunk.

    Out-of-order and duplicate uploads are allowed. Overlapping bytes must be
    byte-identical; on a mismatch the whole write is rolled back and 409 is
    returned. Any Content-Type is accepted; the body is treated as raw bytes.
    """
    body = await request.body()
    length = len(body)
    if length < MIN_CHUNK:
        raise HTTPException(
            status_code=400,
            detail=f"chunk must contain {MIN_CHUNK}..{MAX_CHUNK} bytes",
        )
    if length > MAX_CHUNK:
        raise HTTPException(
            status_code=413,
            detail=f"chunk exceeds maximum of {MAX_CHUNK} bytes",
        )
    return await run_in_threadpool(_do_upload, task_id, offset, body)


@app.get("/images/{task_id}")
def get_image(task_id: str) -> dict:
    conn = connect()
    try:
        return _image_payload(conn, _get_image(conn, task_id))
    finally:
        conn.close()


@app.post("/images/cleanup")
def cleanup_images(req: CleanupRequest) -> dict:
    """Reap unsealed tasks that have been idle past the cutoff.

    The cutoff is fixed once, at request start: ``now - idle_seconds``.
    Inside a single ``BEGIN IMMEDIATE`` write transaction the endpoint then
    selects at most ``limit`` *unsealed* tasks whose ``last_activity_at``
    is at or before the cutoff, ordered by (last_activity_at, id) ascending,
    and deletes them together with their chunk rows.  Sealed images are
    never selected, so their attestations and any channels referencing them
    are always preserved.

    Because selection and deletion share one write transaction, cleanup
    serializes against concurrent uploads and finalization strictly by
    transaction commit order: an upload/finalize that commits first is seen
    with its freshest state (a freshly sealed task is no longer eligible),
    and a task this transaction deletes is gone for every later request —
    subsequent chunk uploads, status reads and finalizations get 404.  Any
    error rolls the whole batch back; a cleanup call never deletes part of
    its selected set.
    """
    # Fixed at request start, before opening the transaction.
    cutoff = (
        datetime.now(timezone.utc) - timedelta(seconds=req.idle_seconds)
    ).isoformat()

    conn = connect()
    deleted_ids: list[str] = []
    released_bytes = 0
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            due = conn.execute(
                "SELECT id FROM images "
                "WHERE finalized = 0 AND last_activity_at <= ? "
                "ORDER BY last_activity_at ASC, id ASC "
                "LIMIT ?",
                (cutoff, req.limit),
            ).fetchall()
            deleted_ids = [r["id"] for r in due]

            if deleted_ids:
                placeholders = ",".join("?" * len(deleted_ids))
                # Stored runs are pairwise disjoint, so this is the exact
                # number of chunk bytes the reaped tasks held.
                released_bytes = conn.execute(
                    f'SELECT COALESCE(SUM(end_offset - "offset"), 0) AS n '
                    f"FROM chunks WHERE image_id IN ({placeholders})",
                    deleted_ids,
                ).fetchone()["n"]

                # Children first (chunks FK -> images).  The finalized=0
                # predicate is a second guard on top of the selection WHERE:
                # nothing under the IMMEDIATE lock can seal a row in between,
                # but delete a selected image only while it is still unsealed.
                conn.executemany(
                    "DELETE FROM chunks WHERE image_id = ?",
                    [(i,) for i in deleted_ids],
                )
                conn.executemany(
                    "DELETE FROM images WHERE id = ? AND finalized = 0",
                    [(i,) for i in deleted_ids],
                )

                # Defensive: under the IMMEDIATE write lock every selected row
                # must be gone.  Anything else means an unexpected partial
                # delete, which must abort (roll back) the whole call.
                leftover = conn.execute(
                    f"SELECT COUNT(*) AS n FROM images "
                    f"WHERE id IN ({placeholders})",
                    deleted_ids,
                ).fetchone()["n"]
                if leftover:
                    raise RuntimeError(
                        "cleanup aborted: fewer image rows deleted than selected"
                    )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    finally:
        conn.close()

    return {
        "cutoff": cutoff,
        "idle_seconds": req.idle_seconds,
        "limit": req.limit,
        "deleted": len(deleted_ids),
        "deleted_ids": deleted_ids,
        "released_bytes": released_bytes,
    }


@app.post("/images/{task_id}/finalize")
def finalize_image(task_id: str) -> dict:
    with task_lock(task_id):
        conn = connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = _get_image(conn, task_id)
                if row["finalized"]:
                    return {
                        "id": task_id,
                        "status": "finalized",
                        "already_finalized": True,
                        "sha256": row["sha256"],
                        "total_size": row["total_size"],
                    }

                runs = _runs(conn, task_id)
                covered, missing, received = _intervals(row["total_size"], runs)
                if missing:
                    raise HTTPException(
                        status_code=409,
                        detail={
                            "reason": "image has gaps",
                            "missing_intervals": missing,
                        },
                    )

                digest = hashlib.sha256()
                for r in runs:
                    digest.update(r["data"])
                actual = digest.hexdigest()
                if actual != row["sha256"]:
                    raise HTTPException(
                        status_code=409,
                        detail={
                            "reason": "sha256 mismatch",
                            "expected": row["sha256"],
                            "actual": actual,
                        },
                    )

                conn.execute(
                    "UPDATE images SET finalized = 1 WHERE id = ?", (task_id,)
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise

            return {
                "id": task_id,
                "status": "finalized",
                "already_finalized": False,
                "sha256": row["sha256"],
                "total_size": row["total_size"],
                "bytes_received": received,
            }
        finally:
            conn.close()


@app.get("/images/{task_id}/content")
def get_content(task_id: str):
    conn = connect()
    try:
        row = _get_image(conn, task_id)
        if not row["finalized"]:
            raise HTTPException(
                status_code=409,
                detail="image has not been finalized; content is unavailable",
            )
    finally:
        conn.close()

    def stream():
        # Dedicated connection for the iterator; Starlette may resume a sync
        # generator on another threadpool worker, hence check_same_thread=False.
        sconn = sqlite3.connect(db_path(), check_same_thread=False)
        sconn.row_factory = sqlite3.Row
        sconn.execute("PRAGMA busy_timeout = 10000")
        try:
            for r in sconn.execute(
                'SELECT data FROM chunks WHERE image_id = ? ORDER BY "offset"',
                (task_id,),
            ):
                yield r["data"]
        finally:
            sconn.close()

    headers = {
        "Content-Length": str(row["total_size"]),
        "X-SHA256": row["sha256"],
        "Content-Disposition": f'attachment; filename="{task_id}.bin"',
    }
    return StreamingResponse(
        stream(),
        media_type="application/octet-stream",
        headers=headers,
    )


@app.get("/images/{base_id}/delta/{target_id}")
def get_delta(base_id: str, target_id: str):
    """Stream the block-wise delta from one sealed image to another.

    The *target* image is walked on a fixed ``DELTA_BLOCK_SIZE`` (65536-byte)
    grid starting at offset 0. For each grid block the bytes at the same
    position in the *base* image are read in lockstep (base bytes beyond its
    end are treated as absent, so a target-grown block always differs). A
    block is emitted only when its content differs OR the base has no block
    of that length at that position — i.e. target growth, shrink and a short
    final block are all handled. Identical images yield an empty block list.

    Consumers restore the target by truncating **or** zero-padding the base
    to ``target_size`` first, then overwriting each emitted
    ``[offset, offset+len(block))`` range. Blocks are emitted in ascending
    offset order and never overlap.

    Both images must exist (404 otherwise) and both must be sealed
    (409 otherwise). The scan is fully streamed: neither image is assembled
    in memory and nothing is written — images and attestations are untouched.
    """
    conn = connect()
    try:
        base_row = _get_image(conn, base_id)
        target_row = _get_image(conn, target_id)
        if not base_row["finalized"] or not target_row["finalized"]:
            raise HTTPException(
                status_code=409,
                detail="both base and target images must be finalized",
            )
        base_size = base_row["total_size"]
        target_size = target_row["total_size"]
        base_sha = base_row["sha256"]
        target_sha = target_row["sha256"]
    finally:
        conn.close()

    def stream():
        # Dedicated connection for the iterator; a sync generator may resume
        # on another threadpool worker, hence check_same_thread=False.
        sconn = sqlite3.connect(db_path(), check_same_thread=False)
        sconn.row_factory = sqlite3.Row
        sconn.execute("PRAGMA busy_timeout = 10000")
        try:
            base_reader = _ShardReader(sconn, base_id)
            target_reader = _ShardReader(sconn, target_id)

            head = (
                "{"
                f'"base_id":{json.dumps(base_id)},'
                f'"base_sha256":{json.dumps(base_sha)},'
                f'"base_size":{base_size},'
                f'"target_id":{json.dumps(target_id)},'
                f'"target_sha256":{json.dumps(target_sha)},'
                f'"target_size":{target_size},'
                f'"block_size":{DELTA_BLOCK_SIZE},'
                '"blocks":['
            )
            first = True
            offset = 0
            while offset < target_size:
                length = min(DELTA_BLOCK_SIZE, target_size - offset)
                target_block = target_reader.read(length)
                base_block = base_reader.read(length)
                if len(target_block) != length:
                    # Defensive: a sealed image always covers its full length.
                    raise RuntimeError("sealed target image has unexpected gap")
                if base_block != target_block:
                    if not first:
                        head += ","
                    head += (
                        "{"
                        f'"offset":{offset},'
                        f'"length":{length},'
                        f'"data":{json.dumps(base64.b64encode(target_block).decode("ascii"))}'
                        "}"
                    )
                    first = False
                # Hand the accumulated prefix (plus any new block) to the
                # wire and reset, so the whole block list is never buffered.
                yield head
                head = ""
                offset += length
            yield head + "]}"
        finally:
            sconn.close()

    return StreamingResponse(stream(), media_type="application/json")


@app.get("/images/{task_id}/merkle")
def get_merkle(task_id: str) -> dict:
    """Merkle commitment of a sealed image: total size, leaf count, root.

    The image is committed to as a binary Merkle tree over 65536-byte
    leaves (the last leaf keeps its actual length): leaf hashes are
    ``SHA-256(0x00 || block)``, parent hashes ``SHA-256(0x01 || left ||
    right)`` over the raw 32-byte child hashes, odd levels duplicate their
    last node before pairing, and a single-leaf tree's root is the leaf
    hash itself.  The tree is rebuilt from the stored bytes on every
    request with a bounded read buffer, so every sealed image — including
    ones sealed before this endpoint existed — answers without migration.
    """
    conn = connect()
    try:
        row = _get_image(conn, task_id)
        if not row["finalized"]:
            raise HTTPException(
                status_code=409,
                detail="image has not been finalized; merkle root is unavailable",
            )
        levels, _ = _merkle_scan(conn, task_id, row["total_size"])
    finally:
        conn.close()
    return {
        "id": task_id,
        "total_size": row["total_size"],
        "leaf_size": MERKLE_LEAF_SIZE,
        "leaf_count": len(levels[0]),
        "root": levels[-1][0].hex(),
    }


@app.post("/images/{task_id}/proof")
def post_merkle_proof(task_id: str, req: ProofRequest) -> dict:
    """Shared Merkle multi-proof for 1..64 distinct leaf indices.

    Returns the selected leaves (index-ordered, Base64 block bytes) plus
    the minimal shared proof: (level, index, hash) triples — leaf level is
    0 — sorted by level then index, listing only the sibling hashes that
    cannot be recomputed from the selected leaves.  Duplicated tail nodes
    of odd levels are never listed.  All hashes are hex-encoded.  Clients
    verify by recomputing the root from the leaves and the proof and
    comparing it against a previously stored root (see README).
    """
    conn = connect()
    try:
        row = _get_image(conn, task_id)
        if not row["finalized"]:
            raise HTTPException(
                status_code=409,
                detail="image has not been finalized; proofs are unavailable",
            )
        total_size = row["total_size"]
        leaf_count = -(-total_size // MERKLE_LEAF_SIZE)  # ceil, size >= 1
        if max(req.indices) >= leaf_count:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"leaf index out of range: this image has {leaf_count} "
                    f"leaves (valid indices 0..{leaf_count - 1})"
                ),
            )
        wanted = set(req.indices)
        levels, kept = _merkle_scan(conn, task_id, total_size, keep=wanted)
    finally:
        conn.close()

    proof = [
        {"level": level, "index": index, "hash": levels[level][index].hex()}
        for level, index in _merkle_proof_plan(levels, wanted)
    ]
    leaves = [
        {
            "index": i,
            "length": len(kept[i]),
            "data": base64.b64encode(kept[i]).decode("ascii"),
        }
        for i in sorted(kept)
    ]
    return {
        "id": task_id,
        "total_size": total_size,
        "leaf_size": MERKLE_LEAF_SIZE,
        "leaf_count": leaf_count,
        "root": levels[-1][0].hex(),
        "leaves": leaves,
        "proof": proof,
    }


@app.post("/images/{task_id}/attestations")
def post_attestation(task_id: str, req: AttestationRequest) -> dict:
    """Record an Ed25519 attestation for a *sealed* image.

    The signed message is the ASCII string ``FWIMGv1|{id}|{sha256}|
    {total_size}`` rebuilt from the server-side record.  Unknown key_ids,
    malformed base64 and invalid signatures are rejected with 400 and
    nothing is persisted.  Each (image, key_id) pair stores exactly one
    signature: resubmitting the identical signature is an idempotent no-op,
    a new valid signature replaces the old one.
    """
    conn = connect()
    try:
        row = _get_image(conn, task_id)
        if not row["finalized"]:
            raise HTTPException(
                status_code=409,
                detail="image is not finalized; only sealed images can be attested",
            )
        message = attestation_message(row["id"], row["sha256"], row["total_size"])
    finally:
        conn.close()

    # Everything below is validated *before* any write touches the DB.
    public_key = trusted_keys().get(req.key_id)
    if public_key is None:
        raise HTTPException(status_code=400, detail="unknown key_id")
    try:
        signature = base64.b64decode(req.signature, validate=True)
    except ValueError:
        raise HTTPException(
            status_code=400, detail="signature is not valid base64"
        )
    if not _signature_valid(public_key, message, signature):
        raise HTTPException(status_code=400, detail="invalid signature")

    created_at = datetime.now(timezone.utc).isoformat()
    with task_lock(task_id):
        conn = connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                existing = conn.execute(
                    "SELECT signature FROM attestations "
                    "WHERE image_id = ? AND key_id = ?",
                    (task_id, req.key_id),
                ).fetchone()
                if existing is not None and existing["signature"] == req.signature:
                    status = "unchanged"  # idempotent resubmission
                else:
                    conn.execute(
                        "INSERT INTO attestations "
                        "(image_id, key_id, signature, created_at) "
                        "VALUES (?, ?, ?, ?) "
                        "ON CONFLICT (image_id, key_id) DO UPDATE SET "
                        "signature = excluded.signature, "
                        "created_at = excluded.created_at",
                        (task_id, req.key_id, req.signature, created_at),
                    )
                    status = "recorded" if existing is None else "replaced"
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        finally:
            conn.close()
    return {"id": task_id, "key_id": req.key_id, "status": status}


@app.get("/images/{task_id}/trust")
def get_trust(task_id: str) -> dict:
    """Re-verify every stored attestation against the *current* public keys.

    Trust is never cached: a signature only counts if its key_id is still
    configured AND the signature verifies under the currently configured
    public key, so rotating a key immediately invalidates old signatures.
    """
    conn = connect()
    try:
        row = _get_image(conn, task_id)
        stored = conn.execute(
            "SELECT COUNT(*) AS n FROM attestations WHERE image_id = ?",
            (task_id,),
        ).fetchone()["n"]
        valid = _valid_attestation_key_ids(conn, row, trusted_keys())
    finally:
        conn.close()
    return {
        "id": task_id,
        "finalized": bool(row["finalized"]),
        "trusted": len(valid) >= TRUST_THRESHOLD,
        "valid_key_ids": valid,
        "threshold": TRUST_THRESHOLD,
        "attestations_stored": stored,
    }


# --------------------------------------------------------------------------- #
# Gray-release channels
# --------------------------------------------------------------------------- #

#: Resolution bucket space: the per-device hash is reduced modulo this many
#: buckets and ``percent`` maps to exactly ``percent * 100`` of them, so one
#: percentage point is 100 buckets and the endpoints are percent=0 (never
#: candidate) and percent=100 (always candidate, trust permitting).
CHANNEL_BUCKET_COUNT = 10000


def _channel_row(conn: sqlite3.Connection, name: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT name, stable_id, candidate_id, percent, revision, updated_at "
        "FROM channels WHERE name = ?",
        (name,),
    ).fetchone()


def _safety_row(conn: sqlite3.Connection, name: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT channel, rule_revision, min_reports, max_bad_percent, "
        "tripped, created_at, updated_at "
        "FROM channel_safety WHERE channel = ?",
        (name,),
    ).fetchone()


def _safety_candidate_counts(
    conn: sqlite3.Connection, channel: sqlite3.Row
) -> tuple[int, int]:
    """(sample, anomalies) over the *candidate* canary of the current revision.

    The sample is the current-revision receipts whose frozen ``expected_id``
    is the channel's candidate image — i.e. devices that were *supposed* to
    install the candidate at acceptance time (a receipt frozen to the stable
    image via an untrusted-candidate fallback never enters the canary
    sample).  An anomaly is a failed install, or a reported success whose
    ``installed_id`` differs from the frozen ``expected_id``.  Each device
    counts once through its single latest receipt.  One statement, one
    snapshot — used both by the safety endpoint and by the in-transaction
    latch evaluation after a new receipt lands.
    """
    row = conn.execute(
        "SELECT "
        "COALESCE(SUM(CASE WHEN r.expected_id = c.candidate_id "
        "             THEN 1 ELSE 0 END), 0) AS sample_n, "
        "COALESCE(SUM(CASE WHEN r.expected_id = c.candidate_id AND "
        "    (r.status = 'failed' OR "
        "     (r.status = 'success' AND r.installed_id <> r.expected_id)) "
        "             THEN 1 ELSE 0 END), 0) AS bad_n "
        "FROM channels c LEFT JOIN receipts r "
        "  ON r.channel = c.name AND r.revision = c.revision "
        "WHERE c.name = ? "
        "GROUP BY c.name, c.revision",
        (channel["name"],),
    ).fetchone()
    if row is None:  # channel vanished mid-transaction (defensive)
        return 0, 0
    return row["sample_n"], row["bad_n"]


def _safety_tripped(
    channel: sqlite3.Row, safety: sqlite3.Row | None
) -> bool:
    """Whether an armed rule latched at the *current* revision says tripped."""
    return (
        safety is not None
        and safety["rule_revision"] == channel["revision"]
        and bool(safety["tripped"])
    )


def _safety_payload(
    channel: sqlite3.Row, safety: sqlite3.Row, sample: int, anomalies: int
) -> dict:
    tripped = bool(safety["tripped"])
    return {
        "name": channel["name"],
        "revision": channel["revision"],
        "rule_revision": safety["rule_revision"],
        "min_reports": safety["min_reports"],
        "max_bad_percent": safety["max_bad_percent"],
        "reports": sample,
        "anomalies": anomalies,
        "tripped": tripped,
        "status": "tripped" if tripped else "monitoring",
    }


def _channel_image(conn: sqlite3.Connection, role: str, image_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT id, total_size, sha256, finalized, created_at "
        "FROM images WHERE id = ?",
        (image_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=f"{role} image not found")
    return row


def _resolve_bucket(name: str, device_id: str) -> int:
    """Deterministic bucket in [0, 10000) for one (channel, device) pair.

    SHA-256 over the channel name's UTF-8 bytes, a single 0x00 separator
    and the device_id's UTF-8 bytes; the first 8 digest bytes are read as
    a big-endian unsigned integer and reduced modulo 10000.  This is a pure
    function of the stored policy inputs, so with an unchanged policy the
    same device lands in the same bucket across processes and rebuilds.
    """
    digest = hashlib.sha256(
        name.encode("utf-8") + b"\x00" + device_id.encode("utf-8")
    ).digest()
    return int.from_bytes(digest[:8], "big") % CHANNEL_BUCKET_COUNT


def _resolve_for_device(
    conn: sqlite3.Connection,
    channel: sqlite3.Row,
    device_id: str,
    breaker_tripped: bool = False,
) -> tuple[str, str, int]:
    """Resolve one device under the stored policy: (image_id, reason, bucket).

    Trust is re-verified against the *current* public keys on every call:
    an untrusted candidate falls back to the trusted stable image, and an
    untrusted stable image aborts the resolution with 409 — a device is
    never directed at an untrusted image.  Used both by the read-only
    resolve endpoint and by the receipt endpoint, which freezes the
    returned image id as the receipt's ``expected_id``.

    When ``breaker_tripped`` is set (the channel's armed safety rule has
    latched at this revision), every bucket that would have selected the
    candidate is instead directed at the trusted stable image with reason
    ``risk_circuit_breaker_fallback`` — the percentage is unchanged, so
    the decision flips back automatically once a new revision (with a new
    rule) is armed.  The stable image remains the trust floor regardless:
    if it has lost trust the resolution still aborts with 409.
    """
    images = {
        role: _channel_image(conn, role, image_id)
        for role, image_id in (
            ("stable", channel["stable_id"]),
            ("candidate", channel["candidate_id"]),
        )
    }
    keys = trusted_keys()
    trusted = {
        role: _image_currently_trusted(conn, row, keys)
        for role, row in images.items()
    }
    if not trusted["stable"]:
        raise HTTPException(
            status_code=409,
            detail="stable image is not currently trusted; channel cannot resolve",
        )

    bucket = _resolve_bucket(channel["name"], device_id)
    if bucket < channel["percent"] * 100:  # 100 buckets per percentage point
        if breaker_tripped:
            # Latched canary risk: steer the canary bucket to the trusted
            # stable image and mark the risk rollback.
            return channel["stable_id"], "risk_circuit_breaker_fallback", bucket
        if trusted["candidate"]:
            return channel["candidate_id"], "candidate", bucket
        return channel["stable_id"], "candidate_untrusted_fallback", bucket
    return channel["stable_id"], "stable", bucket


@app.put("/channels/{name}")
def put_channel(
    req: ChannelRequest,
    name: str = Path(..., min_length=1, max_length=256),
) -> dict:
    """Create or update a gray-release channel.

    ``expected_revision`` is an optimistic concurrency token: 0 creates the
    channel (revision becomes 1), any later update must present the current
    revision and bumps it by one — a mismatch returns 409 and nothing is
    written.  Both images must exist (404 otherwise) and must be sealed and
    *currently* trusted (409 otherwise): the check re-verifies stored
    attestations against the public keys configured right now, exactly like
    ``GET /images/{id}/trust``.  The whole validate-and-write runs in one
    BEGIN IMMEDIATE transaction, so concurrent updates cannot interleave.
    Any safety rule armed at the previous revision (including a latched
    circuit breaker) is deleted by the same transaction — the new revision
    starts unarmed and must be re-armed via ``PUT .../safety``.
    """
    with task_lock(f"channel:{name}"):
        conn = connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                existing = _channel_row(conn, name)
                current = existing["revision"] if existing is not None else 0
                if req.expected_revision != current:
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            f"expected_revision {req.expected_revision} does "
                            f"not match current revision {current}"
                        ),
                    )

                images = {
                    role: _channel_image(conn, role, image_id)
                    for role, image_id in (
                        ("stable", req.stable_id),
                        ("candidate", req.candidate_id),
                    )
                }
                keys = trusted_keys()
                for role, row in images.items():
                    if not row["finalized"]:
                        raise HTTPException(
                            status_code=409,
                            detail=f"{role} image is not finalized",
                        )
                    if not _image_currently_trusted(conn, row, keys):
                        raise HTTPException(
                            status_code=409,
                            detail=f"{role} image is not currently trusted",
                        )

                new_revision = current + 1
                updated_at = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    "INSERT INTO channels "
                    "(name, stable_id, candidate_id, percent, revision, "
                    " updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT (name) DO UPDATE SET "
                    "stable_id = excluded.stable_id, "
                    "candidate_id = excluded.candidate_id, "
                    "percent = excluded.percent, "
                    "revision = excluded.revision, "
                    "updated_at = excluded.updated_at",
                    (
                        name,
                        req.stable_id,
                        req.candidate_id,
                        req.percent,
                        new_revision,
                        updated_at,
                    ),
                )
                # The accepted update starts a new revision: the armed
                # safety rule (and its sticky latch) belongs to the old
                # revision and is invalidated.  The new revision starts
                # unarmed; recovery is a channel update followed by a
                # fresh PUT .../safety at the new revision.
                conn.execute(
                    "DELETE FROM channel_safety WHERE channel = ?", (name,)
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        finally:
            conn.close()
    return {
        "name": name,
        "stable_id": req.stable_id,
        "candidate_id": req.candidate_id,
        "percent": req.percent,
        "revision": new_revision,
        "updated_at": updated_at,
    }


@app.get("/channels/{name}/resolve")
def resolve_channel(
    name: str = Path(..., min_length=1, max_length=256),
    device_id: str = Query(..., min_length=1, max_length=256),
) -> dict:
    """Resolve one device to the stable or candidate image of a channel.

    The device lands in bucket ``SHA-256(name || 0x00 || device_id)[:8]``
    (big-endian) mod 10000; a bucket below ``percent * 100`` selects the
    candidate, anything else the stable image.  Trust is re-verified against
    the *current* public keys on every call: an untrusted candidate falls
    back to the trusted stable image, and an untrusted stable image fails
    the whole resolution with 409.  If the channel's armed safety rule has
    latched at this revision (risk circuit breaker tripped), every
    candidate bucket is redirected to the trusted stable image with reason
    ``risk_circuit_breaker_fallback``; an untrusted stable image still fails
    with 409.  The percentage and revision are never rewritten by tripping;
    recovery is a channel update (new revision, rule invalidated).
    Read-only; nothing is persisted.
    """
    conn = connect()
    try:
        channel = _channel_row(conn, name)
        if channel is None:
            raise HTTPException(status_code=404, detail="channel not found")
        tripped = _safety_tripped(channel, _safety_row(conn, name))
        image_id, reason, bucket = _resolve_for_device(
            conn, channel, device_id, breaker_tripped=tripped
        )
    finally:
        conn.close()
    return {
        "name": name,
        "device_id": device_id,
        "image_id": image_id,
        "revision": channel["revision"],
        "reason": reason,
        "bucket": bucket,
        "percent": channel["percent"],
    }


# --------------------------------------------------------------------------- #
# Canary risk circuit breaker
# --------------------------------------------------------------------------- #


@app.put("/channels/{name}/safety")
def put_channel_safety(
    req: SafetyRequest,
    name: str = Path(..., min_length=1, max_length=256),
) -> dict:
    """Arm (or replace) the canary risk circuit-breaker rule for a channel.

    ``expected_revision`` must equal the channel's *current* revision: a
    mismatch returns 409 and nothing is written.  Each revision starts
    unarmed — an accepted ``PUT /channels/{name}`` bumps the revision and
    deletes the rule armed at its predecessor, so the rule must be re-armed
    after every channel update.  Resubmitting the *identical* rule
    (``min_reports`` and ``max_bad_percent`` unchanged) at the same revision
    is an idempotent no-op; submitting different rule values at the same
    revision is a 409 conflict — to change the rule, bump the channel
    revision first.  The tripped latch is never created armed and an armed
    latch cannot be reset by this endpoint; recovery likewise goes through a
    channel update and re-armament.
    """
    now = datetime.now(timezone.utc).isoformat()
    with task_lock(f"channel:{name}"):
        conn = connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                channel = _channel_row(conn, name)
                if channel is None:
                    raise HTTPException(
                        status_code=404, detail="channel not found"
                    )
                if req.expected_revision != channel["revision"]:
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            f"expected_revision {req.expected_revision} does "
                            f"not match current revision "
                            f"{channel['revision']}"
                        ),
                    )

                safety = _safety_row(conn, name)
                if safety is not None:
                    if safety["rule_revision"] != channel["revision"]:
                        # Defensive: a stale row for a superseded revision
                        # must not survive — channel updates delete it in the
                        # same transaction as the revision bump.
                        conn.execute(
                            "DELETE FROM channel_safety WHERE channel = ?",
                            (name,),
                        )
                        safety = None
                    elif (
                        safety["min_reports"] != req.min_reports
                        or safety["max_bad_percent"] != req.max_bad_percent
                    ):
                        raise HTTPException(
                            status_code=409,
                            detail=(
                                "a different safety rule is already armed at "
                                f"revision {channel['revision']}; update the "
                                "channel to a new revision before changing "
                                "min_reports or max_bad_percent"
                            ),
                        )

                if safety is None:
                    conn.execute(
                        "INSERT INTO channel_safety "
                        "(channel, rule_revision, min_reports, "
                        " max_bad_percent, tripped, created_at, updated_at) "
                        "VALUES (?, ?, ?, ?, 0, ?, ?)",
                        (
                            name,
                            channel["revision"],
                            req.min_reports,
                            req.max_bad_percent,
                            now,
                            now,
                        ),
                    )
                    stored = "armed"
                else:
                    stored = "unchanged"
                conn.commit()
                safety = _safety_row(conn, name)
                sample, anomalies = _safety_candidate_counts(conn, channel)
            except Exception:
                conn.rollback()
                raise
        finally:
            conn.close()
    payload = _safety_payload(channel, safety, sample, anomalies)
    payload["stored"] = stored
    return payload


@app.get("/channels/{name}/safety")
def get_channel_safety(
    name: str = Path(..., min_length=1, max_length=256),
) -> dict:
    """Return the armed rule, current sample/anomaly counts and latch state.

    ``reports`` is the number of devices whose current-revision receipt
    froze the candidate image as the expected one (the canary sample);
    ``anomalies`` counts the failed installs and successful-but-deviated
    installs among them.  ``status`` is ``monitoring`` until, once the
    sample reaches ``min_reports`` and ``anomalies * 100`` strictly exceeds
    ``reports * max_bad_percent``, the breaker latches to ``tripped`` —
    sticky for the rest of the revision.  404 if the channel does not
    exist or the current revision has no armed rule (an earlier revision's
    rule is gone after a channel update).  Read-only.
    """
    conn = connect()
    try:
        channel = _channel_row(conn, name)
        if channel is None:
            raise HTTPException(status_code=404, detail="channel not found")
        safety = _safety_row(conn, name)
        if safety is None or safety["rule_revision"] != channel["revision"]:
            raise HTTPException(
                status_code=404,
                detail="no safety rule armed at the channel's current revision",
            )
        sample, anomalies = _safety_candidate_counts(conn, channel)
    finally:
        conn.close()
    return _safety_payload(channel, safety, sample, anomalies)


# --------------------------------------------------------------------------- #
# Installation receipts & audit
# --------------------------------------------------------------------------- #


@app.post("/channels/{name}/receipts")
def post_receipt(
    req: ReceiptRequest,
    name: str = Path(..., min_length=1, max_length=256),
) -> dict:
    """Record one device's installation receipt for a channel.

    Only the channel's *current* revision is accepted: a report naming any
    other revision (in particular a delayed report for a superseded
    revision) is rejected with 409 and cannot overwrite newer data.  For a
    report that will be stored, the image the device *should* have
    installed is computed by the channel's normal resolution rules —
    per-device bucket, live trust re-verification, candidate-untrusted
    fallback — inside the same BEGIN IMMEDIATE write transaction that
    persists the receipt, and is frozen as ``expected_id``; an untrusted
    stable image rejects the receipt with 409 and nothing is stored.

    Each (channel, device) pair keeps only the receipt with the largest
    ``seq``; ``seq`` is monotonic across channel revisions.  A smaller
    ``seq`` than the stored one, or the same ``seq`` with different
    content (revision / status / installed_id), is a 409 conflict;
    resubmitting the identical receipt is an idempotent no-op that returns
    the stored row (its frozen ``expected_id`` included) unchanged.
    Channel updates and receipts serialize on the same per-channel lock
    and SQLite write transactions, so commit order alone arbitrates races.

    When an armed safety rule exists at the current revision, the expected
    image is resolved under the breaker's current latch state: once
    tripped, candidate-bucket devices freeze the stable image (risk
    rollback) as their ``expected_id``.  After a new receipt lands — but
    never for an idempotent replay — the canary sample and anomaly counts
    are recomputed in the SAME write transaction; once the sample reaches
    ``min_reports`` and ``anomalies * 100`` exceeds
    ``sample * max_bad_percent`` the breaker latches to tripped.  The
    latch is sticky: later receipt overwrites (even with better results)
    never clear it.
    """
    with task_lock(f"channel:{name}"):
        conn = connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                channel = _channel_row(conn, name)
                if channel is None:
                    raise HTTPException(
                        status_code=404, detail="channel not found"
                    )
                if req.revision != channel["revision"]:
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            f"revision {req.revision} does not match the "
                            f"channel's current revision "
                            f"{channel['revision']}"
                        ),
                    )

                safety = _safety_row(conn, name)
                if (
                    safety is not None
                    and safety["rule_revision"] != channel["revision"]
                ):
                    safety = None  # defensive: stale row of an old revision
                tripped_before = _safety_tripped(channel, safety)

                existing = conn.execute(
                    "SELECT seq, revision, status, installed_id, expected_id "
                    "FROM receipts WHERE channel = ? AND device_id = ?",
                    (name, req.device_id),
                ).fetchone()

                if existing is not None and req.seq <= existing["seq"]:
                    if req.seq < existing["seq"]:
                        raise HTTPException(
                            status_code=409,
                            detail=(
                                f"seq {req.seq} is below this device's "
                                f"stored seq {existing['seq']}"
                            ),
                        )
                    same = (
                        req.revision == existing["revision"]
                        and req.status == existing["status"]
                        and req.installed_id == existing["installed_id"]
                    )
                    if not same:
                        raise HTTPException(
                            status_code=409,
                            detail=(
                                f"seq {req.seq} was already reported with "
                                "different content"
                            ),
                        )
                    # Idempotent resubmission: the stored row — including
                    # its frozen expected_id — is returned as-is.
                    stored = "unchanged"
                    expected_id = existing["expected_id"]
                else:
                    # New device or a larger seq: resolve the expected image
                    # now, inside this write transaction, and freeze it.  A
                    # latched circuit breaker redirects candidate buckets to
                    # the stable image at this point, so new receipts after
                    # tripping freeze the rollback image.
                    expected_id, _, _ = _resolve_for_device(
                        conn,
                        channel,
                        req.device_id,
                        breaker_tripped=tripped_before,
                    )
                    conn.execute(
                        "INSERT INTO receipts "
                        "(channel, device_id, seq, revision, status, "
                        " installed_id, expected_id, created_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                        "ON CONFLICT (channel, device_id) DO UPDATE SET "
                        "seq = excluded.seq, "
                        "revision = excluded.revision, "
                        "status = excluded.status, "
                        "installed_id = excluded.installed_id, "
                        "expected_id = excluded.expected_id, "
                        "created_at = excluded.created_at",
                        (
                            name,
                            req.device_id,
                            req.seq,
                            req.revision,
                            req.status,
                            req.installed_id,
                            expected_id,
                            datetime.now(timezone.utc).isoformat(),
                        ),
                    )
                    stored = "recorded" if existing is None else "replaced"

                    # Evaluate the risk breaker in the SAME write transaction
                    # in which the receipt lands.  Only receipts whose frozen
                    # expected image is the candidate form the canary sample;
                    # a failed install or a success whose installed image
                    # differs from the frozen one is an anomaly.  The latch
                    # is one-way: once set it is never cleared, regardless of
                    # how later overwrites move the percentages.
                    if safety is not None and not tripped_before:
                        sample_n, bad_n = _safety_candidate_counts(
                            conn, channel
                        )
                        if sample_n >= safety["min_reports"] and bad_n * 100 > (
                            sample_n * safety["max_bad_percent"]
                        ):
                            conn.execute(
                                "UPDATE channel_safety SET tripped = 1, "
                                "updated_at = ? WHERE channel = ?",
                                (
                                    datetime.now(timezone.utc).isoformat(),
                                    name,
                                ),
                            )
                conn.commit()
                # Re-read the latch after commit so the response reflects a
                # trip triggered by this very transaction.
                safety_after = _safety_row(conn, name)
                tripped_after = _safety_tripped(channel, safety_after)
            except Exception:
                conn.rollback()
                raise
        finally:
            conn.close()
    return {
        "name": name,
        "device_id": req.device_id,
        "revision": req.revision,
        "seq": req.seq,
        "status": req.status,
        "installed_id": req.installed_id,
        "expected_id": expected_id,
        "matched": req.status == "success" and req.installed_id == expected_id,
        "stored": stored,
        "circuit_breaker_tripped": tripped_after,
    }


@app.get("/channels/{name}/installation-audit")
def installation_audit(
    name: str = Path(..., min_length=1, max_length=256),
) -> dict:
    """Per-device installation counts over the channel's *current* revision.

    Every stored receipt whose ``revision`` equals the channel's current
    revision falls into exactly one bucket: ``success_matched`` (reported
    success and ``installed_id`` equals the frozen ``expected_id``),
    ``success_deviated`` (reported success but installed something else)
    or ``failed``.  Receipts of older revisions are not counted.  The
    frozen ``expected_id`` is read back as saved — later policy or public
    key changes never rewrite it — so the audit reflects what was decided
    at acceptance time.  Read-only; one SQL statement, one snapshot.
    """
    conn = connect()
    try:
        row = conn.execute(
            "SELECT c.revision AS revision, "
            "COALESCE(SUM(CASE WHEN r.status = 'success' "
            "  AND r.installed_id = r.expected_id THEN 1 ELSE 0 END), 0) "
            "  AS matched, "
            "COALESCE(SUM(CASE WHEN r.status = 'success' "
            "  AND r.installed_id <> r.expected_id THEN 1 ELSE 0 END), 0) "
            "  AS deviated, "
            "COALESCE(SUM(CASE WHEN r.status = 'failed' THEN 1 ELSE 0 END), 0) "
            "  AS failed "
            "FROM channels c LEFT JOIN receipts r "
            "  ON r.channel = c.name AND r.revision = c.revision "
            "WHERE c.name = ? "
            "GROUP BY c.name, c.revision",
            (name,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="channel not found")
    return {
        "name": name,
        "revision": row["revision"],
        "success_matched": row["matched"],
        "success_deviated": row["deviated"],
        "failed": row["failed"],
    }
