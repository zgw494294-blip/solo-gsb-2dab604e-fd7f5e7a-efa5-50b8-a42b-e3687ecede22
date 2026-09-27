"""SQLite persistence for the firmware image acceptance service.

Storage model
-------------
``images`` holds one row per task (total size, expected SHA-256 and
finalization state).  ``last_activity_at`` records the task's most recent
activity as an ISO-8601 UTC timestamp: it is written at creation and
refreshed inside every successful chunk-upload transaction (duplicate
uploads included); rejected writes (conflicts, out-of-range chunks) never
touch it.  The idle-reaping endpoint (``POST /images/cleanup``) deletes
unsealed tasks whose ``last_activity_at`` is older than its cutoff; sealed
images — and therefore their attestations and any channels referencing
them — are never reaped.  Databases created before this column existed
are upgraded in-place by backfilling ``last_activity_at`` from
``created_at``.

``chunks`` stores the *merged* covered interval of a
task: whenever a new upload touches or abuts an existing interval, the two
are joined into a single row inside the same transaction.  Hence the rows
for any given task are always pairwise disjoint, ordered and, taken
together, exactly equal to the byte ranges accepted so far.  This makes gap
detection and final assembly trivial and conflict detection a single
range query.

``attestations`` holds at most one Ed25519 signature per (image, key_id):
the latest valid attestation submitted for a sealed image.  Trust is never
stored — it is always re-derived from these rows and the *currently*
configured public keys.

``channels`` holds one row per gray-release channel: the bound stable and
candidate image ids, the canary percentage and an optimistic-concurrency
revision that bumps on every accepted update.  Both images are validated
(exist, sealed, currently trusted) on every PUT; resolution re-derives
trust live, so the stored row is policy only, never a trust cache.

``receipts`` holds at most one installation receipt per (channel,
device_id): the device's latest report.  ``seq`` is a per-device sequence
number that must strictly increase for a report to replace the stored one
(monotonic across channel revisions); ``revision`` is the channel revision
the report was accepted under (only the channel's *current* revision is
accepted); ``expected_id`` is the image the device should have installed,
computed by the channel's resolution rules inside the same write
transaction that stored the receipt and never rewritten afterwards —
later policy or public-key changes do not alter it, and the
installation-audit endpoint reads it back as saved.  ``bucket_role`` is
the resolution role frozen at that same instant (``candidate`` for a
trusted-candidate canary bucket, ``stable`` for a stable bucket,
``candidate_untrusted_fallback`` / ``risk_circuit_breaker_fallback`` for
the two rollback paths): the risk breaker classifies canary samples by
this role, never by image id, so stable and candidate slots bound to the
SAME image id cannot be confused.  The column is nullable on purpose:
rows written before this column existed whose role cannot be recovered
reliably (see the migration in ``init_db``) stay NULL and are never
guessed as canary samples.

``channel_safety`` holds at most one risk circuit-breaker rule per
channel, bound to the channel revision (``rule_revision``) at arming
time: the minimum canary sample (``min_reports``) and the tolerated
anomaly percentage (``max_bad_percent``).  The tripped flag is a sticky
latch — once set it is never cleared by receipt overwrites; an accepted
channel update deletes the row (the old rule is invalid for the new
revision), so re-armament requires a fresh ``PUT .../safety``.  Like the
rest of the policy, rule and latch state live only in this file and
therefore survive container rebuilds via the mounted volume.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional

#: Hard protocol limits (see README).
MIN_SIZE = 1
MAX_SIZE = 64 * 1024 * 1024            # 67,108,864 bytes
MIN_CHUNK = 1
MAX_CHUNK = 1024 * 1024                 # 1,048,576 bytes
SHA256_LEN = 64


def db_path() -> str:
    return os.environ.get("IMAGE_DB_PATH", "/data/images.db")


def connect(path: Optional[str] = None) -> sqlite3.Connection:
    """Open a short-lived connection with sane concurrency settings."""
    conn = sqlite3.connect(path or db_path(), timeout=10.0)
    # We manage transactions explicitly (BEGIN IMMEDIATE ... COMMIT) so that
    # "read everything -> validate -> write" is atomic against other writers.
    conn.isolation_level = None
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {10_000}")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(path: Optional[str] = None) -> None:
    conn = connect(path)
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS images (
                id          TEXT PRIMARY KEY,
                total_size  INTEGER NOT NULL,
                sha256      TEXT    NOT NULL,
                finalized   INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT    NOT NULL,
                last_activity_at TEXT NOT NULL
            );

            -- WITHOUT ROWID: (image_id, offset) is the natural primary key and
            -- every access pattern looks a row up by it.
            CREATE TABLE IF NOT EXISTS chunks (
                image_id   TEXT    NOT NULL,
                "offset"   INTEGER NOT NULL,
                end_offset INTEGER NOT NULL,
                data       BLOB    NOT NULL,
                PRIMARY KEY (image_id, "offset"),
                FOREIGN KEY (image_id) REFERENCES images (id)
            ) WITHOUT ROWID;

            CREATE INDEX IF NOT EXISTS idx_chunks_image_end
                ON chunks (image_id, end_offset);

            -- One row per (image, key_id): the latest accepted attestation.
            -- The signature is stored as the base64 text that was submitted
            -- (and verified) at POST time.
            CREATE TABLE IF NOT EXISTS attestations (
                image_id   TEXT NOT NULL,
                key_id     TEXT NOT NULL,
                signature  TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (image_id, key_id),
                FOREIGN KEY (image_id) REFERENCES images (id)
            ) WITHOUT ROWID;

            -- One row per gray-release channel.  `revision` starts at 1 on
            -- creation and increments on every accepted update; writers must
            -- present the previous value as `expected_revision`.
            CREATE TABLE IF NOT EXISTS channels (
                name         TEXT PRIMARY KEY,
                stable_id    TEXT NOT NULL,
                candidate_id TEXT NOT NULL,
                percent      INTEGER NOT NULL,
                revision     INTEGER NOT NULL,
                updated_at   TEXT NOT NULL,
                FOREIGN KEY (stable_id) REFERENCES images (id),
                FOREIGN KEY (candidate_id) REFERENCES images (id)
            ) WITHOUT ROWID;

            -- One row per (channel, device_id): the device's latest
            -- installation receipt.  `seq` strictly increases for a report
            -- to replace the stored one (monotonic across revisions);
            -- `expected_id` and `bucket_role` are frozen at acceptance time
            -- (role NULL only for legacy rows migrated from an older schema).
            CREATE TABLE IF NOT EXISTS receipts (
                channel      TEXT    NOT NULL,
                device_id    TEXT    NOT NULL,
                seq          INTEGER NOT NULL,
                revision     INTEGER NOT NULL,
                status       TEXT    NOT NULL,
                installed_id TEXT,
                expected_id  TEXT    NOT NULL,
                bucket_role  TEXT,
                created_at   TEXT    NOT NULL,
                PRIMARY KEY (channel, device_id),
                FOREIGN KEY (channel) REFERENCES channels (name)
            ) WITHOUT ROWID;

            -- One row per channel: the armed risk circuit-breaker rule,
            -- bound to the channel revision at arming time.  `tripped` is a
            -- sticky latch: flipped to 1 once the anomaly threshold is
            -- crossed and never reset by later receipts.  An accepted
            -- channel update deletes this row (see PUT /channels/{name});
            -- each revision starts with no rule and must be re-armed.
            CREATE TABLE IF NOT EXISTS channel_safety (
                channel         TEXT PRIMARY KEY,
                rule_revision   INTEGER NOT NULL,
                min_reports     INTEGER NOT NULL,
                max_bad_percent INTEGER NOT NULL,
                tripped         INTEGER NOT NULL DEFAULT 0,
                created_at      TEXT    NOT NULL,
                updated_at      TEXT    NOT NULL,
                FOREIGN KEY (channel) REFERENCES channels (name)
            ) WITHOUT ROWID;
            """
        )

        # Upgrade a database created before idle reaping existed (see the
        # table-rebuild block below): add the last-activity column and
        # backfill it from created_at.
        cols = {
            r["name"]
            for r in conn.execute("PRAGMA table_info(images)")
        }
        if "last_activity_at" not in cols:
            # Canonical SQLite table rebuild (ALTER TABLE ADD COLUMN cannot
            # install NOT NULL without a default) so an upgraded database ends
            # with the exact same schema as a freshly created one.  Runs once,
            # at startup, before the service accepts traffic: foreign keys are
            # suspended on this connection for the swap and legacy rows are
            # backfilled from created_at.  Wrapped in one transaction — an
            # interrupted upgrade leaves the old table in place.
            conn.execute("PRAGMA foreign_keys = OFF")
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    """
                    CREATE TABLE images_new (
                        id          TEXT PRIMARY KEY,
                        total_size  INTEGER NOT NULL,
                        sha256      TEXT    NOT NULL,
                        finalized   INTEGER NOT NULL DEFAULT 0,
                        created_at  TEXT    NOT NULL,
                        last_activity_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    "INSERT INTO images_new "
                    "(id, total_size, sha256, finalized, created_at, "
                    " last_activity_at) "
                    "SELECT id, total_size, sha256, finalized, created_at, "
                    "created_at FROM images"
                )
                # DROP TABLE also drops images' indexes; FKs stay suspended for
                # this connection so chunks/attestations/channels survive.
                conn.execute("DROP TABLE images")
                conn.execute("ALTER TABLE images_new RENAME TO images")
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.execute("PRAGMA foreign_keys = ON")
            violations = conn.execute("PRAGMA foreign_key_check(images)").fetchall()
            if violations:
                raise RuntimeError(
                    "images migration left dangling foreign-key rows"
                )

        # Upgrade a database written before receipts froze their bucket role:
        # add the role column and make the breaker count by role instead of by
        # image id (the two slots may legitimately bind the same image id).
        has_receipts = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'receipts'"
        ).fetchone() is not None
        receipt_cols = {
            r["name"] for r in conn.execute("PRAGMA table_info(receipts)")
        } if has_receipts else set()
        if "bucket_role" not in receipt_cols:
            # ALTER TABLE ADD COLUMN on a WITHOUT ROWID table leaves existing
            # rows with NULL.  Runs once, at startup, before traffic: one
            # BEGIN IMMEDIATE transaction performs the column add, the
            # best-effort role backfill and the ambiguous-latch clearing
            # together, so an interrupted upgrade leaves the old schema in
            # place and is retried on the next start.
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute("ALTER TABLE receipts ADD COLUMN bucket_role TEXT")

                # Backfill only roles that are recoverable with certainty:
                # a current-revision receipt of a channel whose two slots
                # hold DIFFERENT image ids, frozen to the candidate id, is
                # unambiguously a canary receipt.  Everything else — notably
                # every receipt of a same-image channel, and every
                # old-revision receipt whose policy is no longer stored —
                # stays NULL and is never guessed as a candidate.
                conn.execute(
                    "UPDATE receipts SET bucket_role = 'candidate' "
                    "WHERE bucket_role IS NULL "
                    "AND revision = ("
                    "    SELECT c.revision FROM channels c "
                    "    WHERE c.name = receipts.channel"
                    ") "
                    "AND expected_id = ("
                    "    SELECT c.candidate_id FROM channels c "
                    "    WHERE c.name = receipts.channel"
                    ") "
                    "AND EXISTS ("
                    "    SELECT 1 FROM channels c "
                    "    WHERE c.name = receipts.channel "
                    "    AND c.stable_id <> c.candidate_id"
                    ")"
                )

                # Old code classified canary receipts by image id, so a
                # latched rule at a same-image revision could have been
                # flipped by stable-bucket/rollback receipts (its sample was
                # ambiguous).  Clear that revision's latch — keeping the
                # armed rule — so subsequent receipts re-evaluate under the
                # role-based rule; distinct-image channels keep their
                # (reliably-derived) latches.
                conn.execute(
                    "UPDATE channel_safety SET tripped = 0, updated_at = ? "
                    "WHERE tripped = 1 AND rule_revision = ("
                    "    SELECT c.revision FROM channels c "
                    "    WHERE c.name = channel_safety.channel"
                    ") AND EXISTS ("
                    "    SELECT 1 FROM channels c "
                    "    WHERE c.name = channel_safety.channel "
                    "    AND c.stable_id = c.candidate_id"
                    ") AND EXISTS ("
                    "    SELECT 1 FROM receipts r "
                    "    WHERE r.channel = channel_safety.channel "
                    "    AND r.revision = rule_revision "
                    "    AND r.bucket_role IS NULL"
                    ")",
                    (datetime.now(timezone.utc).isoformat(),),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise

        # Reaper's selection order: unsealed, due tasks ordered by
        # (last_activity_at, id).  Created after the migration above (a table
        # rebuild drops old indexes), so it always exists.
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_images_activity "
            "ON images (last_activity_at, id)"
        )
    finally:
        conn.close()


def new_id() -> str:
    return uuid.uuid4().hex


# Serializes writers *to the same task* within this process.  SQLite
# transactions (BEGIN IMMEDIATE) remain the real cross-process guarantee;
# this lock merely makes the common case deterministic and avoids wasting
# work that would otherwise die with SQLITE_BUSY.
_task_locks_guard = threading.Lock()
_task_locks: dict[str, threading.Lock] = {}


def task_lock(task_id: str) -> threading.Lock:
    with _task_locks_guard:
        lock = _task_locks.get(task_id)
        if lock is None:
            lock = threading.Lock()
            _task_locks[task_id] = lock
        return lock
