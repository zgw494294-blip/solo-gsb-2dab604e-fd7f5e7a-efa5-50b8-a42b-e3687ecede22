import base64
import hashlib
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

# Point the service at a throwaway DB *before* importing the app.
_tmpdir = tempfile.mkdtemp(prefix="imgapi-")
os.environ["IMAGE_DB_PATH"] = os.path.join(_tmpdir, "test.db")

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    PublicFormat,
)

from app.db import init_db  # noqa: E402
from app.main import app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture(scope="session")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


def create(client, data: bytes) -> str:
    r = client.post(
        "/images",
        json={"total_size": len(data), "sha256": hashlib.sha256(data).hexdigest()},
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


def finalize(client, data: bytes) -> str:
    """Create a task, upload it in one chunk and seal it; return the id."""
    tid = create(client, data)
    assert client.put(f"/images/{tid}/chunks?offset=0", content=data).status_code == 200
    assert client.post(f"/images/{tid}/finalize").status_code == 200
    return tid


# --------------------------------------------------------------------------- #
# Trust / attestation helpers
# --------------------------------------------------------------------------- #


def gen_key():
    """Return (private_key, base64_public_key) for a fresh Ed25519 keypair."""
    sk = Ed25519PrivateKey.generate()
    pk_b64 = base64.b64encode(
        sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    return sk, pk_b64


def set_keys(monkeypatch, mapping: dict) -> None:
    monkeypatch.setenv("TRUSTED_KEYS_JSON", json.dumps(mapping))


def sign(sk, image_id: str, sha256: str, total_size: int) -> str:
    """Sign the canonical FWIMGv1 message, return base64 signature."""
    msg = f"FWIMGv1|{image_id}|{sha256}|{total_size}".encode("ascii")
    return base64.b64encode(sk.sign(msg)).decode()


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_create_validation(client):
    r = client.post("/images", json={"total_size": 0, "sha256": "a" * 64})
    assert r.status_code == 422
    r = client.post("/images", json={"total_size": 64 * 1024 * 1024 + 1,
                                     "sha256": "a" * 64})
    assert r.status_code == 422
    r = client.post("/images", json={"total_size": 10, "sha256": "z" * 64})
    assert r.status_code == 422
    r = client.post("/images", json={"total_size": 10, "sha256": "ab"})
    assert r.status_code == 422


def test_chunk_size_limits_and_unknown(client):
    tid = create(client, b"x" * 10)
    assert client.put(f"/images/{tid}/chunks?offset=0", content=b"").status_code == 400
    big = b"y" * (1024 * 1024 + 1)
    assert client.put(f"/images/{tid}/chunks?offset=0", content=big).status_code == 413
    assert client.put("/images/nope/chunks?offset=0", content=b"x").status_code == 404
    assert client.get("/images/nope").status_code == 404


def test_out_of_order_duplicate_merge_and_bounds(client):
    data = bytes(range(256)) * 4  # 1024 bytes
    tid = create(client, data)

    # out of order
    assert client.put(f"/images/{tid}/chunks?offset=512",
                      content=data[512:1024]).status_code == 200
    r = client.put(f"/images/{tid}/chunks?offset=0", content=data[0:256])
    assert r.status_code == 200
    body = r.json()
    assert body["covered_intervals"] == [[0, 256], [512, 1024]]
    assert body["missing_intervals"] == [[256, 512]]

    # overlap that agrees -> merges into one run
    r = client.put(f"/images/{tid}/chunks?offset=200", content=data[200:600])
    assert r.status_code == 200
    assert r.json()["covered_intervals"] == [[0, 1024]]
    assert r.json()["missing_intervals"] == []
    assert r.json()["merged_interval"] == [0, 1024]

    # exact duplicate upload is accepted
    assert client.put(f"/images/{tid}/chunks?offset=200",
                      content=data[200:600]).status_code == 200

    # out of bounds
    assert client.put(f"/images/{tid}/chunks?offset=1020",
                      content=data[1020:1024] + b"q").status_code == 400


def test_conflict_rolls_back_entire_write(client):
    data = b"".join(bytes([i % 256]) * 256 for i in range(4))  # 1024 bytes
    tid = create(client, data)
    assert client.put(f"/images/{tid}/chunks?offset=0",
                      content=data[:512]).status_code == 200
    # conflicting chunk: [400,512) matches stored bytes, [512,700) is new
    # ground — flip one byte in the overlapping region [400,512).
    bad = bytearray(data[400:700])
    bad[50] ^= 0xFF
    r = client.put(f"/images/{tid}/chunks?offset=400", content=bytes(bad))
    assert r.status_code == 409, r.text

    state = client.get(f"/images/{tid}").json()
    # nothing from the rejected write landed; bytes past 512 still missing
    assert state["covered_intervals"] == [[0, 512]]
    assert state["missing_intervals"] == [[512, 1024]]

    # same upload with correct bytes now succeeds
    r = client.put(f"/images/{tid}/chunks?offset=400", content=data[400:700])
    assert r.status_code == 200
    assert r.json()["covered_intervals"] == [[0, 700]]


def test_finalize_gap_hash_seal_and_content(client):
    data = os.urandom(3000)
    tid = create(client, data)

    # cannot finalize with a gap
    client.put(f"/images/{tid}/chunks?offset=0", content=data[:1000])
    r = client.post(f"/images/{tid}/finalize")
    assert r.status_code == 409
    assert r.json()["detail"]["reason"] == "image has gaps"

    # wrong hash -> 409: create a same-size task, cover it with different bytes
    tid2 = create(client, data)
    other = b"\xff" * len(data)
    client.put(f"/images/{tid2}/chunks?offset=0", content=other[:2000])
    client.put(f"/images/{tid2}/chunks?offset=2000", content=other[2000:])
    r = client.post(f"/images/{tid2}/finalize")
    assert r.status_code == 409
    assert r.json()["detail"]["reason"] == "sha256 mismatch"

    # content unavailable before finalization
    assert client.get(f"/images/{tid}/content").status_code == 409

    # complete the good task
    client.put(f"/images/{tid}/chunks?offset=1000", content=data[1000:2500])
    client.put(f"/images/{tid}/chunks?offset=2500", content=data[2500:])
    r = client.post(f"/images/{tid}/finalize")
    assert r.status_code == 200
    assert r.json()["status"] == "finalized"
    # idempotent
    assert client.post(f"/images/{tid}/finalize").json()["already_finalized"] is True

    # sealed: writes rejected
    assert client.put(f"/images/{tid}/chunks?offset=0",
                      content=data[:100]).status_code == 409

    # content streams back identically
    r = client.get(f"/images/{tid}/content")
    assert r.status_code == 200
    assert r.content == data
    assert int(r.headers["content-length"]) == len(data)
    assert r.headers["x-sha256"] == hashlib.sha256(data).hexdigest()


def test_concurrent_writers_same_task(client):
    """Many threads hammer the same task with duplicated, reordered and
    overlapping windows of correct bytes; assembled image must be exact."""
    import concurrent.futures

    data = b"".join(bytes([i % 256]) * 64 for i in range(128))  # 8192 bytes
    tid = create(client, data)

    # All uploads stay 256-aligned so overlapping windows are consistent:
    # chunks are [o, o+512) at 256-strided offsets (each 512-byte window
    # equals the corresponding two 256-blocks), submitted from many threads.
    offsets = list(range(0, len(data), 256))

    def put(off):
        hi = min(len(data), off + 512)
        r = client.put(f"/images/{tid}/chunks?offset={off}", content=data[off:hi])
        return r.status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        codes = list(pool.map(put, offsets))
    assert set(codes) <= {200}, codes

    state = client.get(f"/images/{tid}").json()
    assert state["covered_intervals"] == [[0, len(data)]]
    assert client.post(f"/images/{tid}/finalize").status_code == 200
    assert client.get(f"/images/{tid}/content").content == data


def test_concurrent_conflicting_writers_rollback_cleanly(client):
    """Two writers submit *different* bytes for the same overlapping range
    concurrently: one must win, the other get 409, and the stored bytes must
    be exactly one of the two candidates — never a mixture."""
    import concurrent.futures

    data_a = b"A" * 4096
    data_b = b"B" * 4096
    tid = create(client, data_a)  # expected hash = A image

    def put(payload):
        return client.put("/images/%s/chunks?offset=0" % tid,
                          content=payload).status_code

    # Fresh task: upload full A or full B many times; first commit wins,
    # subsequent identical winner uploads are 200, the other side gets 409.
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futs = []
        for i in range(20):
            futs.append(pool.submit(put, data_a if i % 2 == 0 else data_b))
        codes = [f.result() for f in futs]
    assert 200 in codes and 409 in codes, codes

    state = client.get(f"/images/{tid}").json()
    assert state["covered_intervals"] == [[0, 4096]]
    # Stored content is uniform — proves no torn/merged garbage
    assert client.put(f"/images/{tid}/chunks?offset=0",
                      content=data_a).status_code in (200, 409)
    a_ok = client.put(f"/images/{tid}/chunks?offset=0",
                      content=data_a).status_code == 200
    b_ok = client.put(f"/images/{tid}/chunks?offset=0",
                      content=data_b).status_code == 200
    assert a_ok != b_ok  # exactly one matches what is stored


def test_persistence_survives_process_restart():
    """The DB file is the single source of truth: a brand-new client/app
    instance against the same file sees prior tasks, chunks and seals."""
    data = b"persist-me-" * 100
    with TestClient(app) as c1:
        r = c1.post("/images", json={
            "total_size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
        tid = r.json()["id"]
        c1.put(f"/images/{tid}/chunks?offset=700", content=data[700:])
        c1.put(f"/images/{tid}/chunks?offset=0", content=data[:700])
        assert c1.post(f"/images/{tid}/finalize").status_code == 200

    # Simulate a container rebuild: a fresh TestClient over the same file.
    with TestClient(app) as c2:
        state = c2.get(f"/images/{tid}").json()
        assert state["finalized"] is True
        assert state["covered_intervals"] == [[0, len(data)]]
        assert c2.get(f"/images/{tid}/content").content == data
        # still write-protected after restart
        assert c2.put(f"/images/{tid}/chunks?offset=0",
                      content=data[:10]).status_code == 409


# --------------------------------------------------------------------------- #
# Attestations & trust
# --------------------------------------------------------------------------- #


def test_attestation_requires_existing_finalized_image(client, monkeypatch):
    sk, pk = gen_key()
    set_keys(monkeypatch, {"ops": pk})

    # unknown image -> 404
    r = client.post("/images/nope/attestations",
                    json={"key_id": "ops", "signature": "AAAA"})
    assert r.status_code == 404

    # not yet finalized -> 409
    data = os.urandom(200)
    tid = create(client, data)
    client.put(f"/images/{tid}/chunks?offset=0", content=data)
    sha = hashlib.sha256(data).hexdigest()
    r = client.post(f"/images/{tid}/attestations",
                    json={"key_id": "ops",
                          "signature": sign(sk, tid, sha, len(data))})
    assert r.status_code == 409

    # unknown image also 404 on the trust endpoint
    assert client.get("/images/nope/trust").status_code == 404


def test_attestation_rejects_bad_input_and_never_persists(client, monkeypatch):
    sk, pk = gen_key()
    other_sk, _ = gen_key()
    set_keys(monkeypatch, {"ops": pk})

    data = os.urandom(128)
    tid = finalize(client, data)
    sha = hashlib.sha256(data).hexdigest()

    # unknown key_id -> 400
    r = client.post(f"/images/{tid}/attestations",
                    json={"key_id": "ghost",
                          "signature": sign(sk, tid, sha, len(data))})
    assert r.status_code == 400

    # malformed base64 -> 400
    r = client.post(f"/images/{tid}/attestations",
                    json={"key_id": "ops", "signature": "!!!not-base64!!!"})
    assert r.status_code == 400

    # valid base64 but not a signature over the server record -> 400
    r = client.post(f"/images/{tid}/attestations",
                    json={"key_id": "ops",
                          "signature": base64.b64encode(b"x" * 64).decode()})
    assert r.status_code == 400

    # signature from a *different* key than the configured one -> 400
    r = client.post(f"/images/{tid}/attestations",
                    json={"key_id": "ops",
                          "signature": sign(other_sk, tid, sha, len(data))})
    assert r.status_code == 400

    # signature over a tampered message (wrong total_size) -> 400
    r = client.post(f"/images/{tid}/attestations",
                    json={"key_id": "ops",
                          "signature": sign(sk, tid, sha, len(data) + 1)})
    assert r.status_code == 400

    # nothing was persisted by any of the rejected calls
    trust = client.get(f"/images/{tid}/trust").json()
    assert trust["attestations_stored"] == 0
    assert trust["valid_key_ids"] == []
    assert trust["trusted"] is False


def test_attestation_and_trust_flow(client, monkeypatch):
    sk1, pk1 = gen_key()
    sk2, pk2 = gen_key()
    set_keys(monkeypatch, {"ops": pk1, "ci": pk2})

    data = os.urandom(512)
    tid = finalize(client, data)
    sha = hashlib.sha256(data).hexdigest()

    # first attestation: recorded, but one key is below the threshold
    sig1 = sign(sk1, tid, sha, len(data))
    r = client.post(f"/images/{tid}/attestations",
                    json={"key_id": "ops", "signature": sig1})
    assert r.status_code == 200
    assert r.json()["status"] == "recorded"

    trust = client.get(f"/images/{tid}/trust").json()
    assert trust["trusted"] is False
    assert trust["valid_key_ids"] == ["ops"]
    assert trust["threshold"] == 2

    # identical resubmission is idempotent
    r = client.post(f"/images/{tid}/attestations",
                    json={"key_id": "ops", "signature": sig1})
    assert r.status_code == 200
    assert r.json()["status"] == "unchanged"
    assert client.get(f"/images/{tid}/trust").json()["attestations_stored"] == 1

    # second distinct key crosses the threshold
    r = client.post(f"/images/{tid}/attestations",
                    json={"key_id": "ci",
                          "signature": sign(sk2, tid, sha, len(data))})
    assert r.status_code == 200
    trust = client.get(f"/images/{tid}/trust").json()
    assert trust["trusted"] is True
    assert trust["valid_key_ids"] == ["ci", "ops"]


def test_trust_without_configured_keys(client, monkeypatch):
    monkeypatch.delenv("TRUSTED_KEYS_JSON", raising=False)
    data = os.urandom(64)
    tid = finalize(client, data)

    # service runs, but every key_id is unknown and nothing can be trusted
    r = client.post(f"/images/{tid}/attestations",
                    json={"key_id": "ops", "signature": "AAAA"})
    assert r.status_code == 400
    trust = client.get(f"/images/{tid}/trust").json()
    assert trust["trusted"] is False
    assert trust["valid_key_ids"] == []


def test_key_rotation_invalidates_old_signatures(client, monkeypatch):
    sk_old, pk_old = gen_key()
    sk_new, pk_new = gen_key()
    set_keys(monkeypatch, {"ops": pk_old})

    data = os.urandom(256)
    tid = finalize(client, data)
    sha = hashlib.sha256(data).hexdigest()

    r = client.post(f"/images/{tid}/attestations",
                    json={"key_id": "ops",
                          "signature": sign(sk_old, tid, sha, len(data))})
    assert r.status_code == 200
    assert client.get(f"/images/{tid}/trust").json()["valid_key_ids"] == ["ops"]

    # Rotate: same key_id now maps to a different public key. The stored
    # signature must no longer count.
    set_keys(monkeypatch, {"ops": pk_new})
    trust = client.get(f"/images/{tid}/trust").json()
    assert trust["valid_key_ids"] == []
    assert trust["trusted"] is False
    assert trust["attestations_stored"] == 1  # row kept, just not counted

    # A new valid signature under the rotated key replaces the stale one.
    r = client.post(f"/images/{tid}/attestations",
                    json={"key_id": "ops",
                          "signature": sign(sk_new, tid, sha, len(data))})
    assert r.status_code == 200
    assert r.json()["status"] == "replaced"
    trust = client.get(f"/images/{tid}/trust").json()
    assert trust["valid_key_ids"] == ["ops"]
    assert trust["attestations_stored"] == 1  # still one row per key_id

    # Removing the key from the configuration entirely also un-counts it.
    set_keys(monkeypatch, {})
    assert client.get(f"/images/{tid}/trust").json()["valid_key_ids"] == []


def test_attestations_persist_across_restart(client, monkeypatch):
    sk1, pk1 = gen_key()
    sk2, pk2 = gen_key()
    keys = {"ops": pk1, "ci": pk2}
    set_keys(monkeypatch, keys)

    data = os.urandom(1000)
    tid = finalize(client, data)
    sha = hashlib.sha256(data).hexdigest()
    for key_id, sk in (("ops", sk1), ("ci", sk2)):
        r = client.post(f"/images/{tid}/attestations",
                        json={"key_id": key_id,
                              "signature": sign(sk, tid, sha, len(data))})
        assert r.status_code == 200
    assert client.get(f"/images/{tid}/trust").json()["trusted"] is True

    # Simulate a container rebuild: a fresh TestClient over the same DB file
    # (TRUSTED_KEYS_JSON is still set, as it would be via the environment).
    with TestClient(app) as c2:
        trust = c2.get(f"/images/{tid}/trust").json()
        assert trust["trusted"] is True
        assert trust["valid_key_ids"] == ["ci", "ops"]
        assert trust["attestations_stored"] == 2


# --------------------------------------------------------------------------- #
# Incremental delta distribution
# --------------------------------------------------------------------------- #


def restore(base: bytes, delta: dict) -> bytes:
    """Reference client: truncate/zero-pad base then overwrite emitted blocks."""
    out = bytearray(delta["target_size"])
    out[: min(len(base), delta["target_size"])] = base[: delta["target_size"]]
    for blk in delta["blocks"]:
        raw = base64.b64decode(blk["data"])
        assert len(raw) == blk["length"]
        out[blk["offset"] : blk["offset"] + blk["length"]] = raw
    return bytes(out)


def _finalize_sharded(client, data: bytes, shard: int = 100003) -> str:
    """Upload in shards deliberately misaligned to the 64 KiB delta grid."""
    tid = create(client, data)
    for off in range(0, len(data), shard):
        r = client.put(f"/images/{tid}/chunks?offset={off}",
                       content=data[off : off + shard])
        assert r.status_code == 200, r.text
    assert client.post(f"/images/{tid}/finalize").status_code == 200
    return tid


def test_delta_status_codes(client):
    data = os.urandom(1000)
    base_sealed = finalize(client, data)

    # target missing
    assert client.get(f"/images/{base_sealed}/delta/nope").status_code == 404
    # base missing
    assert client.get(f"/images/nope/delta/{base_sealed}").status_code == 404
    # both missing
    assert client.get("/images/nope/delta/also-nope").status_code == 404

    # unsealed base
    unsealed = create(client, data)
    client.put(f"/images/{unsealed}/chunks?offset=0", content=data)
    target = finalize(client, data)
    r = client.get(f"/images/{unsealed}/delta/{target}")
    assert r.status_code == 409
    # unsealed target
    r = client.get(f"/images/{base_sealed}/delta/{unsealed}")
    assert r.status_code == 409


def test_delta_identical_images_empty_blocks(client):
    data = os.urandom(200000)
    base = _finalize_sharded(client, data)
    target = _finalize_sharded(client, data)

    r = client.get(f"/images/{base}/delta/{target}")
    assert r.status_code == 200
    body = r.json()
    assert body["blocks"] == []
    assert body["block_size"] == 65536
    assert body["target_size"] == len(data)
    assert body["target_sha256"] == hashlib.sha256(data).hexdigest()
    assert body["base_sha256"] == hashlib.sha256(data).hexdigest()

    # delta of an image against itself
    assert client.get(f"/images/{base}/delta/{base}").json()["blocks"] == []


def test_delta_grows_and_restores(client):
    # 2.5 blocks; target grows beyond the base end.
    base_data = b"A" * 100000
    target_data = bytearray(base_data)
    target_data[0:10] = b"Z" * 10                 # first block differs
    target_data.extend(b"B" * 90000)              # target grows
    target_data[150000:150010] = b"Q" * 10        # a grown region block
    base = _finalize_sharded(client, bytes(base_data))
    target = _finalize_sharded(client, bytes(target_data))

    body = client.get(f"/images/{base}/delta/{target}").json()
    assert body["target_size"] == len(target_data)
    offsets = [b["offset"] for b in body["blocks"]]
    assert offsets == sorted(offsets)
    assert all(b["length"] <= 65536 for b in body["blocks"])
    # blocks on a fixed 64 KiB grid -> non-overlapping by construction
    for a, b in zip(body["blocks"], body["blocks"][1:]):
        assert a["offset"] + a["length"] <= b["offset"]
    assert restore(bytes(base_data), body) == bytes(target_data)

    # content and attestations untouched by a read-only delta
    assert client.get(f"/images/{target}/content").content == bytes(target_data)
    assert client.get(f"/images/{base}/content").content == bytes(base_data)


def test_delta_shrinks_short_final_block(client):
    # equal prefix, target shorter: the tail simply disappears on restore.
    base_data = (b"abc" * 40000) + os.urandom(50000)   # 170000 bytes
    target_data = base_data[:140001]                  # < 3 full blocks
    base = _finalize_sharded(client, base_data)
    target = _finalize_sharded(client, target_data)

    body = client.get(f"/images/{base}/delta/{target}").json()
    assert body["target_size"] == len(target_data)
    lengths = [b["length"] for b in body["blocks"]]
    tail = len(target_data) % 65536
    if body["blocks"]:
        assert lengths[-1] == (tail if tail else 65536)
    assert restore(base_data, body) == target_data

    # reverse direction: now the target grows, last emitted block is a short one
    rev = client.get(f"/images/{target}/delta/{base}").json()
    assert rev["target_size"] == len(base_data)
    assert restore(target_data, rev) == base_data


def test_delta_randomized_round_trip_across_grid_boundaries(client):
    """Random base/target pairs: every grid block differing must be emitted,
    identical blocks must not, and restoration must always reproduce target
    byte-for-byte — including when changes straddle 64 KiB boundaries."""
    rng = __import__("random").Random(42)

    def perturb(data: bytes) -> bytes:
        out = bytearray(data)
        for _ in range(rng.randint(0, 8)):
            pos = rng.randrange(len(out))
            span = rng.randint(1, 5)
            for i in range(pos, min(len(out), pos + span)):
                out[i] = rng.randrange(256)
        return bytes(out)

    for n in (1, 65535, 65536, 65537, 200000):
        base_data = bytes(rng.randrange(256) for _ in range(n))
        target_data = perturb(base_data)
        base = _finalize_sharded(client, base_data, shard=37171)
        target = _finalize_sharded(client, target_data, shard=55511)

        body = client.get(f"/images/{base}/delta/{target}").json()
        assert body["target_size"] == n

        # independently compute the expected differing grid blocks
        expected_offsets = []
        for off in range(0, n, 65536):
            end = min(n, off + 65536)
            if base_data[off:end] != target_data[off:end]:
                expected_offsets.append(off)
        assert [b["offset"] for b in body["blocks"]] == expected_offsets
        for b in body["blocks"]:
            assert b["data"] == base64.b64encode(
                target_data[b["offset"] : b["offset"] + b["length"]]
            ).decode()

        assert restore(base_data, body) == target_data


def test_shard_reader_stitches_row_boundaries(client):
    """Unit-level check: a window straddling two stored rows is assembled
    transparently, exercising reads that cross existing shard boundaries.

    Sealed real images always merge into one row; use an isolated throwaway
    image with two adjacent rows so no real image or signature is touched.
    """
    import sqlite3 as _sqlite3
    import uuid

    from app.db import db_path
    from app.main import DELTA_BLOCK_SIZE, _ShardReader

    data = os.urandom(200000)
    cut = DELTA_BLOCK_SIZE - 10  # row boundary 10 bytes inside delta block 1
    fake_id = uuid.uuid4().hex

    conn = _sqlite3.connect(db_path())
    conn.row_factory = _sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        conn.execute(
            "INSERT INTO images (id, total_size, sha256, finalized, created_at, "
            "last_activity_at) VALUES (?, ?, ?, 1, ?, ?)",
            (fake_id, len(data), hashlib.sha256(data).hexdigest(), "t", "t"),
        )
        conn.execute(
            'INSERT INTO chunks (image_id, "offset", end_offset, data) '
            "VALUES (?, 0, ?, ?)",
            (fake_id, cut, data[:cut]),
        )
        conn.execute(
            'INSERT INTO chunks (image_id, "offset", end_offset, data) '
            "VALUES (?, ?, ?, ?)",
            (fake_id, cut, len(data), data[cut:]),
        )
        conn.commit()

        reader = _ShardReader(conn, fake_id)
        first = reader.read(DELTA_BLOCK_SIZE)  # straddles the row boundary
        assert first == data[:DELTA_BLOCK_SIZE]
        rest = reader.read(len(data) - DELTA_BLOCK_SIZE)
        assert first + rest == data
        assert reader.read(1) == b""  # clean EOF
    finally:
        conn.close()


def test_delta_large_images_peak_memory_is_bounded(client):
    """Large sealed images: the delta scan must not make either image
    memory-resident — its read buffer is bounded by the 64 KiB grid, not
    by the image length.

    Both images are uploaded through the normal API in consecutive 1 MiB
    shards, so the server merges each into ONE whole-image BLOB row (the
    worst case for row-at-a-time reading).  The old reader pulled the
    entire `data` column on the first window, pinning BOTH images
    (>= 2 x image size) for the whole stream; the fixed-size substr()
    slicing reader must stay far below one image.
    """
    import sqlite3 as _sqlite3
    import tracemalloc

    from app.db import MAX_CHUNK, db_path

    size = 16 * 1024 * 1024  # 16 MiB per image
    base_data = os.urandom(size)
    target = bytearray(base_data)
    target[0:100] = b"\xff" * 100                         # block 0 differs
    target[5 * 65536 : 5 * 65536 + 100] = b"\xfe" * 100   # block 5 differs
    target_data = bytes(target)

    def finalize_sequential(data: bytes) -> str:
        """Upload in consecutive max-size shards and seal."""
        tid = create(client, data)
        for off in range(0, len(data), MAX_CHUNK):
            r = client.put(f"/images/{tid}/chunks?offset={off}",
                           content=data[off : off + MAX_CHUNK])
            assert r.status_code == 200, r.text
        assert client.post(f"/images/{tid}/finalize").status_code == 200
        return tid

    base = finalize_sequential(base_data)
    target_id = finalize_sequential(target_data)

    # Scenario precondition: adjacent shards really did merge into a single
    # whole-image BLOB row per image.
    conn = _sqlite3.connect(db_path())
    try:
        for tid in (base, target_id):
            rows = conn.execute(
                "SELECT COUNT(*) FROM chunks WHERE image_id = ?", (tid,)
            ).fetchone()[0]
            assert rows == 1
    finally:
        conn.close()

    # 1) Python-level peak allocation over one full delta request.
    tracemalloc.start()
    tracemalloc.reset_peak()
    try:
        r = client.get(f"/images/{base}/delta/{target_id}")
        assert r.status_code == 200
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    body = r.json()
    assert restore(base_data, body) == target_data
    assert peak < size // 2, f"delta request peaked at {peak / 2**20:.1f} MiB"

    # 2) Process RSS sampled while the streamed response is mid-flight
    #    (Linux /proc only; skipped elsewhere).
    def vmrss_kib() -> int | None:
        try:
            with open("/proc/self/status") as fh:
                for line in fh:
                    if line.startswith("VmRSS:"):
                        return int(line.split()[1])
        except OSError:
            return None

    before = vmrss_kib()
    if before is not None:
        with client.stream("GET", f"/images/{base}/delta/{target_id}") as resp:
            assert resp.status_code == 200
            chunks = resp.iter_bytes()
            first = next(chunks)  # server is now mid-scan
            mid = vmrss_kib()
            tail = b"".join(chunks)
        assert restore(base_data, json.loads(first + tail)) == target_data
        assert mid - before < (size // 2) // 1024, (
            f"RSS grew {(mid - before) / 1024:.1f} MiB mid-stream"
        )


# --------------------------------------------------------------------------- #
# Merkle commitments & multi-proofs
# --------------------------------------------------------------------------- #

MERKLE_LEAF = 65536


def ref_merkle_levels(data: bytes) -> list[list[bytes]]:
    """Independent reference: every tree level for `data` (hashes as bytes)."""
    leaves = [
        hashlib.sha256(b"\x00" + data[o : o + MERKLE_LEAF]).digest()
        for o in range(0, len(data), MERKLE_LEAF)
    ]
    levels = [leaves]
    while len(levels[-1]) > 1:
        nodes = levels[-1]
        if len(nodes) % 2 == 1:
            nodes = nodes + [nodes[-1]]
        levels.append(
            [
                hashlib.sha256(b"\x01" + nodes[i] + nodes[i + 1]).digest()
                for i in range(0, len(nodes), 2)
            ]
        )
    return levels


def ref_proof_plan(leaf_count: int, indices) -> list[tuple[int, int]]:
    """(level, index) pairs a minimal shared proof must contain, sorted."""
    plan = []
    known = set(indices)
    n, level = leaf_count, 0
    while n > 1:
        needed = set()
        for i in known:
            sib = i ^ 1
            if sib < n and sib not in known:
                needed.add(sib)
        plan.extend((level, s) for s in sorted(needed))
        known = {i // 2 for i in known}
        n = (n + 1) // 2
        level += 1
    return plan


def ref_verify(root_hex: str, leaf_count: int, leaves, proof) -> bool:
    """Recompute the root from `leaves` [(index, bytes)] + `proof` entries."""
    known = {i: hashlib.sha256(b"\x00" + d).digest() for i, d in leaves}
    provided = {(p["level"], p["index"]): bytes.fromhex(p["hash"]) for p in proof}
    n, level = leaf_count, 0
    while n > 1:
        nxt = {}
        for i, h in known.items():
            sib = i ^ 1
            if sib < n:
                sh = known.get(sib, provided.get((level, sib)))
                if sh is None:
                    return False
                left, right = (h, sh) if i % 2 == 0 else (sh, h)
            else:
                left = right = h  # odd-level tail pairs with its own copy
            nxt[i // 2] = hashlib.sha256(b"\x01" + left + right).digest()
        known, n, level = nxt, (n + 1) // 2, level + 1
    return len(known) == 1 and known[0].hex() == root_hex


def proof_leaves(body) -> list[tuple[int, bytes]]:
    return [(l["index"], base64.b64decode(l["data"])) for l in body["leaves"]]


def test_merkle_status_codes(client):
    data = os.urandom(1000)

    # unknown image -> 404 on both endpoints
    assert client.get("/images/nope/merkle").status_code == 404
    assert client.post("/images/nope/proof", json={"indices": [0]}).status_code == 404

    # unsealed image -> 409
    tid = create(client, data)
    client.put(f"/images/{tid}/chunks?offset=0", content=data)
    assert client.get(f"/images/{tid}/merkle").status_code == 409
    assert client.post(f"/images/{tid}/proof", json={"indices": [0]}).status_code == 409


def test_merkle_root_matches_reference(client):
    # sizes: single short leaf, one exact leaf, two leaves, odd leaf counts,
    # and a tree whose odd node counts span several levels (5 -> 3 -> 2 -> 1)
    for n in (1, 100, 65535, 65536, 65537, 3 * 65536, 300000):
        data = os.urandom(n)
        tid = finalize(client, data)
        r = client.get(f"/images/{tid}/merkle")
        assert r.status_code == 200, r.text
        body = r.json()
        levels = ref_merkle_levels(data)
        assert body["id"] == tid
        assert body["total_size"] == n
        assert body["leaf_size"] == MERKLE_LEAF
        assert body["leaf_count"] == (n + MERKLE_LEAF - 1) // MERKLE_LEAF
        assert body["root"] == levels[-1][0].hex()
        if n <= MERKLE_LEAF:
            # single-leaf tree: the root IS the leaf hash
            assert body["root"] == hashlib.sha256(b"\x00" + data).hexdigest()


def test_merkle_proof_round_trip(client):
    # 5 leaves -> odd node counts on several levels (5 -> 3 -> 2 -> 1)
    data = os.urandom(300000)
    tid = finalize(client, data)
    root = client.get(f"/images/{tid}/merkle").json()["root"]
    levels = ref_merkle_levels(data)
    leaf_count = 5

    for indices in ([0], [4], [1, 3], [0, 2, 4], [2, 3], list(range(5))):
        r = client.post(f"/images/{tid}/proof", json={"indices": indices})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["root"] == root
        assert body["leaf_count"] == leaf_count
        assert body["total_size"] == len(data)

        # leaves come back index-sorted with their exact bytes and lengths
        got_idx = [l["index"] for l in body["leaves"]]
        assert got_idx == sorted(set(indices))
        for l in body["leaves"]:
            raw = base64.b64decode(l["data"])
            start = l["index"] * MERKLE_LEAF
            expect = data[start : start + MERKLE_LEAF]
            assert l["length"] == len(raw) == len(expect)
            assert raw == expect

        # proof entries: sorted by (level, index), exactly the minimal set,
        # hashes equal to the reference tree nodes
        plan = [(p["level"], p["index"]) for p in body["proof"]]
        assert plan == sorted(plan)
        assert plan == ref_proof_plan(leaf_count, indices)
        for p in body["proof"]:
            assert p["hash"] == levels[p["level"]][p["index"]].hex()

        # and the proof convinces a verifier holding only the root
        assert ref_verify(root, leaf_count, proof_leaves(body), body["proof"])


def test_merkle_proof_omits_duplicated_tail(client):
    # 3 leaves: level 0 duplicates leaf 2; proving it needs no level-0 entry
    data = os.urandom(3 * 65536 - 100)
    tid = finalize(client, data)
    body = client.post(f"/images/{tid}/proof", json={"indices": [2]}).json()
    assert [(p["level"], p["index"]) for p in body["proof"]] == [(1, 0)]
    root = client.get(f"/images/{tid}/merkle").json()["root"]
    assert ref_verify(root, 3, proof_leaves(body), body["proof"])

    # asking for every leaf needs no proof nodes at all
    body = client.post(f"/images/{tid}/proof", json={"indices": [0, 1, 2]}).json()
    assert body["proof"] == []


def test_merkle_single_leaf(client):
    data = os.urandom(100)
    tid = finalize(client, data)
    body = client.post(f"/images/{tid}/proof", json={"indices": [0]}).json()
    assert body["leaf_count"] == 1
    assert body["proof"] == []
    assert body["root"] == hashlib.sha256(b"\x00" + data).hexdigest()
    assert ref_verify(body["root"], 1, proof_leaves(body), [])


def test_merkle_proof_validation(client):
    data = os.urandom(70000)  # 2 leaves
    tid = finalize(client, data)

    def code(indices):
        return client.post(f"/images/{tid}/proof",
                           json={"indices": indices}).status_code

    assert code([]) == 422                    # too few
    assert code(list(range(65))) == 422       # too many
    assert code([0, 0]) == 422                # duplicates
    assert code([-1]) == 422                  # negative
    assert code([2]) == 422                   # >= leaf_count
    assert code([0, 5]) == 422
    assert code(["x"]) == 422                 # not an integer
    assert code([1.5]) == 422
    assert client.post(f"/images/{tid}/proof", json={}).status_code == 422
    assert code([0, 1]) == 200
    assert code([64]) == 422                  # 64 distinct valid ones are OK...
    many = client.post(f"/images/{tid}/proof",
                       json={"indices": list(range(64))})
    assert many.status_code == 422            # ...but they must be < leaf_count


def test_merkle_proof_max_indices_ok(client):
    # 70 leaves: a request for 64 distinct valid indices succeeds
    data = os.urandom(70 * MERKLE_LEAF)
    tid = _finalize_sharded(client, data)  # > 1 MiB: upload in shards
    indices = list(range(3, 67))
    r = client.post(f"/images/{tid}/proof", json={"indices": indices})
    assert r.status_code == 200, r.text
    body = r.json()
    assert [l["index"] for l in body["leaves"]] == indices
    root = client.get(f"/images/{tid}/merkle").json()["root"]
    assert ref_verify(root, 70, proof_leaves(body), body["proof"])


def test_merkle_proof_tampering_breaks_verification(client):
    data = os.urandom(200000)  # 4 leaves
    tid = finalize(client, data)
    root = client.get(f"/images/{tid}/merkle").json()["root"]
    body = client.post(f"/images/{tid}/proof", json={"indices": [1, 2]}).json()
    leaves = proof_leaves(body)
    assert ref_verify(root, 4, leaves, body["proof"])

    # flip one byte in a returned block -> recomputed root no longer matches
    bad = bytearray(leaves[0][1])
    bad[0] ^= 0xFF
    assert not ref_verify(root, 4, [(leaves[0][0], bytes(bad)), leaves[1]],
                          body["proof"])

    # corrupt a proof hash -> fails
    broken = [dict(p) for p in body["proof"]]
    broken[0]["hash"] = "00" * 32
    assert not ref_verify(root, 4, leaves, broken)

    # drop a needed proof node -> fails
    assert not ref_verify(root, 4, leaves, body["proof"][1:])

    # honest proof checked against a different (attacker-supplied) root -> fails
    assert not ref_verify("11" * 32, 4, leaves, body["proof"])


def test_merkle_works_for_previously_sealed_images(client):
    """Images sealed before this feature existed need no migration: the tree
    is derived from the stored bytes on every request."""
    data = os.urandom(150000)
    tid = finalize(client, data)

    # Simulate a container rebuild: a fresh TestClient over the same DB file.
    with TestClient(app) as c2:
        body = c2.get(f"/images/{tid}/merkle").json()
        assert body["root"] == ref_merkle_levels(data)[-1][0].hex()
        proof = c2.post(f"/images/{tid}/proof", json={"indices": [1, 2]}).json()
        assert ref_verify(body["root"], body["leaf_count"],
                          proof_leaves(proof), proof["proof"])


def test_merkle_large_image_scan_is_bounded(client):
    """Building the tree must not make the image memory-resident: the scan
    reads through the same bounded-slice reader as the delta endpoint, so
    peak allocation stays far below the image length."""
    import tracemalloc

    from app.db import MAX_CHUNK

    size = 16 * 1024 * 1024  # 16 MiB, 256 leaves
    data = os.urandom(size)
    tid = create(client, data)
    for off in range(0, len(data), MAX_CHUNK):
        r = client.put(f"/images/{tid}/chunks?offset={off}",
                       content=data[off : off + MAX_CHUNK])
        assert r.status_code == 200, r.text
    assert client.post(f"/images/{tid}/finalize").status_code == 200

    tracemalloc.start()
    tracemalloc.reset_peak()
    try:
        body = client.get(f"/images/{tid}/merkle").json()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert body["leaf_count"] == size // MERKLE_LEAF
    assert body["root"] == ref_merkle_levels(data)[-1][0].hex()
    assert peak < size // 2, f"merkle scan peaked at {peak / 2**20:.1f} MiB"

    # a proof request for a handful of leaves is bounded the same way
    tracemalloc.start()
    tracemalloc.reset_peak()
    try:
        proof = client.post(f"/images/{tid}/proof",
                            json={"indices": [0, 100, 255]}).json()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert ref_verify(body["root"], body["leaf_count"],
                      proof_leaves(proof), proof["proof"])
    assert peak < size // 2, f"proof scan peaked at {peak / 2**20:.1f} MiB"


# --------------------------------------------------------------------------- #
# Gray-release channels
# --------------------------------------------------------------------------- #


def ref_channel_bucket(name: str, device_id: str) -> int:
    """Independent reference: SHA-256(name || 0x00 || device_id), first 8
    bytes big-endian, mod 10000."""
    digest = hashlib.sha256(
        name.encode("utf-8") + b"\x00" + device_id.encode("utf-8")
    ).digest()
    return int.from_bytes(digest[:8], "big") % 10000


def finalize_trusted(client, data: bytes, signers: dict) -> str:
    """Seal `data` and attest it with every {key_id: sk}; assert trusted."""
    tid = finalize(client, data)
    sha = hashlib.sha256(data).hexdigest()
    for key_id, sk in signers.items():
        r = client.post(f"/images/{tid}/attestations",
                        json={"key_id": key_id,
                              "signature": sign(sk, tid, sha, len(data))})
        assert r.status_code == 200, r.text
    assert client.get(f"/images/{tid}/trust").json()["trusted"] is True
    return tid


def make_channel_images(client, monkeypatch):
    """Two trusted images plus the key material that made them trusted."""
    sk1, pk1 = gen_key()
    sk2, pk2 = gen_key()
    set_keys(monkeypatch, {"ops": pk1, "ci": pk2})
    signers = {"ops": sk1, "ci": sk2}
    stable = finalize_trusted(client, os.urandom(600), signers)
    candidate = finalize_trusted(client, os.urandom(700), signers)
    return stable, candidate


def test_channel_put_validation(client, monkeypatch):
    stable, candidate = make_channel_images(client, monkeypatch)
    body = {"stable_id": stable, "candidate_id": candidate,
            "percent": 25, "expected_revision": 0}

    def put(**override):
        return client.put("/channels/v", json={**body, **override})

    assert put(percent=-1).status_code == 422
    assert put(percent=101).status_code == 422
    assert put(percent=12.5).status_code == 422
    assert put(expected_revision=-1).status_code == 422
    assert client.put("/channels/v", json={"stable_id": stable}).status_code == 422
    # unknown channel: only expected_revision=0 creates
    assert put(expected_revision=1).status_code == 409
    assert client.get("/channels/v/resolve", params={"device_id": "d"}).status_code == 404


def test_channel_revision_flow(client, monkeypatch):
    stable, candidate = make_channel_images(client, monkeypatch)

    r = client.put("/channels/rel-1", json={
        "stable_id": stable, "candidate_id": candidate,
        "percent": 25, "expected_revision": 0,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["revision"] == 1
    assert body["percent"] == 25
    assert body["stable_id"] == stable and body["candidate_id"] == candidate

    # stale and future revisions are both rejected; nothing changes
    for wrong in (0, 2, 99):
        r = client.put("/channels/rel-1", json={
            "stable_id": stable, "candidate_id": candidate,
            "percent": 50, "expected_revision": wrong,
        })
        assert r.status_code == 409, r.text
    assert client.get("/channels/rel-1/resolve",
                      params={"device_id": "d"}).json()["revision"] == 1

    # the exact current revision updates and bumps
    r = client.put("/channels/rel-1", json={
        "stable_id": stable, "candidate_id": candidate,
        "percent": 50, "expected_revision": 1,
    })
    assert r.status_code == 200
    assert r.json()["revision"] == 2
    assert client.get("/channels/rel-1/resolve",
                      params={"device_id": "d"}).json()["percent"] == 50


def test_channel_image_existence_and_trust_gates(client, monkeypatch):
    sk1, pk1 = gen_key()
    sk2, pk2 = gen_key()
    sk3, pk3 = gen_key()
    set_keys(monkeypatch, {"ops": pk1, "ci": pk2, "solo": pk3})
    signers = {"ops": sk1, "ci": sk2}
    stable = finalize_trusted(client, os.urandom(600), signers)
    candidate = finalize_trusted(client, os.urandom(700), signers)

    # either image missing -> 404
    for payload in ({"stable_id": "nope", "candidate_id": candidate},
                    {"stable_id": stable, "candidate_id": "nope"}):
        r = client.put("/channels/g1", json={
            **payload, "percent": 10, "expected_revision": 0,
        })
        assert r.status_code == 404, r.text

    # unsealed image -> 409
    unsealed = create(client, b"raw" * 100)
    client.put(f"/images/{unsealed}/chunks?offset=0", content=b"raw" * 100)
    r = client.put("/channels/g2", json={
        "stable_id": stable, "candidate_id": unsealed,
        "percent": 10, "expected_revision": 0,
    })
    assert r.status_code == 409

    # sealed but never attested -> 409
    sealed_untrusted = finalize(client, os.urandom(128))
    r = client.put("/channels/g3", json={
        "stable_id": sealed_untrusted, "candidate_id": candidate,
        "percent": 10, "expected_revision": 0,
    })
    assert r.status_code == 409

    # attested by a single key: below the trust threshold -> 409
    data = os.urandom(128)
    one_sig = finalize(client, data)
    sha = hashlib.sha256(data).hexdigest()
    client.post(f"/images/{one_sig}/attestations",
                json={"key_id": "solo",
                      "signature": sign(sk3, one_sig, sha, len(data))})
    assert client.get(f"/images/{one_sig}/trust").json()["trusted"] is False
    r = client.put("/channels/g4", json={
        "stable_id": stable, "candidate_id": one_sig,
        "percent": 10, "expected_revision": 0,
    })
    assert r.status_code == 409

    # nothing was persisted by any rejected call
    for name in ("g1", "g2", "g3", "g4"):
        assert client.get(f"/channels/{name}/resolve",
                          params={"device_id": "d"}).status_code == 404


def test_channel_resolve_matches_reference_buckets(client, monkeypatch):
    stable, candidate = make_channel_images(client, monkeypatch)
    assert client.put("/channels/gray", json={
        "stable_id": stable, "candidate_id": candidate,
        "percent": 50, "expected_revision": 0,
    }).status_code == 200

    saw = {"candidate": 0, "stable": 0}
    for i in range(40):
        device_id = f"device-{i}-異常"  # exercise non-ASCII UTF-8 hashing
        r = client.get("/channels/gray/resolve", params={"device_id": device_id})
        assert r.status_code == 200, r.text
        body = r.json()
        bucket = ref_channel_bucket("gray", device_id)
        assert body["bucket"] == bucket
        assert body["revision"] == 1
        if bucket < 50 * 100:
            assert body["image_id"] == candidate
            assert body["reason"] == "candidate"
        else:
            assert body["image_id"] == stable
            assert body["reason"] == "stable"
        saw[body["reason"]] += 1
    assert saw["candidate"] > 0 and saw["stable"] > 0  # both paths exercised

    # repeated resolution of the same device is identical
    again = client.get("/channels/gray/resolve",
                       params={"device_id": "device-0-異常"}).json()
    assert again == client.get("/channels/gray/resolve",
                               params={"device_id": "device-0-異常"}).json()

    # device_id is required
    assert client.get("/channels/gray/resolve").status_code == 422


def test_channel_resolve_percent_extremes(client, monkeypatch):
    stable, candidate = make_channel_images(client, monkeypatch)
    for name, percent in (("never", 0), ("always", 100)):
        assert client.put(f"/channels/{name}", json={
            "stable_id": stable, "candidate_id": candidate,
            "percent": percent, "expected_revision": 0,
        }).status_code == 200
        for i in range(10):
            body = client.get(f"/channels/{name}/resolve",
                              params={"device_id": f"dev-{i}"}).json()
            expected = stable if percent == 0 else candidate
            assert body["image_id"] == expected


def test_channel_resolve_trust_fallback(client, monkeypatch):
    # stable and candidate are attested by *disjoint* key pairs, so key
    # rotation can kill one image's trust without touching the other's.
    sk_s1, pk_s1 = gen_key()
    sk_s2, pk_s2 = gen_key()
    sk_c1, pk_c1 = gen_key()
    sk_c2, pk_c2 = gen_key()
    all_keys = {"ops": pk_s1, "ci": pk_s2, "ops2": pk_c1, "ci2": pk_c2}
    set_keys(monkeypatch, all_keys)
    stable = finalize_trusted(client, os.urandom(300),
                              {"ops": sk_s1, "ci": sk_s2})
    candidate = finalize_trusted(client, os.urandom(300),
                                 {"ops2": sk_c1, "ci2": sk_c2})
    assert client.put("/channels/rot", json={
        "stable_id": stable, "candidate_id": candidate,
        "percent": 100, "expected_revision": 0,  # every device picks candidate
    }).status_code == 200

    def resolve():
        r = client.get("/channels/rot/resolve", params={"device_id": "dev-1"})
        return r.status_code, (r.json() if r.status_code == 200 else None)

    code, body = resolve()
    assert code == 200 and body["image_id"] == candidate
    assert body["reason"] == "candidate"

    # candidate's keys rotated out -> fall back to the trusted stable image
    set_keys(monkeypatch, {"ops": pk_s1, "ci": pk_s2})
    code, body = resolve()
    assert code == 200
    assert body["image_id"] == stable
    assert body["reason"] == "candidate_untrusted_fallback"
    assert body["revision"] == 1

    # stable's keys rotated out -> resolution fails with 409
    set_keys(monkeypatch, {"ops2": pk_c1, "ci2": pk_c2})
    code, _ = resolve()
    assert code == 409

    # no keys at all -> still 409 (stable can never be served untrusted)
    set_keys(monkeypatch, {})
    code, _ = resolve()
    assert code == 409


def test_channel_survives_rebuild_and_resolves_identically(client, monkeypatch):
    stable, candidate = make_channel_images(client, monkeypatch)
    assert client.put("/channels/lts", json={
        "stable_id": stable, "candidate_id": candidate,
        "percent": 37, "expected_revision": 0,
    }).status_code == 200
    before = client.get("/channels/lts/resolve",
                        params={"device_id": "dev-42"}).json()

    # Simulate a container rebuild: a fresh TestClient over the same DB file
    # (TRUSTED_KEYS_JSON unchanged, as it would be via the environment).
    with TestClient(app) as c2:
        after = c2.get("/channels/lts/resolve",
                       params={"device_id": "dev-42"}).json()
        assert after == before  # same image, revision, bucket and reason

        # the stored revision gates updates after the rebuild too
        r = c2.put("/channels/lts", json={
            "stable_id": stable, "candidate_id": candidate,
            "percent": 80, "expected_revision": 0,
        })
        assert r.status_code == 409
        r = c2.put("/channels/lts", json={
            "stable_id": stable, "candidate_id": candidate,
            "percent": 80, "expected_revision": 1,
        })
        assert r.status_code == 200 and r.json()["revision"] == 2
        assert c2.get("/channels/lts/resolve",
                      params={"device_id": "dev-42"}).json()["revision"] == 2

# --------------------------------------------------------------------------- #
# Idle reaping of unsealed tasks
# --------------------------------------------------------------------------- #


def _iso(seconds_ago: float = 0.0) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()


def _set_activity(tid: str, value: str) -> None:
    """Directly set a task's last_activity_at (bypasses the API heartbeat)."""
    import sqlite3 as _sqlite3

    from app.db import db_path

    conn = _sqlite3.connect(db_path())
    try:
        conn.execute(
            "UPDATE images SET last_activity_at = ? WHERE id = ?", (value, tid)
        )
        conn.commit()
    finally:
        conn.close()


def _exists(tid: str) -> bool:
    import sqlite3 as _sqlite3

    from app.db import db_path

    conn = _sqlite3.connect(db_path())
    try:
        return conn.execute(
            "SELECT 1 FROM images WHERE id = ?", (tid,)
        ).fetchone() is not None
    finally:
        conn.close()


def test_cleanup_validation(client):
    assert client.post("/images/cleanup",
                       json={"idle_seconds": 0, "limit": 10}).status_code == 422
    assert client.post("/images/cleanup",
                       json={"idle_seconds": -1, "limit": 10}).status_code == 422
    assert client.post("/images/cleanup",
                       json={"idle_seconds": 10, "limit": 0}).status_code == 422
    assert client.post("/images/cleanup",
                       json={"idle_seconds": 10, "limit": 101}).status_code == 422
    assert client.post("/images/cleanup",
                       json={"idle_seconds": 10, "limit": 5.5}).status_code == 422
    assert client.post("/images/cleanup",
                       json={"idle_seconds": 10}).status_code == 422
    assert client.post("/images/cleanup", json={}).status_code == 422
    assert client.post("/images/cleanup",
                       json={"idle_seconds": 10, "limit": 1}).status_code == 200


def test_cleanup_reaps_only_due_unsealed_and_reports_bytes(client):
    # idle unsealed task holding 300 bytes (two disjoint runs)
    idle = create(client, b"i" * 1000)
    client.put(f"/images/{idle}/chunks?offset=0", content=b"i" * 100)
    client.put(f"/images/{idle}/chunks?offset=500", content=b"i" * 200)
    _set_activity(idle, _iso(seconds_ago=100))

    # unsealed but touched recently: must survive
    fresh = create(client, b"f" * 10)
    client.put(f"/images/{fresh}/chunks?offset=0", content=b"f" * 5)

    # sealed but idle since before the cutoff: must survive
    sealed = finalize(client, b"s" * 256)
    _set_activity(sealed, _iso(seconds_ago=1000))

    r = client.post("/images/cleanup", json={"idle_seconds": 60, "limit": 10})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["deleted"] == 1
    assert body["deleted_ids"] == [idle]
    assert body["released_bytes"] == 300   # disjoint runs, no double counting

    assert not _exists(idle)
    assert client.get(f"/images/{idle}").status_code == 404
    assert _exists(fresh)
    assert _exists(sealed)
    # reaped task's chunks are gone too
    import sqlite3 as _sqlite3
    from app.db import db_path
    conn = _sqlite3.connect(db_path())
    try:
        assert conn.execute(
            "SELECT COUNT(*) FROM chunks WHERE image_id = ?", (idle,)
        ).fetchone()[0] == 0
    finally:
        conn.close()


def test_cleanup_limit_order_and_repeated_calls(client):
    # Four idle tasks with distinct activity times; ids are deliberately not
    # sorted the same way as the timestamps (they are random hex anyway, but
    # the assertion is against last_activity_at, id order).
    tasks = []
    ages = (400, 200, 300, 100)
    for age in ages:
        tid = create(client, b"x" * 4)
        client.put(f"/images/{tid}/chunks?offset=0", content=b"x")
        _set_activity(tid, _iso(seconds_ago=age))
        tasks.append((tid, age))
    # one fresh task never selected
    young = create(client, b"y" * 2)
    _set_activity(young, _iso())

    expect_order = [tid for tid, age in sorted(tasks, key=lambda t: (-t[1], t[0]))]

    r = client.post("/images/cleanup", json={"idle_seconds": 50, "limit": 2})
    assert r.json()["deleted_ids"] == expect_order[:2]
    r = client.post("/images/cleanup", json={"idle_seconds": 50, "limit": 2})
    assert r.json()["deleted_ids"] == expect_order[2:]
    r = client.post("/images/cleanup", json={"idle_seconds": 50, "limit": 10})
    assert r.json()["deleted_ids"] == []
    assert r.json()["released_bytes"] == 0
    assert _exists(young)


def test_cleanup_order_tie_breaks_on_id(client):
    t1 = create(client, b"a" * 2)
    t2 = create(client, b"b" * 2)
    stamp = _iso(seconds_ago=500)
    _set_activity(t1, stamp)
    _set_activity(t2, stamp)
    r = client.post("/images/cleanup", json={"idle_seconds": 10, "limit": 1})
    assert r.json()["deleted_ids"] == [min(t1, t2)]
    r = client.post("/images/cleanup", json={"idle_seconds": 10, "limit": 1})
    assert r.json()["deleted_ids"] == [max(t1, t2)]


def test_successful_upload_refreshes_activity(client):
    data = bytes(range(10))
    tid = create(client, data)
    _set_activity(tid, _iso(seconds_ago=1000))

    # a fresh successful upload refreshes: no longer due
    assert client.put(f"/images/{tid}/chunks?offset=0",
                      content=data).status_code == 200
    r = client.post("/images/cleanup", json={"idle_seconds": 60, "limit": 10})
    assert r.json()["deleted_ids"] == []

    # an exact duplicate upload also refreshes
    _set_activity(tid, _iso(seconds_ago=1000))
    assert client.put(f"/images/{tid}/chunks?offset=0",
                      content=data).status_code == 200
    r = client.post("/images/cleanup", json={"idle_seconds": 60, "limit": 10})
    assert r.json()["deleted_ids"] == []


def test_rejected_uploads_do_not_refresh(client):
    data = bytes(range(10))
    tid = create(client, data)
    client.put(f"/images/{tid}/chunks?offset=0", content=data)

    # out-of-range chunk -> 400, activity untouched
    _set_activity(tid, _iso(seconds_ago=1000))
    assert client.put(f"/images/{tid}/chunks?offset=9",
                      content=b"zzz").status_code == 400
    r = client.post("/images/cleanup", json={"idle_seconds": 60, "limit": 10})
    assert r.json()["deleted_ids"] == [tid]

    # conflicting bytes -> 409, activity untouched (fresh task to upload into)
    other = create(client, b"a" * 8)
    client.put(f"/images/{other}/chunks?offset=0", content=b"a" * 8)
    _set_activity(other, _iso(seconds_ago=1000))
    assert client.put(f"/images/{other}/chunks?offset=0",
                      content=b"b" * 4).status_code == 409
    r = client.post("/images/cleanup", json={"idle_seconds": 60, "limit": 10})
    assert other in r.json()["deleted_ids"]

    # writing to a finalized (sealed) task -> 409, no refresh
    sealed = finalize(client, b"q" * 8)
    _set_activity(sealed, _iso(seconds_ago=1000))
    assert client.put(f"/images/{sealed}/chunks?offset=0",
                      content=b"q").status_code == 409
    r = client.post("/images/cleanup", json={"idle_seconds": 60, "limit": 10})
    # sealed tasks are never reaped regardless of age/activity
    assert r.json()["deleted_ids"] == []
    assert _exists(sealed)


def test_reaped_task_returns_404_everywhere_afterward(client):
    tid = create(client, b"z" * 4)
    client.put(f"/images/{tid}/chunks?offset=0", content=b"zz")
    _set_activity(tid, _iso(seconds_ago=1000))
    assert client.post("/images/cleanup",
                       json={"idle_seconds": 10, "limit": 1}).json()["deleted"] == 1

    assert client.get(f"/images/{tid}").status_code == 404
    assert client.put(f"/images/{tid}/chunks?offset=0",
                      content=b"zz").status_code == 404
    assert client.post(f"/images/{tid}/finalize").status_code == 404
    assert client.get(f"/images/{tid}/content").status_code == 404
    assert client.get(f"/images/{tid}/trust").status_code == 404


def test_cleanup_preserves_attestations_and_channels(client, monkeypatch):
    sk1, pk1 = gen_key()
    sk2, pk2 = gen_key()
    set_keys(monkeypatch, {"ops": pk1, "ci": pk2})
    stable = finalize_trusted(client, b"A" * 64, {"ops": sk1, "ci": sk2})
    candidate = finalize_trusted(client, b"B" * 64, {"ops": sk1, "ci": sk2})
    assert client.put("/channels/keep", json={
        "stable_id": stable, "candidate_id": candidate,
        "percent": 100, "expected_revision": 0,
    }).status_code == 200

    # sealed ages ago, plus a stray idle unsealed task
    _set_activity(stable, _iso(seconds_ago=10**8))
    _set_activity(candidate, _iso(seconds_ago=10**8))
    stray = create(client, b"x" * 8)
    _set_activity(stray, _iso(seconds_ago=10**8))

    r = client.post("/images/cleanup", json={"idle_seconds": 1, "limit": 100})
    deleted = r.json()["deleted_ids"]
    assert stray in deleted
    assert stable not in deleted and candidate not in deleted

    # sealed images, their signatures and the channel are all intact
    body = client.get("/channels/keep/resolve",
                      params={"device_id": "d1"}).json()
    assert body["image_id"] == candidate  # percent=100, candidate still trusted
    assert client.get(f"/images/{stable}/trust").json()["trusted"] is True
    assert client.get(f"/images/{stable}/content").content == b"A" * 64


def test_cleanup_is_atomic_on_failure(client, monkeypatch):
    """If the deletes cannot all complete, nothing at all is removed."""
    import sqlite3 as _sqlite3

    from app.db import db_path

    ids = []
    for _ in range(3):
        tid = create(client, b"m" * 8)
        client.put(f"/images/{tid}/chunks?offset=0", content=b"m" * 8)
        _set_activity(tid, _iso(seconds_ago=1000))
        ids.append(tid)

    # A trigger that aborts ANY image deletion: a normal (non-TEMP) trigger
    # fires for every connection, so the app's cleanup statement hits it.
    # RAISE(ROLLBACK) unwinds the whole transaction, chunk deletes included.
    admin = _sqlite3.connect(db_path())
    try:
        admin.execute(
            "CREATE TRIGGER boom_cleanup BEFORE DELETE ON images "
            "BEGIN SELECT RAISE(ROLLBACK, 'injected cleanup failure'); END"
        )
        admin.commit()
        # TestClient (raise_server_exceptions=True, the default) surfaces the
        # injected ROLLBACK error instead of rendering a 500 response.
        with pytest.raises(Exception):
            client.post("/images/cleanup", json={"idle_seconds": 10, "limit": 10})
    finally:
        admin.execute("DROP TRIGGER IF EXISTS boom_cleanup")
        admin.commit()
        admin.close()

    # No partial deletion: every task (and its chunks) survived the rollback.
    for tid in ids:
        assert _exists(tid)
        assert client.get(f"/images/{tid}").status_code == 200
    admin = _sqlite3.connect(db_path())
    try:
        kept = admin.execute(
            "SELECT COUNT(*) FROM chunks WHERE image_id IN ({})".format(
                ",".join("?" * len(ids))
            ),
            ids,
        ).fetchone()[0]
        assert kept == 3
    finally:
        admin.close()

    # the next (un-injected) cleanup succeeds normally
    r = client.post("/images/cleanup", json={"idle_seconds": 10, "limit": 10})
    assert sorted(r.json()["deleted_ids"]) == sorted(ids)


def test_cleanup_concurrent_with_uploads_and_finalizes(client):
    """Commit order decides: tasks that commit an upload/finalize first are
    judged by their newest state; tasks cleanup commits first are 404 later.
    No request may 500 and the final state must be internally consistent."""
    import concurrent.futures

    n = 12
    data = b"".join(bytes([i % 256]) * 4 for i in range(64))  # 256 bytes
    ids = [create(client, data) for _ in range(n)]
    for tid in ids:
        _set_activity(tid, _iso(seconds_ago=1000))

    stop = {"go": False}

    def uploader(tid):
        # full image in one chunk; races cleanup and the finalizers
        r = client.put(f"/images/{tid}/chunks?offset=0", content=data)
        return r.status_code

    def finalizer(tid):
        return client.post(f"/images/{tid}/finalize").status_code

    def reaper():
        codes = []
        while not stop["go"]:
            r = client.post("/images/cleanup",
                            json={"idle_seconds": 60, "limit": 3})
            codes.append(r.status_code)
        return codes

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        reap_fut = pool.submit(reaper)
        up_futs = [pool.submit(uploader, t) for t in ids]
        fin_futs = [pool.submit(finalizer, t) for t in ids]
        up_codes = [f.result() for f in up_futs]
        fin_codes = [f.result() for f in fin_futs]
        stop["go"] = True
        reap_codes = reap_fut.result()

    # No server errors anywhere; uploads win (200) or lose to reaping (404).
    assert set(up_codes) <= {200, 404}, up_codes
    assert set(fin_codes) <= {200, 404, 409}, fin_codes
    assert all(c == 200 for c in reap_codes), reap_codes

    survivors = []
    for tid in ids:
        if not _exists(tid):
            # cleanup committed first: every later operation is 404
            assert client.get(f"/images/{tid}").status_code == 404
            assert client.put(f"/images/{tid}/chunks?offset=0",
                              content=data).status_code == 404
            assert client.post(f"/images/{tid}/finalize").status_code == 404
            continue
        state = client.get(f"/images/{tid}").json()
        if state["finalized"]:
            # finalized tasks are sealed and must never be reaped later
            assert client.get(f"/images/{tid}/content").content == data
        else:
            # unsealed survivor: its upload must have landed consistently
            # (no torn writes); cover it fully and seal it — it must then be
            # immune to reaping just like the finalized tasks above.
            assert state["bytes_received"] == len(data)
            assert client.put(f"/images/{tid}/chunks?offset=0",
                              content=data).status_code == 200
            assert client.post(f"/images/{tid}/finalize").status_code == 200
        survivors.append(tid)

    # All surviving tasks are now sealed.  Age them far past any cutoff and
    # confirm cleanup never removes sealed images, even though other (foreign
    # to this test) idle unsealed tasks in the shared DB may be reaped.
    for tid in survivors:
        _set_activity(tid, _iso(seconds_ago=10**8))
    r = client.post("/images/cleanup",
                    json={"idle_seconds": 1, "limit": 100})
    assert all(tid not in r.json()["deleted_ids"] for tid in survivors)
    for tid in survivors:
        assert _exists(tid)


def test_old_database_migrates_and_backfills_from_created_at(tmp_path):
    """A DB written by the pre-cleanup schema (no last_activity_at) is
    upgraded at startup: the column appears, is NOT NULL, and every legacy
    row gets last_activity_at = created_at, so legacy idle tasks are
    immediately reapable and legacy sealed images keep working."""
    import sqlite3 as _sqlite3

    from app.db import init_db
    from app.main import app as app_module

    old_db = tmp_path / "old.db"
    created = "2020-01-02T03:04:05.000000+00:00"
    conn = _sqlite3.connect(old_db)
    try:
        conn.execute(
            "CREATE TABLE images (id TEXT PRIMARY KEY, total_size INTEGER "
            "NOT NULL, sha256 TEXT NOT NULL, finalized INTEGER NOT NULL "
            "DEFAULT 0, created_at TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO images (id, total_size, sha256, finalized, created_at) "
            "VALUES ('idle1', 4, 'ab', 0, ?)",
            (created,),
        )
        conn.execute(
            "INSERT INTO images (id, total_size, sha256, finalized, created_at) "
            "VALUES ('idle2', 4, 'cd', 0, ?)",
            (created,),
        )
        conn.commit()
    finally:
        conn.close()

    init_db(str(old_db))

    conn = _sqlite3.connect(old_db)
    conn.row_factory = _sqlite3.Row
    try:
        notnull = [
            r for r in conn.execute("PRAGMA table_info(images)")
            if r["name"] == "last_activity_at"
        ]
        assert len(notnull) == 1 and notnull[0]["notnull"] == 1
        rows = conn.execute(
            "SELECT id, created_at, last_activity_at FROM images ORDER BY id"
        ).fetchall()
        assert [r["id"] for r in rows] == ["idle1", "idle2"]
        assert all(r["last_activity_at"] == r["created_at"] == created for r in rows)
    finally:
        conn.close()

    # Service works against the migrated file through a TestClient bound to it.
    old_env = os.environ.get("IMAGE_DB_PATH")
    os.environ["IMAGE_DB_PATH"] = str(old_db)
    try:
        with TestClient(app_module) as c:
            r = c.post("/images/cleanup", json={"idle_seconds": 1, "limit": 10})
            assert r.status_code == 200
            assert sorted(r.json()["deleted_ids"]) == ["idle1", "idle2"]
    finally:
        if old_env is None:
            os.environ.pop("IMAGE_DB_PATH", None)
        else:
            os.environ["IMAGE_DB_PATH"] = old_env


# --------------------------------------------------------------------------- #
# Installation receipts & audit
# --------------------------------------------------------------------------- #


def make_named_channel(client, monkeypatch, name, percent=100):
    """Create a channel over two freshly trusted images; return their ids."""
    stable, candidate = make_channel_images(client, monkeypatch)
    r = client.put(f"/channels/{name}", json={
        "stable_id": stable, "candidate_id": candidate,
        "percent": percent, "expected_revision": 0,
    })
    assert r.status_code == 200, r.text
    return stable, candidate


def post_receipt(client, name, device_id, seq, status="success",
                 installed_id=None, revision=1):
    payload = {"device_id": device_id, "revision": revision, "seq": seq,
               "status": status}
    if installed_id is not None:
        payload["installed_id"] = installed_id
    return client.post(f"/channels/{name}/receipts", json=payload)


def audit(client, name):
    r = client.get(f"/channels/{name}/installation-audit")
    assert r.status_code == 200, r.text
    return r.json()


def _receipt_rows(name):
    """All stored receipt rows of a channel, straight from SQLite."""
    import sqlite3 as _sqlite3

    from app.db import db_path

    conn = _sqlite3.connect(db_path())
    conn.row_factory = _sqlite3.Row
    try:
        return conn.execute(
            "SELECT device_id, seq, revision, status, installed_id, "
            "expected_id FROM receipts WHERE channel = ? ORDER BY device_id",
            (name,),
        ).fetchall()
    finally:
        conn.close()


def test_receipt_validation(client, monkeypatch):
    _, candidate = make_named_channel(client, monkeypatch, "rc-val")

    def code(payload, name="rc-val"):
        return client.post(f"/channels/{name}/receipts",
                           json=payload).status_code

    base = {"device_id": "d1", "revision": 1, "seq": 1,
            "status": "success", "installed_id": candidate}
    assert code(base) == 200

    # seq must be a positive integer
    for bad in (0, -1, 1.5, "x"):
        assert code({**base, "seq": bad}) == 422
    # revision must be a positive integer
    for bad in (0, -2, 1.5, "x"):
        assert code({**base, "revision": bad}) == 422
    # status must be exactly success/failed
    assert code({**base, "status": "ok"}) == 422
    assert code({**base, "status": "SUCCESS"}) == 422
    # success requires a non-empty installed_id
    missing = {**base, "seq": 2}
    del missing["installed_id"]
    assert code(missing) == 422
    assert code({**base, "seq": 2, "installed_id": None}) == 422
    assert code({**base, "seq": 2, "installed_id": ""}) == 422
    assert code({**base, "seq": 2, "installed_id": "x" * 65}) == 422
    # failed must not carry an installed_id
    assert code({**base, "seq": 2, "status": "failed",
                 "installed_id": candidate}) == 422
    assert code({**base, "seq": 2, "status": "failed",
                 "installed_id": ""}) == 422
    # missing fields / empty device_id
    assert code({}) == 422
    assert code({**base, "device_id": ""}) == 422
    # failed without installed_id (absent or explicit null) is accepted
    assert code({"device_id": "d2", "revision": 1, "seq": 1,
                 "status": "failed"}) == 200
    r = client.post("/channels/rc-val/receipts",
                    json={"device_id": "d2", "revision": 1, "seq": 1,
                          "status": "failed", "installed_id": None})
    assert r.status_code == 200 and r.json()["stored"] == "unchanged"
    # unknown channel -> 404 on both endpoints
    assert code(base, name="rc-nope") == 404
    assert client.get("/channels/rc-nope/installation-audit").status_code == 404


def test_receipt_flow_and_audit(client, monkeypatch):
    stable, candidate = make_named_channel(client, monkeypatch, "rc-flow",
                                           percent=100)

    # percent=100: every device resolves to the candidate image
    r = post_receipt(client, "rc-flow", "dev-1", 1, "success", candidate)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["expected_id"] == candidate
    assert body["matched"] is True
    assert body["stored"] == "recorded"
    assert body["revision"] == 1 and body["seq"] == 1

    # success but installed something else -> deviation
    r = post_receipt(client, "rc-flow", "dev-2", 1, "success", stable)
    assert r.status_code == 200
    assert r.json()["expected_id"] == candidate
    assert r.json()["matched"] is False

    # failed install: no installed_id
    r = post_receipt(client, "rc-flow", "dev-3", 1, "failed")
    assert r.status_code == 200
    assert r.json()["installed_id"] is None
    assert r.json()["matched"] is False

    body = audit(client, "rc-flow")
    assert body["revision"] == 1
    assert body["success_matched"] == 1
    assert body["success_deviated"] == 1
    assert body["failed"] == 1


def test_receipt_expected_follows_resolution_rules(client, monkeypatch):
    # percent=0: every device resolves to the stable image
    stable, candidate = make_named_channel(client, monkeypatch, "rc-exp0",
                                           percent=0)
    r = post_receipt(client, "rc-exp0", "dev-1", 1, "success", stable)
    assert r.json()["expected_id"] == stable

    # percent=50: the frozen expected_id follows the reference bucket rule
    stable, candidate = make_named_channel(client, monkeypatch, "rc-exp50",
                                           percent=50)
    saw = {stable: 0, candidate: 0}
    for i in range(20):
        dev = f"dev-{i}-核"
        r = post_receipt(client, "rc-exp50", dev, 1, "failed")
        assert r.status_code == 200, r.text
        expected = (candidate
                    if ref_channel_bucket("rc-exp50", dev) < 50 * 100
                    else stable)
        assert r.json()["expected_id"] == expected
        saw[expected] += 1
    assert saw[stable] > 0 and saw[candidate] > 0  # both paths exercised


def test_receipt_revision_gate_and_cross_revision_seq(client, monkeypatch):
    stable, candidate = make_named_channel(client, monkeypatch, "rc-rev",
                                           percent=100)

    # stale and future revisions are both rejected; nothing is stored
    assert post_receipt(client, "rc-rev", "dev-1", 1, "success", candidate,
                        revision=2).status_code == 409
    assert post_receipt(client, "rc-rev", "dev-1", 1, "success", candidate,
                        revision=99).status_code == 409
    assert _receipt_rows("rc-rev") == []

    assert post_receipt(client, "rc-rev", "dev-1", 1, "success",
                        candidate).status_code == 200

    # bump the channel to revision 2
    r = client.put("/channels/rc-rev", json={
        "stable_id": stable, "candidate_id": candidate,
        "percent": 100, "expected_revision": 1,
    })
    assert r.status_code == 200 and r.json()["revision"] == 2

    # a delayed report for the old revision is rejected and overwrites nothing
    assert post_receipt(client, "rc-rev", "dev-1", 2, "failed",
                        revision=1).status_code == 409
    rows = _receipt_rows("rc-rev")
    assert len(rows) == 1
    assert rows[0]["revision"] == 1 and rows[0]["status"] == "success"

    # the audit counts only the current revision
    body = audit(client, "rc-rev")
    assert body["revision"] == 2
    assert (body["success_matched"], body["success_deviated"],
            body["failed"]) == (0, 0, 0)

    # seq is monotonic across revisions: reusing seq 1 under revision 2
    # conflicts with the stored row; a larger seq is accepted and replaces it
    assert post_receipt(client, "rc-rev", "dev-1", 1, "failed",
                        revision=2).status_code == 409
    r = post_receipt(client, "rc-rev", "dev-1", 2, "failed", revision=2)
    assert r.status_code == 200 and r.json()["stored"] == "replaced"
    body = audit(client, "rc-rev")
    assert body["failed"] == 1 and body["success_matched"] == 0


def test_receipt_seq_rules(client, monkeypatch):
    stable, candidate = make_named_channel(client, monkeypatch, "rc-seq",
                                           percent=100)

    r = post_receipt(client, "rc-seq", "dev-1", 5, "success", candidate)
    assert r.status_code == 200 and r.json()["stored"] == "recorded"

    # smaller seq -> 409
    assert post_receipt(client, "rc-seq", "dev-1", 4, "success",
                        candidate).status_code == 409
    # same seq, different content -> 409
    assert post_receipt(client, "rc-seq", "dev-1", 5, "failed").status_code == 409
    assert post_receipt(client, "rc-seq", "dev-1", 5, "success",
                        stable).status_code == 409
    # same seq, same content -> idempotent, returns the stored row
    r = post_receipt(client, "rc-seq", "dev-1", 5, "success", candidate)
    assert r.status_code == 200
    assert r.json()["stored"] == "unchanged"
    assert r.json()["expected_id"] == candidate
    # larger seq replaces; the audit then reflects only the newest receipt
    r = post_receipt(client, "rc-seq", "dev-1", 6, "failed")
    assert r.status_code == 200 and r.json()["stored"] == "replaced"
    body = audit(client, "rc-seq")
    assert body["success_matched"] == 0 and body["failed"] == 1
    # the superseded content at the old seq stays a conflict
    assert post_receipt(client, "rc-seq", "dev-1", 5, "success",
                        candidate).status_code == 409
    # independent devices have independent sequences
    assert post_receipt(client, "rc-seq", "dev-2", 1, "success",
                        candidate).status_code == 200


def test_receipt_stable_untrusted_rejected(client, monkeypatch):
    # disjoint key pairs per image, so rotation kills one image's trust only
    sk_s1, pk_s1 = gen_key()
    sk_s2, pk_s2 = gen_key()
    sk_c1, pk_c1 = gen_key()
    sk_c2, pk_c2 = gen_key()
    all_keys = {"ops": pk_s1, "ci": pk_s2, "ops2": pk_c1, "ci2": pk_c2}
    set_keys(monkeypatch, all_keys)
    stable = finalize_trusted(client, os.urandom(300), {"ops": sk_s1, "ci": sk_s2})
    candidate = finalize_trusted(client, os.urandom(300),
                                 {"ops2": sk_c1, "ci2": sk_c2})
    assert client.put("/channels/rc-untrusted", json={
        "stable_id": stable, "candidate_id": candidate,
        "percent": 100, "expected_revision": 0,
    }).status_code == 200

    # stable loses trust -> receipts are rejected and nothing is stored
    set_keys(monkeypatch, {"ops2": pk_c1, "ci2": pk_c2})
    assert post_receipt(client, "rc-untrusted", "dev-1", 1, "success",
                        candidate).status_code == 409
    assert _receipt_rows("rc-untrusted") == []
    body = audit(client, "rc-untrusted")
    assert (body["success_matched"], body["success_deviated"],
            body["failed"]) == (0, 0, 0)

    # trust restored -> the very same report is accepted
    set_keys(monkeypatch, all_keys)
    r = post_receipt(client, "rc-untrusted", "dev-1", 1, "success", candidate)
    assert r.status_code == 200 and r.json()["expected_id"] == candidate


def test_receipt_expected_frozen_despite_later_changes(client, monkeypatch):
    sk_s1, pk_s1 = gen_key()
    sk_s2, pk_s2 = gen_key()
    sk_c1, pk_c1 = gen_key()
    sk_c2, pk_c2 = gen_key()
    all_keys = {"ops": pk_s1, "ci": pk_s2, "ops2": pk_c1, "ci2": pk_c2}
    set_keys(monkeypatch, all_keys)
    stable = finalize_trusted(client, os.urandom(300), {"ops": sk_s1, "ci": sk_s2})
    candidate = finalize_trusted(client, os.urandom(300),
                                 {"ops2": sk_c1, "ci2": sk_c2})
    assert client.put("/channels/rc-frozen", json={
        "stable_id": stable, "candidate_id": candidate,
        "percent": 100, "expected_revision": 0,
    }).status_code == 200

    # candidate trusted at acceptance: expected_id freezes to the candidate
    r = post_receipt(client, "rc-frozen", "dev-1", 1, "success", candidate)
    assert r.json()["expected_id"] == candidate

    # candidate's keys rotated out afterwards: live resolution would now
    # fall back to stable, but the saved expected_id is NOT rewritten
    set_keys(monkeypatch, {"ops": pk_s1, "ci": pk_s2})
    body = audit(client, "rc-frozen")
    assert body["success_matched"] == 1 and body["success_deviated"] == 0

    # an idempotent replay returns the frozen row exactly as stored
    r = post_receipt(client, "rc-frozen", "dev-1", 1, "success", candidate)
    assert r.status_code == 200
    assert r.json()["stored"] == "unchanged"
    assert r.json()["expected_id"] == candidate

    # a NEW receipt now resolves to the stable fallback
    r = post_receipt(client, "rc-frozen", "dev-2", 1, "success", stable)
    assert r.json()["expected_id"] == stable
    assert audit(client, "rc-frozen")["success_matched"] == 2

    # a policy change bumps the revision; old receipts keep their frozen
    # expected_id and drop out of the audit
    set_keys(monkeypatch, all_keys)
    r = client.put("/channels/rc-frozen", json={
        "stable_id": stable, "candidate_id": candidate,
        "percent": 0, "expected_revision": 1,
    })
    assert r.status_code == 200 and r.json()["revision"] == 2
    body = audit(client, "rc-frozen")
    assert body["revision"] == 2
    assert (body["success_matched"], body["success_deviated"],
            body["failed"]) == (0, 0, 0)
    frozen = {row["device_id"]: row["expected_id"]
              for row in _receipt_rows("rc-frozen")}
    assert frozen == {"dev-1": candidate, "dev-2": stable}


def test_receipts_persist_across_restart(client, monkeypatch):
    _, candidate = make_named_channel(client, monkeypatch, "rc-lts",
                                      percent=100)
    post_receipt(client, "rc-lts", "dev-1", 3, "success", candidate)
    post_receipt(client, "rc-lts", "dev-2", 1, "failed")

    # Simulate a container rebuild: a fresh TestClient over the same DB file.
    with TestClient(app) as c2:
        body = c2.get("/channels/rc-lts/installation-audit").json()
        assert body["success_matched"] == 1 and body["failed"] == 1
        # idempotent replay is still recognized after the rebuild
        r = c2.post("/channels/rc-lts/receipts", json={
            "device_id": "dev-1", "revision": 1, "seq": 3,
            "status": "success", "installed_id": candidate,
        })
        assert r.status_code == 200 and r.json()["stored"] == "unchanged"
        # and the seq guard survived too
        r = c2.post("/channels/rc-lts/receipts", json={
            "device_id": "dev-1", "revision": 1, "seq": 2,
            "status": "success", "installed_id": candidate,
        })
        assert r.status_code == 409


def test_receipts_race_channel_update_by_commit_order(client, monkeypatch):
    """Receipts and channel updates serialize on the same per-channel lock
    and SQLite write transactions: a receipt either commits before the
    update (stored under the old revision) or after it (409 stale
    revision).  No 500s; delayed old-revision reports never land."""
    import concurrent.futures

    stable, candidate = make_named_channel(client, monkeypatch, "rc-race",
                                           percent=100)

    def report(i):
        return client.post("/channels/rc-race/receipts", json={
            "device_id": f"dev-{i}", "revision": 1, "seq": 1,
            "status": "success", "installed_id": candidate,
        }).status_code

    def bump():
        return client.put("/channels/rc-race", json={
            "stable_id": stable, "candidate_id": candidate,
            "percent": 100, "expected_revision": 1,
        }).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=9) as pool:
        futs = [pool.submit(report, i) for i in range(16)]
        bump_fut = pool.submit(bump)
        codes = [f.result() for f in futs]
        assert bump_fut.result() == 200

    assert set(codes) <= {200, 409}, codes
    stored = _receipt_rows("rc-race")
    # every stored receipt was accepted under revision 1; every 200 reporter
    # has exactly one row; 409 reporters never landed
    assert all(r["revision"] == 1 for r in stored)
    assert len(stored) == codes.count(200)

    # the audit counts only the current revision (2): nothing
    body = audit(client, "rc-race")
    assert body["revision"] == 2
    assert (body["success_matched"], body["success_deviated"],
            body["failed"]) == (0, 0, 0)

    # delayed old-revision reports are rejected and change nothing
    assert post_receipt(client, "rc-race", "dev-late", 1, "success",
                        candidate, revision=1).status_code == 409
    assert len(_receipt_rows("rc-race")) == len(stored)


# --------------------------------------------------------------------------- #
# Canary risk circuit breaker
# --------------------------------------------------------------------------- #


def arm_safety(client, name, expected_revision, min_reports, max_bad_percent):
    return client.put(f"/channels/{name}/safety", json={
        "expected_revision": expected_revision,
        "min_reports": min_reports,
        "max_bad_percent": max_bad_percent,
    })


def safety(client, name):
    r = client.get(f"/channels/{name}/safety")
    assert r.status_code == 200, r.text
    return r.json()


def test_safety_validation_and_missing(client, monkeypatch):
    make_named_channel(client, monkeypatch, "sf-val", percent=100)

    def code(payload, name="sf-val"):
        return client.put(f"/channels/{name}/safety", json=payload).status_code

    base = {"expected_revision": 1, "min_reports": 5, "max_bad_percent": 10}
    assert code(base) == 200
    # range checks on all three fields -> 422
    assert code({**base, "min_reports": 0}) == 422
    assert code({**base, "min_reports": 1001}) == 422
    assert code({**base, "min_reports": 1.5}) == 422
    assert code({**base, "max_bad_percent": -1}) == 422
    assert code({**base, "max_bad_percent": 101}) == 422
    assert code({**base, "expected_revision": 0}) == 422
    assert code({**base, "expected_revision": -1}) == 422
    assert code({}) == 422

    # unknown channel -> 404 on PUT and GET
    assert code(base, name="sf-nope") == 404
    assert client.get("/channels/sf-nope/safety").status_code == 404

    # channel without an armed rule -> 404 on GET
    stable, candidate = make_named_channel(client, monkeypatch, "sf-none",
                                           percent=100)
    assert client.get("/channels/sf-none/safety").status_code == 404

    # expected_revision mismatch -> 409 and nothing armed
    assert client.put("/channels/sf-none/safety", json={
        "expected_revision": 2, "min_reports": 5, "max_bad_percent": 10,
    }).status_code == 409
    assert client.put("/channels/sf-none/safety", json={
        "expected_revision": 99, "min_reports": 5, "max_bad_percent": 10,
    }).status_code == 409
    assert client.get("/channels/sf-none/safety").status_code == 404


def test_safety_arm_get_and_idempotence(client, monkeypatch):
    make_named_channel(client, monkeypatch, "sf-arm", percent=100)

    r = arm_safety(client, "sf-arm", 1, 4, 10)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["stored"] == "armed"
    assert body["revision"] == 1 and body["rule_revision"] == 1
    assert body["min_reports"] == 4 and body["max_bad_percent"] == 10
    assert body["reports"] == 0 and body["anomalies"] == 0
    assert body["tripped"] is False and body["status"] == "monitoring"

    # GET mirrors the armed rule
    assert safety(client, "sf-arm") == {k: body[k] for k in (
        "name", "revision", "rule_revision", "min_reports",
        "max_bad_percent", "reports", "anomalies", "tripped", "status")}

    # identical resubmission at the same revision is idempotent
    r = arm_safety(client, "sf-arm", 1, 4, 10)
    assert r.status_code == 200 and r.json()["stored"] == "unchanged"
    assert r.json()["tripped"] is False

    # changing either rule parameter at the SAME revision conflicts 409
    assert arm_safety(client, "sf-arm", 1, 5, 10).status_code == 409
    assert arm_safety(client, "sf-arm", 1, 4, 20).status_code == 409
    assert arm_safety(client, "sf-arm", 1, 5, 20).status_code == 409
    # rule untouched
    body = safety(client, "sf-arm")
    assert body["min_reports"] == 4 and body["max_bad_percent"] == 10


def test_safety_trips_at_strict_threshold_and_latches(client, monkeypatch):
    """min_reports=2, max_bad_percent=50: 1 bad of 2 is exactly 50% (no trip,
    strictly greater); the second anomaly crosses it; the latch then sticks
    even when better receipts overwrite the bad ones."""
    stable, candidate = make_named_channel(client, monkeypatch, "sf-thr",
                                           percent=100)
    assert arm_safety(client, "sf-thr", 1, 2, 50).status_code == 200

    # one good, one bad: 1*100 == 2*50 -> NOT tripped (strict inequality)
    assert post_receipt(client, "sf-thr", "dev-good", 1, "success",
                        candidate).status_code == 200
    r = post_receipt(client, "sf-thr", "dev-bad", 1, "failed")
    assert r.status_code == 200
    assert r.json()["circuit_breaker_tripped"] is False
    body = safety(client, "sf-thr")
    assert body["reports"] == 2 and body["anomalies"] == 1
    assert body["tripped"] is False and body["status"] == "monitoring"

    # second anomaly: 2*100 > 2*50 -> latches
    assert post_receipt(client, "sf-thr", "dev-bad2", 2, "failed"
                        ).json()["circuit_breaker_tripped"] is True
    body = safety(client, "sf-thr")
    assert body["reports"] == 3 and body["anomalies"] == 2
    assert body["tripped"] is True and body["status"] == "tripped"

    # resolve now rolls every canary bucket back to the stable image and
    # marks the risk rollback; percent/revision in the response are unchanged
    body = client.get("/channels/sf-thr/resolve",
                      params={"device_id": "anyone"}).json()
    assert body["image_id"] == stable
    assert body["reason"] == "risk_circuit_breaker_fallback"
    assert body["percent"] == 100 and body["revision"] == 1

    # a new receipt after the trip freezes the stable image as expected...
    r = post_receipt(client, "sf-thr", "dev-new", 1, "success", candidate)
    assert r.status_code == 200
    assert r.json()["expected_id"] == stable
    assert r.json()["matched"] is False
    assert r.json()["circuit_breaker_tripped"] is True

    # ...and overwrite the two failed devices with clean candidate-matched
    # reports: the latch does NOT clear ("receipt overwrites do not lift it")
    for dev, seq in (("dev-bad", 2), ("dev-bad2", 3)):
        r = post_receipt(client, "sf-thr", dev, seq, "success", candidate)
        assert r.status_code == 200 and r.json()["expected_id"] == stable
        assert r.json()["circuit_breaker_tripped"] is True
    body = safety(client, "sf-thr")
    assert body["tripped"] is True and body["status"] == "tripped"

    # resolution keeps serving the rollback with the candidate still trusted
    assert client.get("/channels/sf-thr/resolve",
                      params={"device_id": "x"}).status_code == 200


def test_safety_min_reports_gate_and_zero_percent(client, monkeypatch):
    make_named_channel(client, monkeypatch, "sf-gate", percent=100)
    # min_reports=3: a fully bad sample of 2 must not trip yet
    assert arm_safety(client, "sf-gate", 1, 3, 10).status_code == 200
    for dev in ("d1", "d2"):
        r = post_receipt(client, "sf-gate", dev, 1, "failed")
        assert r.json()["circuit_breaker_tripped"] is False
    body = safety(client, "sf-gate")
    assert body["reports"] == 2 and body["anomalies"] == 2
    assert body["tripped"] is False
    # third anomaly crosses min_reports and 200 > 3*10
    assert post_receipt(client, "sf-gate", "d3", 1, "failed"
                        ).json()["circuit_breaker_tripped"] is True
    assert safety(client, "sf-gate")["tripped"] is True

    # max_bad_percent=0: any anomaly trips as soon as min_reports is reached
    make_named_channel(client, monkeypatch, "sf-zero", percent=100)
    assert arm_safety(client, "sf-zero", 1, 1, 0).status_code == 200
    assert post_receipt(client, "sf-zero", "d1", 1, "success",
                        "does-not-exist").json()["circuit_breaker_tripped"] is True
    body = safety(client, "sf-zero")
    assert body["reports"] == 1 and body["anomalies"] == 1
    assert body["tripped"] is True


def test_safety_deviation_counts_and_match_does_not(client, monkeypatch):
    stable, candidate = make_named_channel(client, monkeypatch, "sf-dev",
                                           percent=100)
    assert arm_safety(client, "sf-dev", 1, 3, 50).status_code == 200

    # success with a different image is an anomaly just like a failure
    post_receipt(client, "sf-dev", "d1", 1, "success", stable)
    body = safety(client, "sf-dev")
    assert body["reports"] == 1 and body["anomalies"] == 1

    # two clean matched successes dilute to 1/3 = 33% <= 50%: no trip
    post_receipt(client, "sf-dev", "d2", 1, "success", candidate)
    r = post_receipt(client, "sf-dev", "d3", 1, "success", candidate)
    assert r.json()["circuit_breaker_tripped"] is False
    body = safety(client, "sf-dev")
    assert body["reports"] == 3 and body["anomalies"] == 1
    assert body["tripped"] is False


def test_safety_sample_excludes_fallback_receipts(client, monkeypatch):
    """A receipt frozen to the stable image via candidate-untrusted fallback
    never enters the canary sample, so it can neither trip nor inflate
    reports."""
    sk_s1, pk_s1 = gen_key()
    sk_s2, pk_s2 = gen_key()
    sk_c1, pk_c1 = gen_key()
    sk_c2, pk_c2 = gen_key()
    all_keys = {"ops": pk_s1, "ci": pk_s2, "ops2": pk_c1, "ci2": pk_c2}
    set_keys(monkeypatch, all_keys)
    stable = finalize_trusted(client, os.urandom(300),
                              {"ops": sk_s1, "ci": sk_s2})
    candidate = finalize_trusted(client, os.urandom(300),
                                 {"ops2": sk_c1, "ci2": sk_c2})
    assert client.put("/channels/sf-fb", json={
        "stable_id": stable, "candidate_id": candidate,
        "percent": 100, "expected_revision": 0,
    }).status_code == 200
    assert arm_safety(client, "sf-fb", 1, 1, 0).status_code == 200

    # rotate the candidate's keys out before any receipt: expected_id
    # freezes to the stable fallback
    set_keys(monkeypatch, {"ops": pk_s1, "ci": pk_s2})
    r = post_receipt(client, "sf-fb", "d1", 1, "failed")
    assert r.status_code == 200 and r.json()["expected_id"] == stable
    assert r.json()["circuit_breaker_tripped"] is False
    body = safety(client, "sf-fb")
    assert body["reports"] == 0 and body["anomalies"] == 0
    assert body["tripped"] is False


def test_safety_resolve_trust_floor_after_trip(client, monkeypatch):
    sk_s1, pk_s1 = gen_key()
    sk_s2, pk_s2 = gen_key()
    sk_c1, pk_c1 = gen_key()
    sk_c2, pk_c2 = gen_key()
    all_keys = {"ops": pk_s1, "ci": pk_s2, "ops2": pk_c1, "ci2": pk_c2}
    set_keys(monkeypatch, all_keys)
    stable = finalize_trusted(client, os.urandom(300),
                              {"ops": sk_s1, "ci": sk_s2})
    candidate = finalize_trusted(client, os.urandom(300),
                                 {"ops2": sk_c1, "ci2": sk_c2})
    assert client.put("/channels/sf-floor", json={
        "stable_id": stable, "candidate_id": candidate,
        "percent": 100, "expected_revision": 0,
    }).status_code == 200
    assert arm_safety(client, "sf-floor", 1, 1, 0).status_code == 200
    assert post_receipt(client, "sf-floor", "d1", 1, "failed"
                        ).json()["circuit_breaker_tripped"] is True

    # candidate losing trust changes nothing: risk rollback already targets
    # the stable image
    set_keys(monkeypatch, {"ops": pk_s1, "ci": pk_s2})
    body = client.get("/channels/sf-floor/resolve",
                      params={"device_id": "d2"}).json()
    assert body["image_id"] == stable
    assert body["reason"] == "risk_circuit_breaker_fallback"

    # stable losing trust is still a hard 409 even while tripped
    set_keys(monkeypatch, {"ops2": pk_c1, "ci2": pk_c2})
    assert client.get("/channels/sf-floor/resolve",
                      params={"device_id": "d2"}).status_code == 409
    set_keys(monkeypatch, all_keys)


def test_safety_channel_update_invalidates_rule_and_recovers(client, monkeypatch):
    stable, candidate = make_named_channel(client, monkeypatch, "sf-upd",
                                           percent=100)
    assert arm_safety(client, "sf-upd", 1, 1, 0).status_code == 200
    assert post_receipt(client, "sf-upd", "d1", 1, "failed"
                        ).json()["circuit_breaker_tripped"] is True
    assert safety(client, "sf-upd")["tripped"] is True

    # bumping the channel to revision 2 invalidates the old rule and latch
    r = client.put("/channels/sf-upd", json={
        "stable_id": stable, "candidate_id": candidate,
        "percent": 100, "expected_revision": 1,
    })
    assert r.status_code == 200 and r.json()["revision"] == 2

    # no rule armed at revision 2
    assert client.get("/channels/sf-upd/safety").status_code == 404
    # canary is live again at the new revision
    body = client.get("/channels/sf-upd/resolve",
                      params={"device_id": "d1"}).json()
    assert body["image_id"] == candidate and body["reason"] == "candidate"
    assert body["revision"] == 2
    # revision-1 receipts are stale
    assert post_receipt(client, "sf-upd", "d2", 1, "failed",
                        revision=1).status_code == 409

    # arming against the old revision is a 409; arming at revision 2 works
    assert arm_safety(client, "sf-upd", 1, 1, 0).status_code == 409
    r = arm_safety(client, "sf-upd", 2, 1, 0)
    assert r.status_code == 200 and r.json()["stored"] == "armed"
    # old-revision receipts do not feed the new sample
    body = safety(client, "sf-upd")
    assert body["reports"] == 0 and body["anomalies"] == 0
    assert body["tripped"] is False


def test_safety_persists_across_restart(client, monkeypatch):
    stable, candidate = make_named_channel(client, monkeypatch, "sf-lts",
                                           percent=100)
    assert arm_safety(client, "sf-lts", 1, 1, 0).status_code == 200
    assert post_receipt(client, "sf-lts", "d1", 1, "failed"
                        ).json()["circuit_breaker_tripped"] is True

    with TestClient(app) as c2:
        body = c2.get("/channels/sf-lts/safety").json()
        assert body["min_reports"] == 1 and body["max_bad_percent"] == 0
        assert body["reports"] == 1 and body["anomalies"] == 1
        assert body["tripped"] is True and body["status"] == "tripped"
        # risk rollback still in force after the rebuild
        r = c2.get("/channels/sf-lts/resolve", params={"device_id": "d9"})
        assert r.json()["reason"] == "risk_circuit_breaker_fallback"
        # identical rule resubmission is still the idempotent no-op;
        # a changed rule still conflicts
        r = c2.put("/channels/sf-lts/safety", json={
            "expected_revision": 1, "min_reports": 1, "max_bad_percent": 0,
        })
        assert r.status_code == 200 and r.json()["stored"] == "unchanged"
        r = c2.put("/channels/sf-lts/safety", json={
            "expected_revision": 1, "min_reports": 2, "max_bad_percent": 0,
        })
        assert r.status_code == 409
        # idempotent receipt replay does not untrip
        r = c2.post("/channels/sf-lts/receipts", json={
            "device_id": "d1", "revision": 1, "seq": 1, "status": "failed",
        })
        assert r.status_code == 200
        assert r.json()["stored"] == "unchanged"
        assert r.json()["circuit_breaker_tripped"] is True


def test_safety_counts_only_current_revision_receipts(client, monkeypatch):
    stable, candidate = make_named_channel(client, monkeypatch, "sf-rev",
                                           percent=100)
    assert arm_safety(client, "sf-rev", 1, 2, 50).status_code == 200
    # one failure at revision 1: sample 1 < min_reports 2, no trip
    post_receipt(client, "sf-rev", "d1", 1, "failed")
    assert safety(client, "sf-rev")["reports"] == 1

    # channel update wipes the rule and starts revision 2 unarmed
    assert client.put("/channels/sf-rev", json={
        "stable_id": stable, "candidate_id": candidate,
        "percent": 100, "expected_revision": 1,
    }).status_code == 200
    assert client.get("/channels/sf-rev/safety").status_code == 404
    assert arm_safety(client, "sf-rev", 2, 2, 50).status_code == 200

    # revision-1 receipts are invisible to the revision-2 sample
    body = safety(client, "sf-rev")
    assert body["reports"] == 0 and body["anomalies"] == 0
    post_receipt(client, "sf-rev", "d2", 1, "failed", revision=2)
    body = safety(client, "sf-rev")
    assert body["reports"] == 1 and body["anomalies"] == 1
