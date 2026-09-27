# 固件镜像分片验收 API

基于 **Python 3.11 + FastAPI + SQLite** 的固件镜像分片接收/验收服务。
支持分片乱序、重复上传，重叠区间逐字节校验，冲突时整次写入回滚；全部收齐且
SHA-256 校验通过后封存镜像，封存后只读并支持原始内容下载。已封存的镜像可接收
Ed25519 签名（attestation），服务端按**当前配置的公钥**实时重验，达到阈值即判定
可信。在此之上提供**灰度发布通道**：稳定/候选镜像按设备确定性分桶，解析时实时
重验可信并自动回退；设备安装后向通道**上报回执**，服务端在接收时按决议规则
冻结应装镜像，并按当前修订号核对成功匹配/偏离/失败的设备数。通道还可布防
**灰度风险熔断**：候选镜像样本的异常比例越界即在回执写事务内锁存熔断，熔断后
灰度桶整体回退到可信稳定镜像且回执覆盖不解除，通道更新后旧规则失效。超过闲置时长的**未封存**任务可由 `POST /images/cleanup`
连同分片一并回收，封存镜像、签名与通道始终保留。任务、分片、签名、通道策略、
熔断规则/状态与设备回执全部落盘，容器重建后数据不丢。

## 一键启动（Docker Compose）

```bash
docker compose up -d --build
```

如需启用镜像可信判定，先在 shell 中配置可信公钥（见下文「封存镜像可信判定」），
再执行同一条命令即可，端口不变：

```bash
TRUSTED_KEYS_JSON='{"ops":"...base64公钥...","ci":"...base64公钥..."}' \
  docker compose up -d --build
```

- 本地监听端口：**http://localhost:8000**
- 交互式接口文档（Swagger UI）：http://localhost:8000/docs
- 健康检查：http://localhost:8000/health

停止：

```bash
docker compose down            # 容器停止/删除，数据保留在命名卷 firmware-data 中
docker compose down -v         # 同时删除数据卷（谨慎）
```

数据库文件位于容器内 `/data/images.db`（SQLite WAL 模式，另有 `-wal`/`-shm`
辅助文件），挂载在命名卷 `firmware-data` 上。因此执行 `docker compose up -d
--build` 重建镜像/容器后，历史任务、分片、封存状态、已收录的签名、灰度通道与
回执以及熔断规则/锁存状态依然可用。**Compose 启动方式与端口均无变化。**

## 本地直接运行（不使用 Docker）

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
IMAGE_DB_PATH=./data/images.db uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## 协议速览

| 方法   | 路径                              | 说明 |
|--------|-----------------------------------|------|
| POST   | `/images`                         | 创建验收任务，返回任务 ID |
| PUT    | `/images/{id}/chunks?offset=N`    | 上传一块原始二进制（`Content-Type` 任意） |
| GET    | `/images/{id}`                    | 查询已覆盖/缺失的半开区间 |
| POST   | `/images/{id}/finalize`           | 无缺口且哈希匹配时封存 |
| POST   | `/images/cleanup`                 | 回收超过闲置时长的**未封存**任务（含分片） |
| GET    | `/images/{id}/content`            | 封存后下载原始镜像 |
| GET    | `/images/{base_id}/delta/{target_id}` | 两幅已封存镜像间的**增量分发**：按 64 KiB 对齐返回目标差异块 |
| GET    | `/images/{id}/merkle`             | 已封存镜像的 Merkle 承诺（总长、叶数、根哈希） |
| POST   | `/images/{id}/proof`              | 已封存镜像的 Merkle 多块证明（1～64 个叶） |
| POST   | `/images/{id}/attestations`       | 为已封存镜像提交一条 Ed25519 签名（每个 `key_id` 一条） |
| GET    | `/images/{id}/trust`              | 按当前公钥重新验签，返回可信判定 |
| PUT    | `/channels/{name}`                | 创建/更新灰度发布通道（`expected_revision` 乐观并发校验） |
| GET    | `/channels/{name}/resolve?device_id=...` | 按设备确定性解析灰度通道，实时重验可信并回退 |
| PUT    | `/channels/{name}/safety`         | 为当前修订号设置/替换灰度**风险熔断**规则（最小样本、最大异常百分比） |
| GET    | `/channels/{name}/safety`         | 查询熔断规则、当前样本数/异常数与熔断状态 |
| POST   | `/channels/{name}/receipts`       | 上报设备安装回执（仅接受当前修订号，接收时冻结应装镜像） |
| GET    | `/channels/{name}/installation-audit` | 按当前修订号统计成功匹配/成功偏离/失败的设备数 |
| GET    | `/health`                         | 存活探针 |

### 限制

- 镜像总长 `total_size`：**1 ~ 67,108,864** 字节（64 MiB）
- `sha256`：恰好 **64 个十六进制字符**（大小写均可，服务端按小写存储）
- 单块大小：**1 ~ 1,048,576** 字节（1 MiB）
- `offset`：非负整数，且 `offset + len(chunk) ≤ total_size`

### 区间语义

所有区间均为**半开区间 `[lo, hi)`**。上传成功后相邻/重叠的区间会在服务端
合并为一条连续记录，响应中同时给出：

- `covered_intervals`：已覆盖区间（有序、互不相交）
- `missing_intervals`：缺失区间（有序、互不相交）
- `merged_interval`：本次写入后形成/更新的合并区间

### 状态码

| 状态码 | 触发条件 |
|--------|----------|
| 201    | 任务创建成功 |
| 200    | 分片上传/查询/封存/下载/签名提交/可信查询成功 |
| 400    | 分片为空或区间越界；签名接口的 `key_id` 未知、Base64 编码错误或签名无效（均不落库） |
| 404    | 任务不存在（增量接口中基础镜像或目标镜像任一不存在均返回 404）；通道不存在；`PUT /channels` 中稳定或候选镜像不存在；`GET .../safety` 时通道不存在或当前修订号尚未布防熔断规则（上一修订号的规则在通道更新后已失效） |
| 409    | 重叠字节不一致（整次写入回滚）；镜像已封存仍写入；未封存取 content、提交签名、请求增量或请求 Merkle 根/证明；封存时仍有缺口或哈希不匹配；`PUT /channels` 的 `expected_revision` 与当前修订号不符、或任一镜像未封存/当前不可信；解析时稳定镜像失信（熔断回退时仍如此）；回执修订号非当前值、序号小于已存值或同序号内容不同、上报时稳定镜像失信；`PUT /channels/{name}/safety` 的 `expected_revision` 与当前修订号不符、或同修订号已布防且新规则数值不同 |
| 413    | 分片超过 1 MiB |
| 422    | 请求参数校验失败（JSON 字段、offset 为负等）；`proof` 的 `indices` 非法（为空、超过 64 个、重复、负数、非整数或超出叶范围）；`cleanup` 的 `idle_seconds` 非正整数或 `limit` 不在 1～100；回执的 `seq`/`revision` 非正整数、`status` 非法、`success` 缺 `installed_id` 或 `failed` 携带 `installed_id`；熔断规则的 `min_reports` 不在 1～1000、`max_bad_percent` 不在 0～100 或 `expected_revision` 非正整数 |

## 使用示例

```bash
# 1. 准备一个固件并算出长度/SHA-256
head -c 300000 /dev/urandom > fw.bin
SHA=$(sha256sum fw.bin | cut -d' ' -f1)

# 2. 创建任务
ID=$(curl -s -X POST localhost:8000/images \
  -H 'Content-Type: application/json' \
  -d "{\"total_size\":300000,\"sha256\":\"$SHA\"}" | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')

# 3. 按 64KiB 切片（可乱序、可重复上传）
split -b 65536 fw.bin part_
curl -s -X PUT "localhost:8000/images/$ID/chunks?offset=131072" --data-binary @part_ac
curl -s -X PUT "localhost:8000/images/$ID/chunks?offset=0"       --data-binary @part_aa

# 4. 查看覆盖/缺失区间
curl -s "localhost:8000/images/$ID"

# 5. 全部传完后封存（有缺口或哈希不符返回 409）
curl -s -X POST "localhost:8000/images/$ID/finalize"

# 6. 下载原始镜像（仅封存后可用）
curl -s "localhost:8000/images/$ID/content" -o fw.out
cmp fw.bin fw.out
```

## 闲置任务回收（Idle Cleanup）

客户端创建任务后可能中断上传，长期留下未封存的任务和分片占用空间。服务为每个
任务记录**最近活动时间** `last_activity_at`：

- **创建任务时写入**（初始等于 `created_at`）；
- **每一次成功上传分片时，在上传的同一个写事务内刷新**——包括完全重复的上传
  （重复分片也是一次有效活动）；
- 因冲突（重叠字节不一致、向已封存镜像写入）或越界（分片超出 `total_size`）被
  拒绝的请求 **不刷新**；这些请求整体回滚，活动时间随事务一并回滚；
- 封存、查询、签名等操作不改变最近活动时间；**已封存镜像永不参与回收**。

> 旧版本数据库（没有该列）在服务启动时**自动升级**：以标准 SQLite 表重建方式
> 加入 `last_activity_at TEXT NOT NULL`，并用 `created_at` 逐行补齐，因此升级后
> 历史未封存任务可立即按闲置时长回收；分片、签名、通道数据均保留。

### 触发回收

```
POST /images/cleanup
{"idle_seconds": 3600, "limit": 50}
```

- `idle_seconds`：**正整数**。截止时刻在**请求开始时**一次性确定为
  `now − idle_seconds`（UTC）；最近活动时间**早于或等于**截止时刻的任务视为
  到期。
- `limit`：**1～100 的整数**。本次最多回收多少个任务。
- 两个参数任一不合法返回 **422**。

服务在**同一个 `BEGIN IMMEDIATE` 写事务**内：

1. 选出**未封存且到期**的任务，按 `(last_activity_at ASC, id ASC)` 升序取至多
   `limit` 个（活动时间相同时按任务 ID 排序，结果确定）；
2. 汇总这些任务分片占用的字节总数（存储区间两两不相交，即精确的已接收字节）；
3. 删除这些任务及其全部分片。

响应：

```json
{
  "cutoff": "2026-09-26T11:30:00+00:00",
  "idle_seconds": 3600,
  "limit": 50,
  "deleted": 2,
  "deleted_ids": ["0a1b…", "3f8c…"],
  "released_bytes": 7340032
}
```

- `deleted_ids`：本次删除的任务 ID 列表（即上面的升序）；无到期任务时为 `[]`。
- `released_bytes`：随任务一并释放的分片字节总数；无删除时为 `0`。

```bash
# 回收闲置超过 1 小时的未封存任务，每次最多 50 个；可由 cron 周期性调用
curl -s -X POST localhost:8000/images/cleanup \
  -H 'Content-Type: application/json' \
  -d '{"idle_seconds":3600,"limit":50}'
```

### 与并发上传 / 封存的关系

回收与上传、封存全部以 **SQLite 写事务的提交顺序**串行判定，没有可观察的中间态：

- **先提交上传或封存的任务按最新状态处理**：若回收事务拿到写锁时，某任务的上传
  已先提交，其 `last_activity_at` 已刷新（晚于截止时刻则不再被选中）；若封存已先
  提交，该任务 `finalized=1`，永不会被回收。
- **先被回收的任务，后续一切操作返回 404**：任务已在已提交事务中删除，之后的
  分片上传、状态查询、封存、下载、签名等一律 404。
- **回收不会部分删除**：选中、统计、删除在同一事务内，任一步失败整体
  `ROLLBACK`，不会出现任务删了一半或分片残留。
- **封存镜像、签名与通道永不被清理**：回收只选 `finalized=0` 的任务；已封存镜像
  及其 attestations、引用它的灰度通道（外键）一律保留。

## 增量分发（Delta）与客户端还原

设备端通常已经保存了某个旧版镜像（**基础镜像 base**），只需拉取与新版
（**目标镜像 target**）不同的部分即可还原。接口：

```
GET /images/{base_id}/delta/{target_id}
```

- 两幅镜像都**必须已封存**；任一镜像不存在返回 **404**，任一未封存返回 **409**。
- 目标镜像按固定 **65536（64 KiB）** 字节网格从 offset 0 对齐读取：仅当某块与
  基础镜像**同位置的字节不同或长度不同**（目标变长 / 变短 / 末块不足整块）时，
  才输出该块的 `offset` 和 **Base64 编码的目标块字节**；完全相同的块不输出，
  两幅镜像完全相同时 `blocks` 为空数组。
- 响应为 JSON（服务端流式生成，逐块以**固定大小**从 SQLite 读取分片、不把整幅
  镜像载入内存，且只读、不改动任何镜像或签名）：

```json
{
  "base_id": "…",
  "base_sha256": "…",
  "base_size": 300000,
  "target_id": "…",
  "target_sha256": "…",
  "target_size": 305000,
  "block_size": 65536,
  "blocks": [
    {"offset": 0,      "length": 65536, "data": "…base64…"},
    {"offset": 262144, "length": 42856, "data": "…base64…"}
  ]
}
```

`blocks` 按 `offset` 升序排列且互不重叠；除最后一块外每块长度恒为 65536。

### 还原步骤（必须严格按此顺序）

1. 先把本地的基础镜像**截断或补零**到 `target_size`（目标变短则截断，变长则在
   末尾补零）；
2. 再按每个块的 `offset` 把 Base64 解码后的字节覆写到
   `[offset, offset + length)`。

由此得到的字节流必须与目标镜像逐字节一致，可用 `target_sha256` 复核。

```bash
BASE_ID=...     # 设备端已有旧版镜像的任务 ID
TARGET_ID=...   # 新版镜像的任务 ID

curl -s "localhost:8000/images/$BASE_ID/delta/$TARGET_ID" -o delta.json

python3 - <<'EOF'
import base64, hashlib, json

delta = json.load(open("delta.json"))

# 本地已有的基础镜像字节（设备端通常就是 Flash 里的旧固件）
base = open("fw.out", "rb").read()

# 1) 先截断或补零到目标长度
buf = bytearray(delta["target_size"])
buf[: min(len(base), delta["target_size"])] = base[: delta["target_size"]]

# 2) 按 offset 覆写各差异块
for blk in delta["blocks"]:
    buf[blk["offset"] : blk["offset"] + blk["length"]] = base64.b64decode(blk["data"])

open("fw.new", "wb").write(buf)

# 3) 与服务端给出的目标 SHA-256 复核
digest = hashlib.sha256(buf).hexdigest()
assert digest == delta["target_sha256"], (digest, delta["target_sha256"])
print("restored OK:", digest)
EOF

# 与直接下载的完整目标镜像做最终比对
curl -s "localhost:8000/images/$TARGET_ID/content" -o fw.full
cmp fw.new fw.full && echo "byte-identical"
```

- 目标**变长**：新增区域在基础镜像中没有对应字节，对应块（含跨 64 KiB 边界、
  末尾不足整块的情形）必然全部输出。
- 目标**变短**：差异块只覆盖 `target_size` 以内的网格块；还原时的截断步骤负责
  去掉基础镜像多出的尾部。
- 两幅镜像**完全相同**：`blocks` 为 `[]`，还原结果即为基础镜像本身。

### 大镜像峰值内存验证

连续上传的相邻分片会在服务端合并成**单行整幅 BLOB**，因此增量接口的读取器
不直接取出 `data` 列，而是以固定 1 MiB 的 `substr(data, ?, ?)` 分片查询逐步
取数（当前切片作为预读缓冲供给 64 KiB 网格窗口），并拼接跨行窗口。SQLite 对
BLOB 列的 `substr()` 不会把整列物化进内存，读取缓冲只随固定切片大小走、
**不随镜像总长增长**。

`tests/test_api.py` 中的 `test_delta_large_images_peak_memory_is_bounded`
对此做了自动化验证：用两幅 16 MiB 镜像（各按正常接口以 1 MiB 连续分片上传并
封存，且断言已合并为单行 BLOB）——

1. 用 `tracemalloc` 记录一次完整 `GET /images/{base}/delta/{target}` 的 Python
   峰值分配，断言低于单幅镜像大小的一半（旧实现会把两幅整镜像同时驻留内存，
   实测峰值约 2×16 MiB）；
2. 在流式响应中途读取 `/proc/self/status` 的 VmRSS，断言进程 RSS 增长同样
   有界（非 Linux 系统无 `/proc` 时自动跳过该步）；
3. 断言按 `blocks` 还原的结果与目标镜像逐字节一致。

运行方式（不影响现有 Compose 启动命令与端口）：

```bash
python -m pytest tests/test_api.py -k peak_memory -v
```

## 封存镜像 Merkle 承诺与多块证明

每幅**已封存**镜像都对应一棵二进制 Merkle 树。只持有根哈希的一方（设备端、
审计方等）可以借此校验：某些数据块确实属于该镜像，而无需重新下载整幅镜像。
树在每次请求时由已封存字节**在线计算**（只进扫描、有界缓冲，见
「一致性与并发设计」），因此**新旧封存镜像均可直接使用，无需任何迁移**。

### 树的构造

- 按 **65536 字节**切叶，末叶保留实际长度（可能不足 65536 字节）；
- 叶哈希：`SHA-256(0x00 || 块字节)`；
- 父哈希：`SHA-256(0x01 || 左哈希 || 右哈希)`；
- 前缀为**单字节**，拼接的是 32 字节**原始哈希**（不是十六进制文本）；
- 每层节点数为奇时**复制末项**再两两配对；只有一片叶子时，根即该叶哈希。

### 查询根承诺

```
GET /images/{id}/merkle
```

```json
{
  "id": "…",
  "total_size": 300000,
  "leaf_size": 65536,
  "leaf_count": 5,
  "root": "2bea50eb…"
}
```

镜像未封存返回 **409**，任务不存在返回 **404**。

### 请求多块证明

```
POST /images/{id}/proof
{"indices": [0, 3]}
```

- `indices`：**1～64 个互异、从 0 起**的合法叶下标；任一不满足返回 **422**
  （未封存 409、任务不存在 404）。
- 返回按下标排序的所选叶（下标、长度、Base64 块字节）以及一份所有所选叶
  **共用的证明**。
- 证明元素为 `{level, index, hash}` 三元组（**叶层为 0**），按层号和下标
  排序，哈希为十六进制；**仅列出无法由所选叶自行推导的兄弟节点**，奇数层
  复制的末节点不另列。

```json
{
  "id": "…",
  "total_size": 300000,
  "leaf_size": 65536,
  "leaf_count": 5,
  "root": "2bea50eb…",
  "leaves": [
    {"index": 0, "length": 65536, "data": "…base64…"},
    {"index": 3, "length": 65536, "data": "…base64…"}
  ],
  "proof": [
    {"level": 0, "index": 1, "hash": "8454dac7…"},
    {"level": 0, "index": 2, "hash": "939fd86c…"},
    {"level": 2, "index": 1, "hash": "d3ae35a0…"}
  ]
}
```

### 预存根校验（客户端参考实现）

典型流程：镜像封存后**先取一次根哈希并妥善保存**（预存根）；之后每次只对
感兴趣的叶请求证明，用预存根在本地重算校验：

```bash
# 封存后预存根哈希
ROOT=$(curl -s "localhost:8000/images/$ID/merkle" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["root"])')

# 之后随时请求任意叶集合（1~64 个）的多块证明
curl -s -X POST "localhost:8000/images/$ID/proof" \
  -H 'Content-Type: application/json' \
  -d '{"indices":[0,3]}' > proof.json
```

```python
import base64, hashlib, json

def leaf_hash(block):  return hashlib.sha256(b"\x00" + block).digest()
def parent_hash(l, r): return hashlib.sha256(b"\x01" + l + r).digest()

def verify_proof(root_hex, leaf_count, leaves, proof):
    """leaves: [(index, raw_bytes)]；proof: 接口返回的 proof 列表。"""
    known = {i: leaf_hash(d) for i, d in leaves}
    provided = {(p["level"], p["index"]): bytes.fromhex(p["hash"]) for p in proof}
    n, level = leaf_count, 0
    while n > 1:
        nxt = {}
        for i, h in known.items():
            sib = i ^ 1                      # 偶节点的兄弟在右，奇节点在左
            if sib < n:
                sh = known.get(sib, provided.get((level, sib)))
                if sh is None:
                    return False             # 证明缺少所需节点
                pair = (h, sh) if i % 2 == 0 else (sh, h)
            else:
                pair = (h, h)                # 奇数层末节点与自身副本配对
            nxt[i // 2] = parent_hash(*pair)
        known, n, level = nxt, (n + 1) // 2, level + 1
    return len(known) == 1 and known[0].hex() == root_hex

body = json.load(open("proof.json"))
leaves = [(l["index"], base64.b64decode(l["data"])) for l in body["leaves"]]
assert verify_proof(ROOT, body["leaf_count"], leaves, body["proof"])
print("proof OK against pre-stored root:", ROOT)
```

### 篡改失败示例

任何对返回块或证明哈希的改动，都会使重算的根与预存根不一致：

```python
# 篡改返回的块字节：翻转一个字节
bad = bytearray(leaves[0][1]); bad[0] ^= 0xFF
assert not verify_proof(ROOT, body["leaf_count"],
                        [(leaves[0][0], bytes(bad))] + leaves[1:],
                        body["proof"])

# 或篡改证明中的任一哈希
broken = [dict(p) for p in body["proof"]]
broken[0]["hash"] = "00" * 32
assert not verify_proof(ROOT, body["leaf_count"], leaves, broken)
print("tampering detected: verification fails as expected")
```

## 封存镜像可信判定（Attestation）

镜像封存后，各签名方（运维、CI、安全审计……）可对其提交 Ed25519 签名；
服务端收集签名并按**当前配置的公钥**实时重验，给出可信判定。

### 验签原文

签名覆盖的是一条由**服务端记录**拼接的 ASCII 字符串（客户端无需也无法篡改）：

```
FWIMGv1|{id}|{sha256}|{total_size}
```

其中 `sha256` 为小写十六进制，`total_size` 为十进制字节数，均取自服务端
存档的任务记录。

### 配置可信公钥（`TRUSTED_KEYS_JSON`）

通过环境变量 `TRUSTED_KEYS_JSON` 配置 `key_id` → Base64 编码 Ed25519 公钥
（32 字节）的 JSON 映射：

```bash
# 生成一对 Ed25519 密钥（每个签名方一对）
python3 - <<'EOF'
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
)
sk = Ed25519PrivateKey.generate()
print("私钥(妥善保管):", base64.b64encode(sk.private_bytes(
    Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode())
print("公钥(配置到服务端):", base64.b64encode(
    sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode())
EOF

# 把各签名方的公钥配给服务（Compose 直接透传该环境变量）
TRUSTED_KEYS_JSON='{"ops":"3Zy...","ci":"9kQ..."}' docker compose up -d --build
```

- **未配置时可正常启动**，只是所有镜像都判定为不可信，签名接口一律返回 400。
- 配置格式非法（非 JSON 对象、公钥无法解码或长度不为 32 字节）的条目会被忽略，
  不影响服务运行。
- 更换公钥：更新环境变量后 `docker compose up -d` 重建容器即可生效。

### 提交签名

```bash
# 用私钥对验签原文签名（Python 示例）
python3 - "$ID" "$SHA" 300000 <<'EOF'
import base64, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
msg = f"FWIMGv1|{sys.argv[1]}|{sys.argv[2]}|{sys.argv[3]}".encode("ascii")
sk = Ed25519PrivateKey.from_private_bytes(base64.b64decode("...私钥base64..."))
print(base64.b64encode(sk.sign(msg)).decode())
EOF

curl -s -X POST "localhost:8000/images/$ID/attestations" \
  -H 'Content-Type: application/json' \
  -d '{"key_id":"ops","signature":"...base64签名..."}'
# -> {"id":"...","key_id":"ops","status":"recorded"}
```

- 镜像**未封存**时提交返回 **409**；`key_id` 未知、Base64 无法解码或签名验不过
  返回 **400**，且**不会落库**。
- 同一镜像每个 `key_id` 只保留一条签名：重复提交相同签名是幂等空操作
  （`status:"unchanged"`）；提交新的有效签名会覆盖旧值（`status:"replaced"`）。

### 查询可信判定

```bash
curl -s "localhost:8000/images/$ID/trust"
# -> {"id":"...","finalized":true,"trusted":true,
#     "valid_key_ids":["ci","ops"],"threshold":2,"attestations_stored":2}
```

判定规则：

- 每次查询都取出该镜像的全部已存签名，用**当前配置的公钥**逐条重新验签，
  不做任何缓存。
- 至少 **2 个不同 `key_id`** 的签名同时有效，`trusted` 才为 `true`，
  有效的 `key_id` 在 `valid_key_ids` 中列出。
- 更换或移除某个公钥后，旧签名在下次查询时立即不再计入（验签失败或
  `key_id` 未配置），不会被误判为有效。
- 签名持久化在 SQLite `attestations` 表中，随命名卷保留，容器重建后仍可查询。

## 灰度发布通道（Gray Release）

通道把一幅**稳定镜像**和一幅**候选镜像**绑定为一个发布策略：每台设备按
确定性哈希落入某个百分比桶，决定它应拉取哪一幅镜像。策略（含修订号）持久化在
SQLite `channels` 表中，随命名卷跨重建保留；**可信判定不落库**，创建/更新与
解析时都按当前配置的公钥实时重验。

### 创建 / 更新通道

```
PUT /channels/{name}
{"stable_id":"…","candidate_id":"…","percent":25,"expected_revision":0}
```

- `percent`：**0～100 的整数**，表示进入候选镜像的设备百分比（`0` 永不选候选，
  `100` 在候选可信时总选候选）。
- `expected_revision` 是乐观并发令牌：**首次创建必须为 0**（成功后修订号变为
  1）；之后每次更新必须填入**当前修订号**，不符返回 **409** 且不落库；更新成功
  修订号 +1。
- 任一镜像不存在返回 **404**；任一镜像**未封存或当前不可信**（按当前公钥重验
  未达阈值）返回 **409**。整个“校验 + 写入”在一个事务中完成，并发更新不会交错。
- 响应返回写入后的策略与修订号：

```json
{"name":"release-1","stable_id":"…","candidate_id":"…",
 "percent":25,"revision":1,"updated_at":"2026-09-26T…"}
```

```bash
# 前提：STABLE_ID / CANDIDATE_ID 均已封存且按当前公钥可信（见上节）
curl -s -X PUT "localhost:8000/channels/release-1" \
  -H 'Content-Type: application/json' \
  -d "{\"stable_id\":\"$STABLE_ID\",\"candidate_id\":\"$CANDIDATE_ID\",
       \"percent\":25,\"expected_revision\":0}"

# 之后调整灰度比例：必须带上当前修订号
curl -s -X PUT "localhost:8000/channels/release-1" \
  -H 'Content-Type: application/json' \
  -d "{\"stable_id\":\"$STABLE_ID\",\"candidate_id\":\"$CANDIDATE_ID\",
       \"percent\":50,\"expected_revision\":1}"
```

### 按设备解析

```
GET /channels/{name}/resolve?device_id=dev-0042
```

```bash
curl -s "localhost:8000/channels/release-1/resolve?device_id=dev-0042"
```

决议算法（纯函数，无随机性）：

1. 依次拼接 **通道名的 UTF-8 字节**、**一个字节 `0x00`**、**device_id 的 UTF-8
   字节**，求 SHA-256；
2. 取摘要**前 8 字节按大端序**解释为无符号整数，对 **10000** 取模得到桶号
   （0～9999）；
3. 桶号 **小于 `percent × 100`** 选候选镜像，否则选稳定镜像。

解析时按**当前公钥**对两幅镜像重新验签：

- 候选被选中但已失信 → **回退到可信的稳定镜像**；
- 稳定镜像失信 → 整个解析返回 **409**（绝不把设备导向不可信镜像）。

```json
{"name":"release-1","device_id":"dev-0042","image_id":"…",
 "revision":1,"reason":"stable","bucket":8202,"percent":25}
```

`reason` 取值：`candidate`（桶号落在候选区间且候选可信）、`stable`（桶号落在
稳定区间）、`candidate_untrusted_fallback`（候选失信，回退稳定镜像）。

由于桶号只取决于（通道名, device_id, percent），**策略与公钥不变时，同一设备
的决议在容器重建后完全一致**；通道不存在返回 404，缺少 `device_id` 返回 422。

客户端可用同样的算法本地复核桶号：

```python
import hashlib

def bucket(name: str, device_id: str) -> int:
    d = hashlib.sha256(name.encode() + b"\x00" + device_id.encode()).digest()
    return int.from_bytes(d[:8], "big") % 10000

assert bucket("release-1", "dev-0042") == 8202  # 与响应中的 bucket 一致
```

## 灰度安装回执核对（Installation Receipts）

设备完成（或失败）一次安装后向通道上报回执；服务端在**接收时**按灰度决议规则
算出该设备的**应装镜像**并随回执冻结保存，之后可随时按通道核对安装结果。回执
持久化在 SQLite `receipts` 表中，随命名卷与通道一起跨重建保留。

### 上报回执

```
POST /channels/{name}/receipts
{"device_id":"dev-0042","revision":2,"seq":7,"status":"success","installed_id":"…"}
```

- `revision`：**仅接受通道当前修订号**。通道更新后，旧修订号的延迟上报一律
  返回 **409**，不会覆盖新数据。
- `seq`：**正整数**，设备级序号，跨修订号单调递增。每个（通道，设备）只保留
  序号最大的回执：
  - 序号小于已存值 → **409**；
  - 序号相同但内容（`revision` / `status` / `installed_id`）不同 → **409**；
  - 序号相同且内容相同 → 幂等成功，返回已存回执（`stored:"unchanged"`，
    含冻结的 `expected_id`）；
  - 序号更大 → 覆盖已存回执（`stored:"replaced"`；新设备为 `"recorded"`）。
- `status`：`success` 时必须携带非空 `installed_id`；`failed` 时
  `installed_id` 必须为 `null`（或省略），否则 **422**。
- 接收时在**同一个 SQLite 写事务**内按现有决议规则（设备分桶 + 实时重验 +
  候选失信回退）计算 `expected_id` 并随回执落库；**稳定镜像失信时拒收**
  （**409**），不落库。通道不存在返回 **404**。

```bash
# 成功上报（revision 须为通道当前修订号；seq 逐次递增、跨修订号不回退）
curl -s -X POST "localhost:8000/channels/release-1/receipts" \
  -H 'Content-Type: application/json' \
  -d "{\"device_id\":\"dev-0042\",\"revision\":2,\"seq\":7,
       \"status\":\"success\",\"installed_id\":\"$CANDIDATE_ID\"}"
# -> {"name":"release-1","device_id":"dev-0042","revision":2,"seq":7,
#     "status":"success","installed_id":"…","expected_id":"…",
#     "matched":true,"stored":"recorded"}

# 失败上报不带 installed_id
curl -s -X POST "localhost:8000/channels/release-1/receipts" \
  -H 'Content-Type: application/json' \
  -d '{"device_id":"dev-0043","revision":2,"seq":1,"status":"failed"}'
```

响应中 `expected_id` 为接收时冻结的应装镜像；`matched` 表示本次上报成功且
实装与应装一致；`stored` 为 `recorded` / `replaced` / `unchanged`。

### 核对安装结果

```
GET /channels/{name}/installation-audit
```

```bash
curl -s "localhost:8000/channels/release-1/installation-audit"
# -> {"name":"release-1","revision":2,
#     "success_matched":18,"success_deviated":2,"failed":1}
```

- 只统计**当前修订号**的回执；旧修订号的回执保留在库中但不计入。
- `success_matched`：上报成功且 `installed_id` 等于冻结的 `expected_id`；
  `success_deviated`：上报成功但实装了别的镜像；`failed`：上报失败。
  每台设备只按其最新回执计入一次。
- `expected_id` 在接收时冻结，**之后的策略调整或公钥轮换都不会改写它**，
  核对始终按接收时的决议结果进行。通道不存在返回 **404**。

## 灰度风险熔断（Canary Risk Circuit Breaker）

每个修订号可以额外布防一条**风险熔断规则**：监控当前修订号灰度桶设备的回执，
候选镜像异常比例越界即**锁存熔断**，把整个灰度桶回退到可信稳定镜像。规则与
熔断状态持久化在 SQLite `channel_safety` 表中，随命名卷跨容器重建保留。

### 布防 / 替换规则

```
PUT /channels/{name}/safety
{"expected_revision":2,"min_reports":20,"max_bad_percent":5}
```

- `expected_revision`：必须等于通道**当前修订号**，不符返回 **409** 且不落库。
- `min_reports`：**1～1000 的整数**，触发熔断所需的最小样本数。
- `max_bad_percent`：**0～100 的整数**，允许的最大异常百分比。
- 每个修订号**初始无规则**；同修订号重复提交**完全相同**的规则（两个阈值都
  不变）是幂等空操作（响应 `stored:"unchanged"`）；同修订号提交**不同**规则
  返回 **409**——改规则必须先更新通道（修订号 +1）再按新修订号重新布防。
- 通道不存在返回 **404**；参数非法返回 **422**。

```bash
curl -s -X PUT "localhost:8000/channels/release-1/safety" \
  -H 'Content-Type: application/json' \
  -d '{"expected_revision":2,"min_reports":20,"max_bad_percent":5}'
# -> {"name":"release-1","revision":2,"rule_revision":2,
#     "min_reports":20,"max_bad_percent":5,
#     "reports":0,"anomalies":0,"tripped":false,"status":"monitoring",
#     "stored":"armed"}
```

### 样本与异常口径

每次有**新回执落库**（新设备上报或更大 `seq` 覆盖；幂等重交不触发统计），
服务端在**存放回执的同一个 SQLite 写事务内**立即统计当前修订号：

- **样本**：冻结的应装镜像（`expected_id`）为**候选镜像**的当前修订号回执数，
  即本应安装候选镜像的设备。因候选失信而把应装镜像冻结为稳定镜像的回执
  （`candidate_untrusted_fallback`）不进入灰度样本；
- **异常**：样本中 `status:"failed"`，或上报成功但 `installed_id` 与冻结的
  `expected_id` 不一致（实装偏离）的设备。每台设备只按其最新回执计入一次。

### 触发条件

当同时满足：

```
reports >= min_reports
anomalies × 100 > reports × max_bad_percent   （严格大于；边界不触发）
```

熔断即被**锁存（latch）为 tripped**，判定与回执写入在同一事务内提交。例如
`min_reports=20, max_bad_percent=5`：20 个样本中 1 个异常（5%）不触发，第 2
个异常（10%）触发；`max_bad_percent=0` 时样本达标后出现任何异常立即触发。

### 熔断后的行为

- `GET /channels/{name}/resolve`：所有**候选桶**设备一律导向**可信稳定镜像**，
  `reason` 标为 `risk_circuit_breaker_fallback`（风险回退）；桶号、灰度
  `percent` 和修订号都**不变**。候选镜像此时是否可信不再影响候选桶决议；
  **稳定镜像失信仍然返回 409**（绝不导向不可信镜像）。
- 熔断后新上报的回执按风险回退后的决议冻结 `expected_id`（稳定镜像）；
  **后续回执覆盖不能解除熔断**——即使异常设备补交了完美成功的回执，锁存状态
  也保持 tripped。回执响应中带 `circuit_breaker_tripped` 字段。

### 查询规则与状态

```
GET /channels/{name}/safety
```

```bash
curl -s "localhost:8000/channels/release-1/safety"
# -> {"name":"release-1","revision":2,"rule_revision":2,
#     "min_reports":20,"max_bad_percent":5,
#     "reports":21,"anomalies":2,"tripped":true,"status":"tripped"}
```

- `reports` / `anomalies` 为上述口径下的实时计数；`status` 为
  `monitoring`（监控中）或 `tripped`（已熔断锁存）。
- 通道不存在、或当前修订号没有布防规则（包括尚未重新布防的新修订号）时
  返回 **404**。

### 恢复方式

熔断状态在**本修订号内单向锁存**，恢复必须通过一次通道更新：

1. 修复候选镜像后用 `PUT /channels/{name}` 发布新策略（哪怕仅提高/调整
   `percent`），修订号 +1，**旧规则连同熔断锁存在同一事务内删除**；
2. 对新修订号重新 `PUT /channels/{name}/safety` 布防；
3. 旧修订号回执不再进入新规则的样本，灰度在新修订号上重新开始；若新候选仍
   异常，新规则会再次触发。

仅重启容器**不会**解除熔断：规则、计数所依据的回执与锁存状态全部在 SQLite
命名卷中，跨重建保留。

## 一致性与并发设计

- **原子校验-写入**：每次分片上传在一个 `BEGIN IMMEDIATE` 事务中完成
  “读取现有区间 → 重叠逐字节比对 → 合并落库”。并发写同一任务时由 SQLite
  写锁串行化，任何冲突都会 `ROLLBACK`，本次写入的所有字节均不会落库。
- **进程内同任务锁**：同任务的写操作在单进程内额外按任务 ID 加锁，消除锁竞争
  造成的无谓回滚；不同任务互不阻塞。SQLite 事务仍是跨进程的最终保障。
- **区间存储模型**：`chunks` 表始终保存每个任务下互不相交、有序、已合并的
  覆盖区间及其精确字节，因此缺口检测是一次顺序扫描，封存时顺序拼接即可，
  流式计算 SHA-256，无需生成临时文件。
- **封存即冻结**：`finalize` 在同一事务内完成“缺口检查 + 哈希校验 + 置封存位”；
  封存后所有 PUT 返回 409。`finalize` 幂等：重复调用返回 200 且
  `already_finalized=true`。
- **闲置回收按提交顺序裁决**：每个任务保存 `last_activity_at`（创建时写入，成功
  上传——含重复上传——时在上传事务内一并刷新，冲突/越界回滚时不刷新）。
  `POST /images/cleanup` 以请求开始时刻 `now − idle_seconds` 为截止，在单个
  `BEGIN IMMEDIATE` 事务内按 `(last_activity_at, id)` 升序选出至多 `limit` 个
  未封存到期任务，连同分片删除并返回删除 ID 与释放字节数。它与上传、封存按事务
  提交顺序串行：先提交上传/封存的按最新状态处理（刷新后未到期或已封存则保留），
  先被回收的任务后续操作一律 404；任何错误整体回滚，不会部分删除。回收只针对
  `finalized=0` 的任务，封存镜像、签名与引用它们的通道永不被清理。旧库启动时
  自动加入该列并以 `created_at` 补齐。
- **增量分发只顺序读**：`delta` 以只进游标分别顺序扫描两幅镜像，每次只取一个
  64 KiB 网格块。由于连续上传的分片会合并成单行整幅 BLOB，读取器从不直接
  SELECT 整个 `data` 列：先加载 `(offset, end_offset)` 区间表，再以固定大小
  （1 MiB）的 `substr(data, ?, ?)` 查询逐片取字节（当前切片留作预读缓冲，
  连续网格窗口无需每块都查库），透明拼接跨存储分片的窗口，读取缓冲不随镜像
  总长增长，两幅大镜像不会同时驻留内存。不组装整幅镜像、不开启任何写事务，
  镜像内容与签名均不受影响，JSON 响应同样逐块生成、流式下发。
- **Merkle 扫描同样有界**：`merkle`/`proof` 复用与增量接口相同的只进读取器，
  以固定大小分片顺序扫描已封存字节并在线建树；内存占用只随叶数（每叶一个
  32 字节哈希）与本次请求返回的块数（至多 64 块）增长，**不随镜像总长增长**。
  树不落库、无状态，每次请求从已封存字节重算，因此历史封存镜像无需迁移。
- **回执与通道更新按提交顺序裁决**：`POST /channels/{name}/receipts` 与
  `PUT /channels/{name}` 共用同一把进程内通道锁，并各自在单个
  `BEGIN IMMEDIATE` 事务内完成"读通道 → 校验修订号 → 决议应装镜像 → 落库"。
  仅接受通道当前修订号：先提交的通道更新使后续旧修订号上报一律 409，旧修订号
  的延迟上报永远不能覆盖新数据。每个（通道，设备）只保留 `seq` 最大的回执
  （`seq` 跨修订号单调递增）：更小序号或同序号不同内容 409，同序号同内容幂等。
  `expected_id` 在接收事务内按决议规则算出并冻结，后续策略调整或公钥轮换均不
  改写；`installation-audit` 只统计当前修订号，按冻结值判定匹配/偏离/失败，
  稳定镜像失信时拒收且不落库。
- **风险熔断在回执写事务内统计并单向锁存**：`PUT /channels/{name}/safety`
  按当前修订号布防规则（同修订号相同规则幂等、不同规则 409，修订号不符 409）。
  每条新回执落库的**同一个写事务**内统计候选样本数与异常数，样本达到
  `min_reports` 且 `anomalies × 100 > reports × max_bad_percent` 时把
  `tripped` 置位并随回执提交——计数、锁存与回执对外要么同时可见、要么都不
  可见。锁存单向：之后的回执覆盖（即使异常设备补交成功回执）不会解除；熔断后
  解析把候选桶设备导向可信稳定镜像（`risk_circuit_breaker_fallback`），
  `percent` 与修订号不变，稳定镜像失信仍返回 409；熔断后的新回执按回退决议
  冻结应装镜像。通道更新在更新事务内**删除旧修订号的规则与锁存**，新修订号
  初始无规则、需重新布防，这也是唯一的恢复路径。
- **持久化**：全部状态（任务、分片字节、封存标志、签名、灰度通道策略与修订号、
  设备安装回执、熔断规则与锁存状态）都在 SQLite 中；配合 Compose 命名卷，
  容器/镜像重建后任务、分片、签名、通道、回执与熔断状态继续可用。通道的可信
  判定不缓存：解析与回执接收时均按当前公钥实时重验。
- 服务默认以**单个 uvicorn worker** 运行（见 Dockerfile CMD）。单 worker
  配合线程池即可并发处理请求，且与单文件 SQLite 的写模型最为匹配。

## 测试

```bash
pip install -r requirements.txt pytest httpx
python -m pytest tests/ -v
```

测试覆盖：参数校验、乱序/重复/相邻合并、越界、冲突整次回滚、缺口与哈希不符、
封存后写保护、content 下载、16 线程并发写入、并发冲突回滚、模拟容器重建后的
持久化校验，以及签名接口（未封存 409、未知密钥/错误编码/无效签名 400 且不落库、
幂等重交与覆盖、双密钥阈值判定、换钥后旧签名失效、签名持久化）；增量分发覆盖
未封存 409 / 不存在 404、两镜像相同、目标变长/变短/末块不足整块、跨 64 KiB 与
分片边界的随机对拍还原、差异块按 64 KiB 网格精确输出、分片读取器跨行拼接，
以及两幅 16 MiB 大镜像（连续分片上传合并为单行 BLOB 后）增量请求的峰值内存
有界性验证（见上文「大镜像峰值内存验证」）；Merkle 承诺与多块证明覆盖
未封存 409 / 不存在 404 / `indices` 非法 422、多种叶数（单叶、整叶、奇数层
复制、多层奇数）根哈希与参考实现对拍、多块证明的最小性（仅含不可推导的兄弟
节点、复制节点不另列、按层号和下标排序）与客户端重算校验、篡改块字节/证明
哈希的检测、旧封存镜像免迁移可用，以及 16 MiB 大镜像扫描的峰值内存有界性；
灰度通道覆盖参数校验 422、首建/更新修订号校验 409、镜像不存在 404、未封存/
未达可信阈值 409、拒绝调用不落库、按参考实现逐设备对拍桶号与选边（含非 ASCII
device_id）、`percent` 取 0/100 的边界行为、候选失信回退稳定镜像、稳定镜像
失信 409，以及模拟容器重建后策略与同设备决议完全一致；安装回执覆盖参数校验
422（`seq`/`revision` 非正整数、`status` 非法、`success` 缺 `installed_id`、
`failed` 携带 `installed_id` 等）、通道不存在 404、非当前修订号 409 且不落库、
应装镜像按参考分桶规则逐设备对拍（含非 ASCII device_id）、稳定镜像失信拒收、
序号规则（更小 409、同号不同内容 409、同号同内容幂等、更大覆盖且核对随之更新）、
序号跨修订号递增、核对接口只统计当前修订号且按冻结 `expected_id` 判定、公钥
轮换与策略更新不改写已存应装结果、模拟容器重建后回执与幂等性保持，以及与通道
更新并发时按事务提交顺序裁决（旧修订号延迟上报不覆盖新数据）；风险熔断覆盖
参数校验 422（`min_reports` 越界、`max_bad_percent` 越界、修订号非正）、通道
不存在 404、修订号不符 409、同修订号相同规则幂等与改规则 409、无规则时 GET
404、`min_reports` 样本门限与严格百分比边界（恰等不触发、越界即触发）、
`max_bad_percent=0` 边界、失败与成功偏离均计异常而候选失信回退的回执不进样本、
熔断在回执写事务内触发、熔断后 resolve 回退稳定镜像并标明
`risk_circuit_breaker_fallback`（`percent`/修订号不变、稳定镜像失信仍 409）、
熔断后新回执冻结稳定镜像且回执覆盖不解除锁存、通道更新删除旧规则与锁存且仅能
经"更新通道 + 重新布防"恢复、旧修订号回执不计入新样本，以及规则与锁存状态
模拟容器重建后保留；闲置回收覆盖参数校验
422（`idle_seconds` 非正、`limit` 越界/非整数/缺失）、只回收未封存且到期任务、
释放字节数按不相交区间精确统计、`limit` 截断与 `(last_activity_at, id)` 排序
（含同时间戳按 ID 破并）、重复调用逐批清空、成功上传（含重复分片）刷新活动时间、
越界 400 与冲突/封存后写入 409 均不刷新、回收后各端点 404、封存镜像及其签名与
通道不被清理、注入删除故障时整批回滚无部分删除、与并发上传/封存按提交顺序裁决，
以及旧版数据库（无 `last_activity_at` 列）启动时自动建列并以 `created_at` 补齐。

## 目录结构

```
app/
  main.py          # FastAPI 路由与业务逻辑
  db.py            # SQLite 连接、建表、按任务锁
tests/
  test_api.py      # 端到端测试（基于 TestClient）
Dockerfile
docker-compose.yml
requirements.txt
```
