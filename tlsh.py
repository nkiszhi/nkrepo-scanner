"""
tlsh.py - 纯 Python 实现的 TLSH (Trend Micro Locality Sensitive Hash)

移植自官方仓库 trendmicro/tlsh 的 js_ext/tlsh.js (JS port, 与官方 C++ 实现一致):
  - 128 有效桶 (EFF_BUCKETS) / 256 计数桶, 1 字节校验和 (TLSH_CHECKSUM_LEN=1)
  - 输出为 70 位十六进制 (无 T1 前缀, 兼容 VirusTotal / MalwareBazaar 存量数据格式)
  - 最小输入长度 50 字节 (与官方 py-tlsh 默认一致; 复杂度不足时 final() 返回 False)

许可证: Apache-2.0 / BSD-3-Clause (Copyright 2013 Trend Micro Incorporated)
  详见 https://github.com/trendmicro/tlsh 与项目 LICENSE 说明。
"""
import math

try:  # numpy 为可选加速依赖 (缺失时自动回退纯 Python)
    import numpy as _np
except ImportError:  # pragma: no cover
    _np = None

# ---------------------------------------------------------------- 常量
V_TABLE = bytes([
    1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163,
    14, 197, 213, 181, 161, 85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200,
    110, 177, 104, 103, 141, 253, 255, 50, 77, 101, 81, 18, 45, 96, 31, 222,
    25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227, 149, 235,
    97, 234, 57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248,
    174, 169, 211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243,
    132, 56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13, 153, 246, 216, 219,
    119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92, 32, 136, 114, 52, 10,
    138, 30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152,
    170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131,
    125, 173, 15, 238, 79, 95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123,
    118, 73, 2, 157, 46, 116, 9, 145, 134, 228, 207, 212, 202, 215, 69, 229,
    27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39, 203,
    233, 40, 186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76,
    140, 36, 210, 172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120,
    51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71, 109, 184, 209,
])

LOG_1_5 = 0.4054651
LOG_1_3 = 0.26236426
LOG_1_1 = 0.095310180

SLIDING_WND_SIZE = 5
RNG_SIZE = SLIDING_WND_SIZE
TLSH_CHECKSUM_LEN = 1
BUCKETS = 256          # 计数桶
EFF_BUCKETS = 128      # 参与分位的有效桶
CODE_SIZE = 32         # 128 * 2 bits = 32 字节
TLSH_STRING_LEN = 70   # 2 + 1 + 32 字节 → 70 个 hex 字符
RANGE_LVALUE = 256
RANGE_QRATIO = 16

MIN_DATA_LEN = 50      # 官方 py-tlsh 默认最小输入长度


def _rng_idx(i):
    return (i + RNG_SIZE) % RNG_SIZE


def _b_mapping(salt, i, j, k):
    h = 0
    h = V_TABLE[h ^ salt]
    h = V_TABLE[h ^ i]
    h = V_TABLE[h ^ j]
    h = V_TABLE[h ^ k]
    return h


# 预计算 2 级查表: Q[s][i][j] = V_TABLE[V_TABLE[V_TABLE[s] ^ i] ^ j]
# 于是 _b_mapping(s, i, j, k) = V_TABLE[Q[s][i][j] ^ k] —— 把每次映射从 4 次链式查表
# 降至 1 次查表。update() 热循环只用 7 个固定 salt, 预计算内存约 7×256×256 = 458KB。
_SALTS = (0, 2, 3, 5, 7, 11, 13)
_Q = {
    s: [bytes(V_TABLE[V_TABLE[V_TABLE[s] ^ i] ^ j] for j in range(256))
        for i in range(256)]
    for s in _SALTS
}
_Q0, _Q2, _Q3, _Q5, _Q7, _Q11, _Q13 = (_Q[s] for s in _SALTS)


def _l_capturing(length):
    if length <= 656:
        i = int(math.log(length) / LOG_1_5)
    elif length <= 3199:
        i = int(math.log(length) / LOG_1_3 - 8.72777)
    else:
        i = int(math.log(length) / LOG_1_1 - 62.5472)
    return i & 0xFF


def _swap_byte(i):
    return (((i & 0xF0) >> 4) & 0x0F) | (((i & 0x0F) << 4) & 0xF0)


def _set_qlow(q, x):
    return (q & 0xF0) | (x & 0x0F)


def _set_qhigh(q, x):
    return (q & 0x0F) | ((x & 0x0F) << 4)


def _find_quartile(a_bucket):
    """对 128 个有效桶求 q1/q2/q3

    性能优化 (2026-08-22): quickselect 是求顺序统计量的手段, 排序后直接取
    索引 31/63/95 与官方 find_quartile 输出**完全等价** (确定性顺序统计量,
    无平局歧义), 128 元素排序远快于多轮分区。
    """
    buf = sorted(a_bucket[:EFF_BUCKETS])
    p1 = EFF_BUCKETS // 4 - 1          # 31
    p2 = EFF_BUCKETS // 2 - 1          # 63
    p3 = EFF_BUCKETS - EFF_BUCKETS // 4 - 1  # 95
    return buf[p1], buf[p2], buf[p3]


class Tlsh:
    """TLSH 计算器: update(bytes) → final() → hexdigest()"""

    def __init__(self):
        self.checksum = [0] * TLSH_CHECKSUM_LEN
        self.slide_window = [0] * SLIDING_WND_SIZE
        self.a_bucket = [0] * BUCKETS
        self.data_len = 0
        self.tmp_code = [0] * CODE_SIZE
        self.Lvalue = 0
        self.Q = 0
        self._valid = False

    def update(self, data):
        """喂入字节数据 (可多次调用)

        性能优化 (2026-08-22): 将热循环内 7 次 _b_mapping 函数调用 + 链式查表
        内联为基于预计算 Q 表的单次查表 (输出与官方算法逐字节一致)。
        """
        if not data:
            return
        w = self.slide_window
        checksum = self.checksum
        a_bucket = self.a_bucket
        VT = V_TABLE
        Q0, Q2, Q3, Q5, Q7, Q11, Q13 = _Q0, _Q2, _Q3, _Q5, _Q7, _Q11, _Q13
        fed_len = self.data_len
        j = fed_len % RNG_SIZE

        for b in data:
            w[j] = b

            if fed_len >= 4:  # 至少 5 字节才开始计算
                # 窗口索引取模内联 (等价于 _rng_idx, 避免热循环调用开销):
                # j ∈ [0, RNG_SIZE-1], 对负数一次 += RNG_SIZE 即回到有效范围 (RNG_SIZE>=5 恒成立)
                j1 = j - 1
                if j1 < 0:
                    j1 += RNG_SIZE
                j2 = j - 2
                if j2 < 0:
                    j2 += RNG_SIZE
                j3 = j - 3
                if j3 < 0:
                    j3 += RNG_SIZE
                j4 = j - 4
                if j4 < 0:
                    j4 += RNG_SIZE

                wj = w[j]
                wA = w[j1]
                wB = w[j2]
                wC = w[j3]
                wD = w[j4]

                # 校验和 (TLSH_CHECKSUM_LEN=1): checksum[0] = _b_mapping(0, wj, wA, checksum[0])
                checksum[0] = VT[Q0[wj][wA] ^ checksum[0]]

                # 6 个桶更新 (与官方一致; 等价于 _b_mapping(salt, wj, x, y) 各累加一次)
                a_bucket[VT[Q2[wj][wA] ^ wB]] += 1
                a_bucket[VT[Q3[wj][wA] ^ wC]] += 1
                a_bucket[VT[Q5[wj][wB] ^ wC]] += 1
                a_bucket[VT[Q7[wj][wB] ^ wD]] += 1
                a_bucket[VT[Q11[wj][wA] ^ wD]] += 1
                a_bucket[VT[Q13[wj][wC] ^ wD]] += 1

            j += 1
            if j == RNG_SIZE:
                j = 0
            fed_len += 1

        self.data_len = fed_len

    def final(self):
        """完成计算; 返回 True=成功, False=输入过短或复杂度不足"""
        if self.data_len < MIN_DATA_LEN:
            return False

        q1, q2, q3 = _find_quartile(self.a_bucket)

        # 非零桶必须超过一半, 否则视为变化不足
        nonzero = 0
        for k in self.a_bucket[:EFF_BUCKETS]:
            if k > 0:
                nonzero += 1
        if nonzero <= 4 * CODE_SIZE // 2:
            return False

        q1_3, q2_3, q3_3 = q1, q2, q3  # 局部化 (热循环免属性/全局查找)
        for i in range(CODE_SIZE):
            h = 0
            for j in range(4):
                k = self.a_bucket[4 * i + j]
                if q3_3 < k:
                    h += 3 << (j * 2)
                elif q2_3 < k:
                    h += 2 << (j * 2)
                elif q1_3 < k:
                    h += 1 << (j * 2)
            self.tmp_code[i] = h

        self.Lvalue = _l_capturing(self.data_len)
        # 注意: 官方用浮点除法再取整, 这里保持一致
        self.Q = _set_qlow(self.Q, int((q1 * 100) / q3) % 16)
        self.Q = _set_qhigh(self.Q, int((q2 * 100) / q3) % 16)
        self._valid = True
        return True

    def hexdigest(self):
        """返回 70 位大写 hex; 未 final 或失败时返回 None"""
        if not self._valid:
            return None
        # bytes.hex().upper() 远快于逐字节 f-string 拼接
        out = bytearray(CODE_SIZE + 3)
        out[0] = _swap_byte(self.checksum[0])
        out[1] = _swap_byte(self.Lvalue)
        out[2] = _swap_byte(self.Q)
        tc = self.tmp_code
        for i in range(CODE_SIZE):
            out[3 + i] = tc[CODE_SIZE - 1 - i]
        return out.hex().upper()

    def reset(self):
        self.__init__()


def hash_bytes(data):
    """便捷函数: 计算 bytes 的 TLSH, 不适用时返回 None

    性能优化 (2026-08-22): 安装 numpy 且输入 ≥ _NP_MIN_LEN 字节时走
    _hash_bytes_np() 向量化路径 (6 组桶计数用 2D gather + bincount 一次算完,
    仅校验和保持逐字节链式循环), 输出与纯 Python 路径逐字节一致。
    """
    if data is None:
        return None
    if _np is not None and len(data) >= _NP_MIN_LEN:
        try:
            return _hash_bytes_np(data)
        except Exception:
            pass  # 向量化路径异常时回退纯 Python (保证正确性优先)
    t = Tlsh()
    t.update(data)
    if not t.final():
        return None
    return t.hexdigest()


# ---------------------------------------------------------------- numpy 向量化路径 (可选)
_NP_MIN_LEN = 2048          # 低于此长度 numpy 调度开销不划算
_np_tables_cache = None


def _np_tables():
    """缓存 VT/Q 表的 numpy 形式 (VT: (256,), Q[s]: (256,256) uint8)"""
    global _np_tables_cache
    if _np_tables_cache is None:
        VT = _np.frombuffer(V_TABLE, dtype=_np.uint8)
        Qn = {
            s: _np.frombuffer(b"".join(_Q[s]), dtype=_np.uint8).reshape(256, 256)
            for s in _SALTS
        }
        _np_tables_cache = (VT, Qn)
    return _np_tables_cache


def _hash_bytes_np(data):
    """numpy 向量化计算 TLSH (输出与 Tlsh.update+final 逐字节一致)

    update() 每字节的 6 次桶更新形如 a_bucket[VT[Q[s][wj][wX] ^ wY]] += 1,
    桶索引只依赖滑窗字节 → 可对整个输入一次性 2D gather 后 bincount 计数;
    校验和 checksum[0] = VT[Q0[wj][wA] ^ checksum[0]] 是顺序依赖的链, 只能
    逐字节推进 (已预取 Q0 查表结果, 每次仅 1 次 xor + 1 次查表)。
    """
    np = _np
    VTn, Qn = _np_tables()
    arr = np.frombuffer(data, dtype=np.uint8)
    n = arr.size

    wj = arr[4:]     # 当前字节 (位置 i)
    wA = arr[3:-1]   # i-1
    wB = arr[2:-2]   # i-2
    wC = arr[1:-3]   # i-3
    wD = arr[0:-4]   # i-4

    # 6 组桶计数: (salt, (二元组), 第三字节) 与 update() 内联实现一一对应
    counts = np.zeros(256, dtype=np.int64)
    for salt, pair, third in (
        (2,  (wj, wA), wB),
        (3,  (wj, wA), wC),
        (5,  (wj, wB), wC),
        (7,  (wj, wB), wD),
        (11, (wj, wA), wD),
        (13, (wj, wC), wD),
    ):
        bidx = VTn[Qn[salt][pair] ^ third]
        counts += np.bincount(bidx, minlength=256)

    # 校验和链: c = VT[Q0[wj][wA] ^ c] (顺序依赖, 无法向量化)
    m = Qn[0][wj, wA].tolist()
    VTp = V_TABLE
    c = 0
    for x in m:
        c = VTp[x ^ c]

    t = Tlsh()
    t.data_len = n
    t.checksum[0] = c
    t.a_bucket = counts.tolist()
    if not t.final():
        return None
    return t.hexdigest()


# ---------------------------------------------------------------- 距离计算 (相似度比对)
# 移植自官方 trendmicro/tlsh 的 lsh_bin_totalDiff / lsh_bin_h_distance
#   bit_pairs_diff_table 256×256 查表可分解为 4 个独立 2-bit 四分位比较,
#   权重矩阵从 bit_pairs_diff_table[0][0..15] 推导 (见官方 tlsh_impl.h)

# 2-bit 四分位对差异权重矩阵 (va=行, vb=列)
# 官方 bit_pairs_diff_table 的 4×4 基础表 (对角线=0, d(0,3)=d(3,0)=6 加重惩罚)
_BIT_PAIRS_DIFF = (
    (0,  1,  2,  6),   # va=0
    (1,  0,  1,  2),   # va=1
    (2,  1,  0,  1),   # va=2
    (6,  2,  1,  0),   # va=3
)

# 距离计算常量 (与官方一致)
LENGTH_MULT = 12       # 长度差异乘子
QRATIO_MULT = 12       # Q 比率差异乘子


def _mod_diff(x, y, R):
    """模意义下的循环距离: min(|x-y| % R, R - |x-y| % R)"""
    d = abs(x - y) % R
    return min(d, R - d)


def _h_distance(x, y):
    """单字节 body code 差异: 4 个 2-bit 四分位对差异之和 (对应官方 h_distance)

    保留供参考/单点调试; 批量比对请用 byte_dist_table() / diff_bin()。
    """
    diff = 0
    for a in range(4):
        va = (x >> (a * 2)) & 0x3
        vb = (y >> (a * 2)) & 0x3
        diff += _BIT_PAIRS_DIFF[va][vb]
    return diff


# ---------------------------------------------------------------- 字节对距离表 (性能优化)
# 65536 项预合成表: _BYTE_DIST[x*256 + y] = h_distance(x, y)
# 把每字节 4 次"移位+查 4×4 权重矩阵"合并为一次查表 (首用懒构建, 一次约 0.1s)
_BYTE_DIST = None


def byte_dist_table():
    """返回 65536 字节的字节对距离表 (懒构建; 幂等, 可多线程安全调用)"""
    global _BYTE_DIST
    if _BYTE_DIST is None:
        bp = _BIT_PAIRS_DIFF
        t = bytearray(65536)
        for x in range(256):
            base = x << 8
            x0 = bp[x & 3]
            x1 = bp[(x >> 2) & 3]
            x2 = bp[(x >> 4) & 3]
            x3 = bp[(x >> 6) & 3]
            for y in range(256):
                t[base | y] = (
                    x0[y & 3] + x1[(y >> 2) & 3]
                    + x2[(y >> 4) & 3] + x3[(y >> 6) & 3]
                )
        _BYTE_DIST = bytes(t)
    return _BYTE_DIST


# ---------------------------------------------------------------- 二进制表示与字段提取
TLSH_BIN_LEN = 35  # 1(checksum) + 1(Lvalue) + 1(Q) + 32(body)


def to_binary(h):
    """TLSH hex → 35 字节二进制; 兼容可选 T1/t1 前缀与大小写; 无效返回 None"""
    if not h:
        return None
    h = h.upper()
    if h.startswith("T1"):
        h = h[2:]
    if len(h) != TLSH_STRING_LEN:
        return None
    try:
        return bytes.fromhex(h)
    except ValueError:
        return None


def binary_to_hex(b):
    """35 字节二进制 → 70 位大写 hex (本项目 / VirusTotal 存储格式)"""
    return b.hex().upper() if b is not None else None


def header_fields(b):
    """从 35 字节二进制 TLSH 提取头部字段: (lv, q1, q2)

    lv: 反 swap 后的 Lvalue (0..255); q1/q2: 反 swap 后 Q 字节的低/高 nibble (各 0..15)。
    """
    q = _swap_byte(b[2])
    return _swap_byte(b[1]), q & 0x0F, (q >> 4) & 0x0F


def diff_bin(b1, b2, threshold=None):
    """计算两个 35 字节二进制 TLSH 的距离 (语义与 diff() 完全一致)

    b1/b2 为 to_binary() 的输出。给出 threshold 时启用提前终止:
    累计距离一旦超过 threshold 立即返回 — 返回值 ≤ 真实距离, 只可用于
    淘汰判断; 未触发提前终止 (返回值 ≤ threshold) 时为精确距离。
    """
    if b1 is None or b2 is None or len(b1) != TLSH_BIN_LEN or len(b2) != TLSH_BIN_LEN:
        return -1

    total = 0

    # 1. 校验和 (byte 0): 不同则 +1 (TLSH_CHECKSUM_LEN=1, 仅 1 字节)
    if b1[0] != b2[0]:
        total += 1

    # 2. 长度值 (byte 1, 存储为 _swap_byte(Lvalue)): 反 swap 后做 mod_diff
    ldiff = _mod_diff(_swap_byte(b1[1]), _swap_byte(b2[1]), RANGE_LVALUE)
    if ldiff == 1:
        total += 1
    elif ldiff > 1:
        total += ldiff * LENGTH_MULT

    # 3. Q 比率 (byte 2): 低 nibble = Q1ratio, 高 nibble = Q2ratio
    q1b = _swap_byte(b1[2])
    q2b = _swap_byte(b2[2])
    for qa, qb in ((q1b & 0x0F, q2b & 0x0F), ((q1b >> 4) & 0x0F, (q2b >> 4) & 0x0F)):
        qdiff = _mod_diff(qa, qb, RANGE_QRATIO)
        if qdiff <= 1:
            total += qdiff
        else:
            total += (qdiff - 1) * QRATIO_MULT

    if threshold is not None and total > threshold:
        return total

    # 4. body code (bytes 3..34): 预合成字节对距离表一次查表/字节
    dist = byte_dist_table()
    if threshold is None:
        for i in range(3, 35):
            total += dist[(b1[i] << 8) | b2[i]]
        return total
    for i in range(3, 35):
        total += dist[(b1[i] << 8) | b2[i]]
        if total > threshold:
            return total
    return total


def diff(h1_hex, h2_hex):
    """计算两个 TLSH hex 哈希的距离 (越小越相似, 0=完全相同)。

    算法移植自官方 trendmicro/tlsh 的 lsh_bin_totalDiff:
      1. 校验和 (1 字节): 不同则 +1
      2. 长度值 Lvalue: mod_diff(L1, L2, 256); ldiff==0→+0, ldiff==1→+1, else +ldiff×12
      3. Q 比率 (Q1/Q2 各一): mod_diff(Q1, Q2, 16); qdiff≤1→+qdiff, else +(qdiff-1)×12
      4. body code (32 字节): 逐字节 h_distance 累加 (预合成 65536 字节对表)

    返回 -1 表示输入无效 (长度不匹配/非 hex)。
    """
    b1 = to_binary(h1_hex)
    b2 = to_binary(h2_hex)
    if b1 is None or b2 is None:
        return -1
    return diff_bin(b1, b2)


# 别名, 与官方 py-tlsh API 一致
total_diff = diff
