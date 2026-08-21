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


def _partition(buf, left, right):
    """快排分区 (与官方实现一致: 取中点作 pivot, 原地交换)"""
    if left == right:
        return left
    if left + 1 == right:
        if buf[left] > buf[right]:
            buf[left], buf[right] = buf[right], buf[left]
        return left

    ret = left
    pivot = (left + right) >> 1
    val = buf[pivot]
    buf[pivot] = buf[right]
    buf[right] = val

    for i in range(left, right):
        if buf[i] < val:
            buf[ret], buf[i] = buf[i], buf[ret]
            ret += 1
    buf[right], buf[ret] = buf[ret], buf[right]
    return ret


def _find_quartile(a_bucket):
    """对 128 个有效桶求 q1/q2/q3 (quickselect, 与官方 find_quartile 一致)"""
    buf = list(a_bucket[:EFF_BUCKETS])
    short_cut_left = [0] * EFF_BUCKETS
    short_cut_right = [0] * EFF_BUCKETS
    spl = 0
    spr = 0
    p1 = EFF_BUCKETS // 4 - 1          # 31
    p2 = EFF_BUCKETS // 2 - 1          # 63
    p3 = EFF_BUCKETS - EFF_BUCKETS // 4 - 1  # 95
    end = EFF_BUCKETS - 1              # 127
    q1 = q2 = q3 = 0

    l, r = 0, end
    while True:
        ret = _partition(buf, l, r)
        if ret > p2:
            r = ret - 1
            short_cut_right[spr] = ret
            spr += 1
        elif ret < p2:
            l = ret + 1
            short_cut_left[spl] = ret
            spl += 1
        else:
            q2 = buf[p2]
            break

    short_cut_left[spl] = p2 - 1
    short_cut_right[spr] = p2 + 1

    l = 0
    for i in range(spl + 1):
        r = short_cut_left[i]
        if r > p1:
            while True:
                ret = _partition(buf, l, r)
                if ret > p1:
                    r = ret - 1
                elif ret < p1:
                    l = ret + 1
                else:
                    q1 = buf[p1]
                    break
            break
        elif r < p1:
            l = r
        else:
            q1 = buf[p1]
            break

    r = end
    for i in range(spr + 1):
        l = short_cut_right[i]
        if l < p3:
            while True:
                ret = _partition(buf, l, r)
                if ret > p3:
                    r = ret - 1
                elif ret < p3:
                    l = ret + 1
                else:
                    q3 = buf[p3]
                    break
            break
        elif l > p3:
            r = l
        else:
            q3 = buf[p3]
            break

    return q1, q2, q3


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
        """喂入字节数据 (可多次调用)"""
        if not data:
            return
        w = self.slide_window
        j = self.data_len % RNG_SIZE
        fed_len = self.data_len
        checksum = self.checksum
        a_bucket = self.a_bucket

        for i in range(len(data)):
            b = data[i]
            w[j] = b

            if fed_len >= 4:  # 至少 5 字节才开始计算
                j1 = _rng_idx(j - 1)
                j2 = _rng_idx(j - 2)
                j3 = _rng_idx(j - 3)
                j4 = _rng_idx(j - 4)

                for k in range(TLSH_CHECKSUM_LEN):
                    if k == 0:
                        checksum[k] = _b_mapping(0, w[j], w[j1], checksum[k])
                    else:
                        checksum[k] = _b_mapping(checksum[k - 1], w[j], w[j1], checksum[k])

                # 6 个桶更新 (与官方一致; JS port 中 b_mapping(2,..) 重复计算但只累加一次)
                r = _b_mapping(2, w[j], w[j1], w[j2])
                a_bucket[r] += 1
                r = _b_mapping(3, w[j], w[j1], w[j3])
                a_bucket[r] += 1
                r = _b_mapping(5, w[j], w[j2], w[j3])
                a_bucket[r] += 1
                r = _b_mapping(7, w[j], w[j2], w[j4])
                a_bucket[r] += 1
                r = _b_mapping(11, w[j], w[j1], w[j4])
                a_bucket[r] += 1
                r = _b_mapping(13, w[j], w[j3], w[j4])
                a_bucket[r] += 1

            j = _rng_idx(j + 1)
            fed_len += 1

        self.data_len += len(data)

    def final(self):
        """完成计算; 返回 True=成功, False=输入过短或复杂度不足"""
        if self.data_len < MIN_DATA_LEN:
            return False

        q1, q2, q3 = _find_quartile(self.a_bucket)

        # 非零桶必须超过一半, 否则视为变化不足
        nonzero = 0
        for i in range(CODE_SIZE):
            for j in range(4):
                if self.a_bucket[4 * i + j] > 0:
                    nonzero += 1
        if nonzero <= 4 * CODE_SIZE // 2:
            return False

        for i in range(CODE_SIZE):
            h = 0
            for j in range(4):
                k = self.a_bucket[4 * i + j]
                if q3 < k:
                    h += 3 << (j * 2)
                elif q2 < k:
                    h += 2 << (j * 2)
                elif q1 < k:
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
        out = [
            _swap_byte(self.checksum[0]),
            _swap_byte(self.Lvalue),
            _swap_byte(self.Q),
        ]
        out.extend(self.tmp_code[CODE_SIZE - 1 - i] for i in range(CODE_SIZE))
        return "".join(f"{b:02X}" for b in out)

    def reset(self):
        self.__init__()


def hash_bytes(data):
    """便捷函数: 计算 bytes 的 TLSH, 不适用时返回 None"""
    t = Tlsh()
    t.update(data)
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
    """单字节 body code 差异: 4 个 2-bit 四分位对差异之和 (对应官方 h_distance)"""
    diff = 0
    for a in range(4):
        va = (x >> (a * 2)) & 0x3
        vb = (y >> (a * 2)) & 0x3
        diff += _BIT_PAIRS_DIFF[va][vb]
    return diff


def diff(h1_hex, h2_hex):
    """计算两个 TLSH hex 哈希的距离 (越小越相似, 0=完全相同)。

    算法移植自官方 trendmicro/tlsh 的 lsh_bin_totalDiff:
      1. 校验和 (1 字节): 不同则 +1
      2. 长度值 Lvalue: mod_diff(L1, L2, 256); ldiff==0→+0, ldiff==1→+1, else +ldiff×12
      3. Q 比率 (Q1/Q2 各一): mod_diff(Q1, Q2, 16); qdiff≤1→+qdiff, else +(qdiff-1)×12
      4. body code (32 字节): 逐字节 h_distance 累加

    返回 -1 表示输入无效 (长度不匹配/非 hex)。
    """
    if not h1_hex or not h2_hex:
        return -1
    h1_hex = h1_hex.upper()
    h2_hex = h2_hex.upper()
    # 去除可选的 "T1" 前缀 (py-tlsh 兼容; 用 startswith 而非 lstrip 避免误删合法字符)
    if h1_hex.startswith("T1"):
        h1_hex = h1_hex[2:]
    if h2_hex.startswith("T1"):
        h2_hex = h2_hex[2:]
    if len(h1_hex) != TLSH_STRING_LEN or len(h2_hex) != TLSH_STRING_LEN:
        return -1
    try:
        b1 = bytes.fromhex(h1_hex)
        b2 = bytes.fromhex(h2_hex)
    except ValueError:
        return -1

    total = 0

    # 1. 校验和 (hex byte 0): 不同则 +1 (TLSH_CHECKSUM_LEN=1, 仅 1 字节)
    if b1[0] != b2[0]:
        total += 1

    # 2. 长度值 (hex byte 1, 存储为 _swap_byte(Lvalue)): 反 swap 后做 mod_diff
    l1 = _swap_byte(b1[1])
    l2 = _swap_byte(b2[1])
    ldiff = _mod_diff(l1, l2, RANGE_LVALUE)
    if ldiff == 1:
        total += 1
    elif ldiff > 1:
        total += ldiff * LENGTH_MULT

    # 3. Q 比率 (hex byte 2, 存储为 _swap_byte(Q)):
    #    低 nibble = Q1ratio, 高 nibble = Q2ratio; 各做 mod_diff(q, RANGE_QRATIO=16)
    q1b = _swap_byte(b1[2])
    q2b = _swap_byte(b2[2])
    for qa, qb in [(q1b & 0x0F, q2b & 0x0F), ((q1b >> 4) & 0x0F, (q2b >> 4) & 0x0F)]:
        qdiff = _mod_diff(qa, qb, RANGE_QRATIO)
        if qdiff <= 1:
            total += qdiff
        else:
            total += (qdiff - 1) * QRATIO_MULT

    # 4. body code (hex bytes 3..34, 存储为 tmp_code 反序):
    #    两哈希同序, 逐位 h_distance 累加即可 (反序不影响求和)
    for i in range(CODE_SIZE):
        total += _h_distance(b1[3 + i], b2[3 + i])

    return total


# 别名, 与官方 py-tlsh API 一致
total_diff = diff
