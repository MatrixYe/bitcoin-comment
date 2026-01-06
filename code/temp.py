def arith_uint256_get_compact(x, f_negative):
    """
    对应C++函数：uint32_t arith_uint256::GetCompact(bool fNegative) const
    将256位无符号整数（arith_uint256）转换为compact格式（nBits）

    参数:
        x: int - 输入的256位以内无符号整数（对应C++的arith_uint256实例）
        f_negative: bool - 是否为负数标志（比特币中target恒为正，此参数主要兼容通用逻辑）

    返回:
        int - 32位无符号整数（compact格式，即nBits，范围0~0xFFFFFFFF）
    """
    # 1. 计算nSize：对应C++的 (bits() + 7) / 8
    # bits()是arith_uint256的二进制位数（不含前导零），对应Python的bit_length()
    if x == 0:
        bit_count = 0
    else:
        bit_count = x.bit_length()
    n_size = (bit_count + 7) // 8  # 整数除法，等价于C++的(bits()+7)/8

    n_compact = 0
    # 2. 分情况计算尾数部分（nCompact初始值）
    if n_size <= 3:
        # 对应C++：nCompact = GetLow64() << 8 * (3 - nSize);
        # GetLow64()：获取arith_uint256的最低64位，Python中用 & 0xFFFFFFFFFFFFFFFF 实现
        low_64 = x & 0xFFFFFFFFFFFFFFFF  # 提取低64位（8字节）
        shift_bits = 8 * (3 - n_size)
        n_compact = low_64 << shift_bits
    else:
        # 对应C++：arith_uint256 bn = *this >> 8 * (nSize - 3); nCompact = bn.GetLow64();
        shift_bits = 8 * (n_size - 3)
        bn = x >> shift_bits  # 右移操作
        n_compact = bn & 0xFFFFFFFFFFFFFFFF  # 提取右移后结果的低64位

    # 3. 处理0x00800000标志位：若该位已置1，右移8位并增加nSize
    # 对应C++：if (nCompact & 0x00800000) { nCompact >>= 8; nSize++; }
    if n_compact & 0x00800000:
        n_compact >>= 8
        n_size += 1

    # 4. 断言检查（对应C++的assert）
    # 断言1：nCompact的高9位及以上全为0（确保尾数在23位范围内：0x007fffff是23位全1）
    assert (n_compact & ~0x007FFFFF) == 0, "nCompact超出23位尾数范围"
    # 断言2：nSize小于256（确保指数部分在1字节范围内，可存入uint32_t的高8位）
    assert n_size < 256, "nSize超出1字节范围（必须小于256）"

    # 5. 组装最终nCompact：填充高8位的nSize
    # 对应C++：nCompact |= nSize << 24;
    n_compact |= n_size << 24

    # 6. 处理符号位：若fNegative为真且尾数非零，置0x00800000位
    # 对应C++：nCompact |= (fNegative && (nCompact & 0x007fffff) ? 0x00800000 : 0);
    if f_negative and (n_compact & 0x007FFFFF):
        n_compact |= 0x00800000

    # 7. 确保返回值是32位无符号整数（对应C++的uint32_t）
    n_compact = n_compact & 0xFFFFFFFF

    return n_compact

if __name__ == "__main__":
    # 测试1：对应比特币难度上限target（对应nBits=0x1d00ffff）
    # target = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
    target_max = 0xFFFF << (8 * (29 - 3))  # 等价于0x1d00ffff对应的target
    nbits = arith_uint256_get_compact(target_max, f_negative=False)
    # 转换为8位十六进制字符串（带0x前缀）
    nbits_hex = "0x" + format(nbits, "08x")
    print(f"目标值对应的nBits：{nbits_hex}")  # 输出：0x1d00ffff，与预期一致

    # 测试2：创世区块target对应nBits=0x1903a30c
    genesis_target = 0x03a30c << (8 * (25 - 3))
    genesis_nbits = arith_uint256_get_compact(genesis_target, f_negative=False)
    genesis_nbits_hex = "0x" + format(genesis_nbits, "08x")
    print(f"创世区块nBits：{genesis_nbits_hex}")  # 输出：0x1903a30c，与预期一致