def decimal_nbit_to_target(decimal_nbit):
    """
    将十进制nBit值转换为十六进制，提取指数、尾数，并计算目标值（target）
    参数:
        decimal_nbit: int - 十进制的nBit值
    返回:
        dict - 包含十六进制nBit、指数（十进制/十六进制）、尾数（十进制/十六进制）、目标值（十进制/64位十六进制）
    """
    # 1. 将十进制nBit转换为32位无符号整数（确保符合比特币nBit格式）
    nbit_uint32 = decimal_nbit & 0xFFFFFFFF  # 约束为32位无符号整数
    # 转换为8位十六进制字符串（带0x前缀，小写，补前导零）
    nbit_hex = f"0x{nbit_uint32:08x}"
    nbit_hex_upper = f"0x{nbit_uint32:08X}"  # 大写格式，更贴近区块浏览器展示

    # 2. 提取指数（高8位，1字节）
    exponent_dec = (nbit_uint32 >> 24) & 0xFF  # 右移24位后，取低8位（确保1字节范围）
    exponent_hex = f"0x{exponent_dec:02x}"
    exponent_hex_upper = f"0x{exponent_dec:02X}"

    # 3. 提取尾数（低24位，3字节，无符号）
    mantissa_dec = nbit_uint32 & 0x00FFFFFF  # 与0x00FFFFFF按位与，提取低24位
    mantissa_hex = f"0x{mantissa_dec:06x}"
    mantissa_hex_upper = f"0x{mantissa_dec:06X}"

    # 4. 计算目标值（target = mantissa × 256^(exponent - 3)）
    if exponent_dec == 0:
        # 特殊情况：指数为0，目标值为全零
        target_dec = 0
        target_hex_64 = "0" * 64
    else:
        power = exponent_dec - 3
        target_dec = mantissa_dec * (256 ** power)
        # 转换为64位十六进制字符串（256位，补前导零，小写）
        target_hex_64 = f"{target_dec:064x}"
        # 可选：大写格式
        target_hex_64_upper = f"{target_dec:064X}"

    # 整理结果
    result = {
        "十进制nBit": decimal_nbit,
        "32位无符号nBit": nbit_uint32,
        "十六进制nBit（小写，8位）": nbit_hex,
        "十六进制nBit（大写，8位）": nbit_hex_upper,
        "指数（十进制）": exponent_dec,
        "指数（十六进制，2位）": exponent_hex,
        "指数（十六进制大写，2位）": exponent_hex_upper,
        "尾数（十进制）": mantissa_dec,
        "尾数（十六进制，6位）": mantissa_hex,
        "尾数（十六进制大写，6位）": mantissa_hex_upper,
        "目标值（十进制）": target_dec,
        "目标值（64位十六进制小写）": target_hex_64,
        "目标值（64位十六进制大写）": target_hex_64.upper() if target_dec !=0 else "0"*64
    }

    return result

def compare_hash_and_target(block_hash_str, target_hex_64, target_dec):
    """
    规范化区块哈希字符串，并比较区块哈希与目标值的大小，判断是否符合PoW要求
    参数:
        block_hash_str: str - 原始区块哈希字符串（可能含空格、长度不足64位）
        target_hex_64: str - 64位十六进制目标值（小写/大写均可）
        target_dec: int - 十进制目标值
    返回:
        dict - 包含规范化哈希、哈希十进制、大小比较结果、PoW有效性判断
    """
    # 1. 规范化区块哈希字符串
    normalized_hash = block_hash_str.strip()  # 去除前后空格
    normalized_hash = normalized_hash.lower()  # 统一转为小写
    # 补前导零至64位（确保与目标值位数一致，避免转换整数偏差）
    if len(normalized_hash) < 64:
        normalized_hash = normalized_hash.zfill(64)
    elif len(normalized_hash) > 64:
        # 若哈希长度超过64位，截取前64位（实际比特币哈希都是64位十六进制）
        normalized_hash = normalized_hash[:64]

    # 2. 将规范化后的哈希转换为十进制整数
    try:
        block_hash_dec = int(normalized_hash, 16)
    except ValueError as e:
        raise ValueError(f"无效的区块哈希格式，无法转换为整数：{e}")

    # 3. 比较大小
    hash_less_than_target = block_hash_dec <= target_dec
    hash_equal_target = block_hash_dec == target_dec
    hash_greater_than_target = block_hash_dec > target_dec

    # 4. 判断PoW有效性（比特币规则：哈希值 ≤ 目标值 则有效）
    pow_valid = hash_less_than_target

    # 整理结果
    compare_result = {
        "原始区块哈希": block_hash_str,
        "规范化区块哈希（64位小写）": normalized_hash,
        "规范化区块哈希（64位大写）": normalized_hash.upper(),
        "区块哈希（十进制）": block_hash_dec,
        "目标值（十进制）": target_dec,
        "哈希 ≤ 目标值": hash_less_than_target,
        "哈希 = 目标值": hash_equal_target,
        "哈希 > 目标值": hash_greater_than_target,
        "是否符合工作量证明（PoW）": pow_valid
    }

    return compare_result

# 主程序：处理nBit=386000389，并比较指定区块哈希
if __name__ == "__main__":
    # 1. 输入参数
    decimal_nbit = 386000389
    block_hash_str = " 0000000000000000000095c94376daa5924b119bff55dbb7e82748baf493380c"  # 区块哈希

    # 2. 执行nBit转换和目标值计算
    nbit_target_result = decimal_nbit_to_target(decimal_nbit)

    # 3. 提取目标值关键参数（用于比较）
    target_hex_64 = nbit_target_result["目标值（64位十六进制小写）"]
    target_dec = nbit_target_result["目标值（十进制）"]

    # 4. 执行哈希与目标值的比较
    try:
        compare_result = compare_hash_and_target(block_hash_str, target_hex_64, target_dec)
    except ValueError as e:
        print(f"错误：{e}")
        exit(1)

    # 5. 逐行打印完整结果
    print("=" * 80)
    print(f"输入十进制nBit值：{nbit_target_result['十进制nBit']}")
    print("=" * 80)
    print(f"1. nBit 转换结果：")
    print(f"   32位十六进制nBit（大写）：{nbit_target_result['十六进制nBit（大写，8位）']}")
    print(f"   指数（十进制）：{nbit_target_result['指数（十进制）']}（十六进制：{nbit_target_result['指数（十六进制大写，2位）']}）")
    print(f"   尾数（十进制）：{nbit_target_result['尾数（十进制）']}（十六进制：{nbit_target_result['尾数（十六进制大写，6位）']}）")
    print("=" * 80)
    print(f"2. 目标值（target）结果：")
    print(f"   十进制（大整数）：{nbit_target_result['目标值（十进制）']}")
    print(f"   64位十六进制（大写）：{nbit_target_result['目标值（64位十六进制大写）']}")
    print("=" * 80)
    print(f"3. 区块哈希与目标值比较结果：")
    print(f"   原始区块哈希：{compare_result['原始区块哈希']}")
    print(f"   规范化区块哈希（大写）：{compare_result['规范化区块哈希（64位大写）']}")
    print(f"   区块哈希（十进制）：{compare_result['区块哈希（十进制）']}")
    print(f"   目标值（十进制）：{compare_result['目标值（十进制）']}")
    print(f"   哈希 ≤ 目标值：{compare_result['哈希 ≤ 目标值']}")
    print(f"   哈希 = 目标值：{compare_result['哈希 = 目标值']}")
    print(f"   哈希 > 目标值：{compare_result['哈希 > 目标值']}")
    print(f"   是否符合工作量证明：{compare_result['是否符合工作量证明（PoW）']}")
    print("=" * 80)