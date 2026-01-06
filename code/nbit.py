def nbits_to_target(nbits_hex):
    """
    将nBits值转换为目标值（target）

    参数:
        nbits_hex: 字符串形式的nBits十六进制值（如"1d00ffff"）

    返回:
        目标值的十六进制字符串表示（64个字符，256位）
    """
    # 输入验证
    if not isinstance(nbits_hex, str):
        raise TypeError("nBits必须是字符串形式的十六进制数")

    # 去除可能的"0x"前缀
    nbits_hex = nbits_hex.lower()
    if nbits_hex.startswith("0x"):
        nbits_hex = nbits_hex[2:]

    # 检查十六进制字符串的有效性
    if not all(c in "0123456789abcdef" for c in nbits_hex):
        raise ValueError("nBits必须是有效的十六进制数")

    # 确保nBits长度为8个字符（32位）
    if len(nbits_hex) != 8:
        raise ValueError("nBits必须是8个十六进制字符（32位）")

    # 将十六进制转换为整数
    nbits = int(nbits_hex, 16)

    # 提取指数部分（高8位，1字节）
    exponent = nbits >> 24

    # 提取尾数部分（低24位，3字节，无符号，无需符号扩展）
    mantissa = nbits & 0x00FFFFFF

    # 特殊情况：指数为0时表示特殊值
    if exponent == 0:
        return "0" * 64  # 返回全零的256位值

    # 计算目标值：target = mantissa * 256^(exponent - 3)
    target = mantissa * (256 ** (exponent - 3))

    # 将结果转换为64个字符的十六进制字符串（256位，小写）
    target_hex = format(target, "064x")

    return target_hex


def target_to_nbits(target_hex):
    """
    将目标值转换回nBits格式

    参数:
        target_hex: 目标值的十六进制字符串表示（64个字符，256位）

    返回:
        nBits的十六进制字符串表示（带0x前缀，8个字符，32位）
    """
    # 输入验证
    if not isinstance(target_hex, str):
        raise TypeError("目标值必须是字符串形式的十六进制数")

    # 去除可能的"0x"前缀
    target_hex = target_hex.lower()
    if target_hex.startswith("0x"):
        target_hex = target_hex[2:]

    # 检查十六进制字符串的有效性
    if not all(c in "0123456789abcdef" for c in target_hex):
        raise ValueError("目标值必须是有效的十六进制数")

    # 确保目标值长度为64个字符（256位）
    if len(target_hex) != 64:
        raise ValueError("目标值必须是64个十六进制字符（256位）")

    # 将十六进制转换为整数
    target = int(target_hex, 16)

    # 处理特殊情况：target为0
    if target == 0:
        return "0x00000000"  # 返回全零的nBits值

    # 计算target的字节长度（不含前导零）
    target_bytes_length = (target.bit_length() + 7) // 8

    # 确定指数和尾数（修正核心逻辑：exponent始终等于target_bytes_length）
    mantissa = 0
    exponent = target_bytes_length  # 关键修正：不再赋值为0
    if target_bytes_length <= 3:
        # 小目标值：左移补零至3字节（24位）
        shift = (3 - target_bytes_length) * 8
        mantissa = target << shift
    else:
        # 大目标值：右移提取前3字节（24位）
        shift = (target_bytes_length - 3) * 8
        mantissa = target >> shift

    # 确保尾数在24位无符号范围内（直接截断，无需符号扩展）
    mantissa = mantissa & 0x00FFFFFF

    # 计算nBits：高8位指数 + 低24位尾数
    nbits = (exponent << 24) | mantissa

    # 将结果转换为带0x前缀的8字符十六进制字符串（32位）
    nbits_hex = "0x" + format(nbits, "08x")

    return nbits_hex


# 测试函数
if __name__ == "__main__":
    # 测试用例1：比特币创世区块nBits
    genesis_nbits = "0x1903a30c"
    # 测试用例2：比特币难度上限nBits（原测试失败的用例）
    max_diff_nbits = "0x1d00ffff"

    # 批量测试
    for test_nbits in [genesis_nbits, max_diff_nbits]:
        print("=" * 50)
        print(f"测试用例：{test_nbits}")
        print(f"原始nBits值：{test_nbits}")

        # 转换为目标值
        target = nbits_to_target(test_nbits)
        print(f"转换后目标值：{target}")

        # 转换回nBits值
        reconstructed_nbits = target_to_nbits(target)
        print(f"重构的nBits值：{reconstructed_nbits}")

        # 验证转换一致性（忽略大小写，因原始值可能大写，重构值为小写）
        if test_nbits.lower() == reconstructed_nbits.lower():
            print("✅ 转换正确！")
        else:
            print("❌ 转换错误！")
        print("=" * 50 + "\n")