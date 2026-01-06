import math


def nbits_to_target(nbits_hex):
    """
    将nBits值转换为目标值（target）

    参数:
        nbits_hex: 字符串形式的nBits十六进制值（如"1d00ffff"）

    返回:
        目标值的十六进制字符串表示
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

    # 提取指数部分（高24位）
    exponent = nbits >> 24

    # 提取尾数部分（低24位）
    mantissa = nbits & 0x00FFFFFF

    # 处理尾数的符号扩展（如果第24位为1，表示负数）
    # 在比特币中，nBits使用有符号的24位尾数
    if mantissa & 0x00800000:
        mantissa |= 0xFF000000  # 符号扩展

    # 特殊情况：指数为0时表示特殊值
    if exponent == 0:
        return "0" * 64  # 返回全零的256位值

    # 计算目标值
    # 目标值 = mantissa * 256^(exponent - 3)
    # 这里使用Python的大整数运算
    target = mantissa * (256 ** (exponent - 3))

    # 将结果转换为64个字符的十六进制字符串（256位）
    target_hex = format(target, "064x")

    return target_hex


def calculate_mining_difficulty(nbits_hex):
    """
    根据nBits值计算挖矿难度

    参数:
        nbits_hex: nBits的十六进制字符串表示

    返回:
        挖矿难度值（相对于初始难度的倍数）
    """
    # 转换nBits到目标值
    target_hex = nbits_to_target(nbits_hex)
    target = int(target_hex, 16)

    # 初始目标值（创世区块的目标值）
    genesis_target_hex = (
        "00000000ffff0000000000000000000000000000000000000000000000000000"
    )
    genesis_target = int(genesis_target_hex, 16)

    # 计算难度：难度 = 初始目标值 / 当前目标值
    difficulty = genesis_target / target

    return difficulty


def calculate_mining_success_probability(nbits_hex, attempts=1):
    """
    计算基于nBits值的挖矿成功概率

    参数:
        nbits_hex: nBits的十六进制字符串表示
        attempts: 哈希尝试次数（默认1次）

    返回:
        在指定尝试次数内成功挖到区块的概率
    """
    # 转换nBits到目标值
    target_hex = nbits_to_target(nbits_hex)
    target = int(target_hex, 16)

    # SHA-256哈希空间大小
    hash_space = 2**256

    # 单次尝试成功的概率
    single_attempt_prob = target / hash_space

    # 在attempts次尝试内至少成功一次的概率
    # 使用几何分布的累积分布函数
    # P(至少成功一次) = 1 - P(全部失败)
    success_probability = 1 - (1 - single_attempt_prob) ** attempts

    return success_probability


def calculate_expected_hashes_for_success(nbits_hex):
    """
    计算成功挖到一个区块所需的期望哈希次数

    参数:
        nbits_hex: nBits的十六进制字符串表示

    返回:
        期望的哈希尝试次数
    """
    # 转换nBits到目标值
    target_hex = nbits_to_target(nbits_hex)
    target = int(target_hex, 16)

    # SHA-256哈希空间大小
    hash_space = 2**256

    # 单次尝试成功的概率
    single_attempt_prob = target / hash_space

    # 期望尝试次数 = 1 / 单次成功概率
    expected_attempts = 1 / single_attempt_prob

    return expected_attempts


def calculate_hash_rate_for_target_time(nbits_hex, target_time_seconds):
    """
    计算在指定时间内成功挖到一个区块所需的哈希速率

    参数:
        nbits_hex: nBits的十六进制字符串表示
        target_time_seconds: 目标时间（秒）

    返回:
        所需的哈希速率（H/s）
    """
    # 计算期望的哈希尝试次数
    expected_attempts = calculate_expected_hashes_for_success(nbits_hex)

    # 所需哈希速率 = 期望尝试次数 / 目标时间
    required_hash_rate = expected_attempts / target_time_seconds

    return required_hash_rate


# 挖矿概率可视化示例
def plot_mining_probability(nbits_hex, max_attempts=1000000):
    """
    绘制挖矿成功概率随尝试次数变化的图表

    参数:
        nbits_hex: nBits的十六进制字符串表示
        max_attempts: 最大尝试次数
    """
    import matplotlib.pyplot as plt
    import numpy as np

    # 生成尝试次数序列
    attempts = np.logspace(0, math.log10(max_attempts), num=1000)

    # 计算对应的成功概率
    probabilities = [
        calculate_mining_success_probability(nbits_hex, int(a)) for a in attempts
    ]

    # 绘制图表
    plt.figure(figsize=(10, 6))
    plt.semilogx(attempts, probabilities)
    plt.xlabel("尝试次数")
    plt.ylabel("成功概率")
    plt.title(f"nBits={nbits_hex}的挖矿成功概率")
    plt.grid(True, which="both", ls="-")
    plt.show()


# 完整示例
if __name__ == "__main__":
    # 测试用例：比特币创世区块的nBits值
    genesis_nbits = "1d00ffff"

    print("比特币创世区块挖矿分析")
    print(f"nBits值：{genesis_nbits}")

    # 计算挖矿难度
    difficulty = calculate_mining_difficulty(genesis_nbits)
    print(f"挖矿难度：{difficulty:.2f}")

    # 计算单次尝试成功概率
    prob = calculate_mining_success_probability(genesis_nbits, 1)
    print(f"单次尝试成功概率：{prob:.2e}")

    # 计算期望哈希次数
    expected_hashes = calculate_expected_hashes_for_success(genesis_nbits)
    print(f"期望哈希次数：{expected_hashes:.2e}")

    # 计算在10分钟内成功所需的哈希速率
    hash_rate = calculate_hash_rate_for_target_time(genesis_nbits, 10 * 60)
    print(f"10分钟内成功所需的哈希速率：{hash_rate:.2e} H/s")

    # 计算100万次尝试的成功概率
    prob_1m = calculate_mining_success_probability(genesis_nbits, 1000000)
    print(f"100万次尝试的成功概率：{prob_1m:.6f}")
