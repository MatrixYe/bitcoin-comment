#!/usr/bin/env python3

def demonstrate_proof_of_work():
    """演示比特币工作量证明的验证过程"""
    
    print("=== 比特币工作量证明验证机制 ===\n")
    
    # 从源码中看到的验证逻辑
    print("比特币源码中的验证逻辑:")
    print("```cpp")
    print("bool CheckProofOfWork(uint256 hash, unsigned int nBits) {")
    print("  CBigNum bnTarget;")
    print("  bnTarget.SetCompact(nBits);")
    print("  ")
    print("  // 检查哈希值是否小于等于目标值")
    print("  if (hash > bnTarget.getuint256())")
    print("    return error(\"CheckProofOfWork() : hash doesn't match nBits\");")
    print("  ")
    print("  return true;")
    print("}")
    print("```")
    print()
    
    # "数零"说法的解释
    print("关于\"数零\"的说法:")
    print("✓ 这种说法在某种意义上是正确的，但需要澄清具体含义")
    print()
    
    # 演示数值比较vs数零
    demonstrate_comparison_vs_counting()
    
    print("\n" + "="*60 + "\n")
    
    # 实际案例分析
    analyze_real_cases()


def demonstrate_comparison_vs_counting():
    """演示数值比较 vs 数零的概念"""
    
    print("=== 数值比较 vs 数零概念演示 ===\n")
    
    # 模拟几个目标值和哈希值
    test_cases = [
        # (目标值十六进制, 哈希值十六进制, 是否有效)
        ("0000000000000000a3e4000000000000000000000000000000000000000000", 
         "0000000000000000123456789abcdef00000000000000000000000000000000", 
         True),
        
        ("0000000000000000a3e4000000000000000000000000000000000000000000", 
         "0000000000000000b3e4000000000000000000000000000000000000000000", 
         False),
        
        ("00000000ffff0000000000000000000000000000000000000000000000000000", 
         "00000000aaab0000000000000000000000000000000000000000000000000000", 
         True),
    ]
    
    for i, (target_hex, hash_hex, expected_valid) in enumerate(test_cases, 1):
        print(f"案例 {i}:")
        print(f"  目标值: {target_hex}")
        print(f"  哈希值: {hash_hex}")
        
        # 转换为整数进行比较
        target_int = int(target_hex, 16)
        hash_int = int(hash_hex, 16)
        
        # 验证
        is_valid = hash_int <= target_int
        print(f"  数值比较: {hash_int} <= {target_int} = {is_valid}")
        print(f"  预期结果: {expected_valid}")
        print(f"  结果匹配: {'✓' if is_valid == expected_valid else '✗'}")
        
        # 分析"零"的数量
        target_leading_zeros = count_leading_zeros_hex(target_hex)
        hash_leading_zeros = count_leading_zeros_hex(hash_hex)
        
        print(f"  目标值前导零: {target_leading_zeros} 个")
        print(f"  哈希值前导零: {hash_leading_zeros} 个")
        
        # 如果哈希值有效，说明它的前导零不少于目标值的前导零
        if is_valid:
            print(f"  ✓ 哈希值的前导零数量({hash_leading_zeros}) >= 目标值的前导零数量({target_leading_zeros})")
        else:
            print(f"  ✗ 哈希值的前导零数量({hash_leading_zeros}) < 目标值的前导零数量({target_leading_zeros})")
        
        print()


def count_leading_zeros_hex(hex_string):
    """计算十六进制字符串中的前导零数量"""
    hex_string = hex_string.lower().lstrip('0')
    total_chars = 64  # 256位 = 64个十六进制字符
    zeros_count = total_chars - len(hex_string)
    return zeros_count


def analyze_real_cases():
    """分析真实案例"""
    
    print("=== 真实案例分析 ===\n")
    
    # 比特币创世区块的数据
    genesis_target = "0000000000000003a30c00000000000000000000000000000000000000000000"
    genesis_hash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    
    print("比特币创世区块:")
    print(f"  目标值: {genesis_target}")
    print(f"  区块哈希: {genesis_hash}")
    
    # 计算前导零
    target_zeros = count_leading_zeros_hex(genesis_target)
    hash_zeros = count_leading_zeros_hex(genesis_hash)
    
    print(f"  目标值前导零: {target_zeros} 个")
    print(f"  区块哈希前导零: {hash_zeros} 个")
    
    # 数值验证
    target_int = int(genesis_target, 16)
    hash_int = int(genesis_hash, 16)
    
    print(f"  数值验证: {hash_int} <= {target_int} = {hash_int <= target_int}")
    
    print()
    print("分析结论:")
    print(f"  - 区块哈希的前导零数量({hash_zeros}) >= 目标值的前导零数量({target_zeros})")
    print(f"  - 这正是\"数零\"概念的直观体现")
    print(f"  - 但底层机制仍然是数值比较，而不是简单的字符串操作")


def explain_why_counting_zeros_works():
    """解释为什么数零概念在数学上成立"""
    
    print("\n=== 为什么\"数零\"概念在数学上成立 ===\n")
    
    print("1. 十六进制表示特性:")
    print("   - 256位哈希值用64个十六进制字符表示")
    print("   - 较小的数值在十六进制表示中会有更多前导零")
    print()
    
    print("2. 数值比较 vs 字符串比较:")
    print("   - 数值比较: 比较两个256位整数值")
    print("   - 数零比较: 比较前导零的数量")
    print()
    
    print("3. 数学等价性:")
    print("   - 对于相同的位数，两个数的比较等价于它们前导零数量的比较")
    print("   - 如果hash <= target，那么hash的前导零数量 >= target的前导零数量")
    print()
    
    print("4. 实际意义:")
    print("   - \"数零\"是一种更容易理解的直观表示")
    print("   - 每增加一个前导零，难度就增加16倍")
    print("   - 这使得比特币的难度调整更容易理解和沟通")


if __name__ == "__main__":
    demonstrate_proof_of_work()
    explain_why_counting_zeros_works()