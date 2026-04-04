---
tags: []
title: 02-bignum.h 源码分析
date: 2026-04-03 05:11:57
updated: 2026-04-03 06:12:19
---

## 做了什么
`bignum.h` 与 `uint256.h` 一样，都是提供对超大数的支持。`uint256.h` 中定义的 `uint256` 和 `uint160` 两种类型的数据分别是 32 字节的整数和 20 字节的整数。而在 bignum. h 中，同样定一个了新的大数类型 `CBigNum`, 不同的是，这个类是对 OpenSSL 这个密码学第三方库的二次封装。

在 `bignum. h` 中，做了三件事：
1. 定义一个新的数据类型 `CBigNum` 继承自 OpenSSL 的数据类型 BIGNUM
2. 为 `CBigNum` 定义了大部分大数运算的所有功能，同样使用运算符重载
3. 内存回收 (C++ 特色)，错误定义

## 为什么需要这个
比特币中大量使用了密码学的相关方法，ECDSA 签名验证、密钥生成，验证比特币交易的数字签名，处理工作量证明中的大数运算，这些都需要使用 OpenSSL 提供的大数 BIGNUM，直接用也可以，但是不够直观，因此这里中本聪做了一层转化，用二次定义和运算符重载的方式来让涉及到密码学相关的计算过程要更直观一点。

## 构造函数
构造函数提供了一些列数据转化，将各种其他不同类型转化为 CBigNum 类型
```c++
// 从各种整数类型构造

CBigNum(char n) { BN_init(this); if (n >= 0) setulong(n); else setint64(n); }

CBigNum(short n) { BN_init(this); if (n >= 0) setulong(n); else setint64(n); }

CBigNum(int n) { BN_init(this); if (n >= 0) setulong(n); else setint64(n); }

CBigNum(long n) { BN_init(this); if (n >= 0) setulong(n); else setint64(n); }

CBigNum(int64 n) { BN_init(this); setint64(n); }

CBigNum(unsigned char n) { BN_init(this); setulong(n); }

CBigNum(unsigned short n) { BN_init(this); setulong(n); }

CBigNum(unsigned int n) { BN_init(this); setulong(n); }

CBigNum(unsigned long n) { BN_init(this); setulong(n); }

CBigNum(uint64 n) { BN_init(this); setuint64(n); }

explicit CBigNum(uint256 n) { BN_init(this); setuint256(n); }
```
从字节数组转化的构造要特殊一点，因为使用了 explicit 修饰，禁止构造函数被隐式调用（禁止自动类型转换），所以这个方法只能显式调用。
```c++
explicit CBigNum(const std::vector<unsigned char>& vch) // 从字节数组构造
{
BN_init(this);
setvch(vch);
}
```

## 类型方法
```c++
inline const CBigNum operator+(const CBigNum& a, const CBigNum& b) // 加法运算符

inline const CBigNum operator-(const CBigNum& a, const CBigNum& b) // 减法运算符

inline const CBigNum operator-(const CBigNum& a) // 取负运算符

inline const CBigNum operator*(const CBigNum& a, const CBigNum& b) // 乘法运算符

inline const CBigNum operator/(const CBigNum& a, const CBigNum& b) // 除法运算符

inline const CBigNum operator%(const CBigNum& a, const CBigNum& b) // 取模运算符

inline const CBigNum operator<<(const CBigNum& a, unsigned int shift) // 左移运算符

inline const CBigNum operator>>(const CBigNum& a, unsigned int shift) // 右移运算符
```

## 其他工具方法

除了定义类方法之外，还提供了一些工具方法，用于对两个 CBigNum 对象进行某种运算。
```c++
inline bool operator==(const CBigNum& a, const CBigNum& b) { return (BN_cmp(&a, &b) == 0); } // 等于比较

inline bool operator!=(const CBigNum& a, const CBigNum& b) { return (BN_cmp(&a, &b) != 0); } // 不等于比较

inline bool operator<=(const CBigNum& a, const CBigNum& b) { return (BN_cmp(&a, &b) <= 0); } // 小于等于比较

inline bool operator>=(const CBigNum& a, const CBigNum& b) { return (BN_cmp(&a, &b) >= 0); } // 大于等于比较

inline bool operator<(const CBigNum& a, const CBigNum& b) { return (BN_cmp(&a, &b) < 0); } // 小于比较

inline bool operator>(const CBigNum& a, const CBigNum& b) { return (BN_cmp(&a, &b) > 0); } // 大于比较
```

不得不说写 c++ 写程序就是考虑比较细，上面的方法中全部使用 `inline` 修饰，`inline` 表示这些函数都是内联函数，相当于告诉编译器，这个函数尽量不要调用，而是直接把代码复制粘贴到调用处，省去函数调用开销。

普通函数的调用流程是：调用点 → 跳转到函数 → 执行代码 → 跳回来
使用内联函数后就变成了：调用点 → 直接把函数代码贴在这里执行

## CAutoBN_CTX 类
这个类应该是自动管理 OpenSSL BN_CTX 上下文的 RAII 类，让上下文及时的销毁，防止内存溢出。实话说我没看太懂，一些 c++ 的指针搞来搞去我也不知道在干啥。但大意还是清楚，毕竟在 c++ 中，回收内存这种事情完全由程序员自己完成。
