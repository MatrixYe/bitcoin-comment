---
tags: []
title: 05-key.h源码分析
date: 2026-04-04 09:54:09
updated: 2026-04-06 03:51:20
---

在编码风格上 `key.h` 和 `bignum.h` 是一个画风。都是拿着 OpenSSL 中的一些数据，进行了第二次封装。`key.h` 非常简短。
![[asset/attachments/Pasted image 20260406025050.png]]
## 核心概念
CPrivKey 是一个使用安全内存分配器的字节向量，用于存储私钥
CKey 是对 OpenSSL 库中的 EC_KEY 的二次封装而自定义的一个 class。主要职责是管理比特币系统中的密钥对（私钥和公钥），并提供使用这些密钥进行数字签名和验证的功能。
secp256k1 是 OpenSSL 中提供的一个椭圆曲线，比特币系统使用此曲线作为哈希做签名和验签

## secp256k1 曲线
secp256k1 是一条特定的椭圆曲线，数学形式满足如下：
$$
y^2 = x^3 + ax + b \pmod{p}
$$
比特币选择了其中一个条：
$$
y^2 = x^3 + 7 \pmod{p}
$$
其中 $a=0, b=7$, p 是一个常数为 $0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F$

在这条曲线上，会先选择一个点作为元点，或者叫固定点，称 G 点。
曲线阶 n 是 G 生成的循环群大小，是一个超级大的素数，约 $2^{256}$
私钥是一个随机数，称之 $k$ 他的范围是 $1\leq k\leq {n-1}$
公钥 Q 是曲线上的一个点，它由 G 点经过点乘的来，满足：
$$
Q=k × {G}
$$
点乘是一种运算方式，粗浅的说就是点加的累积，点加就是曲线上两个点，连线之后与椭圆曲线相交叉的点的以 x 周对称的点。如果两个点是同一个点，那么它们的点加就是这个点的切线与椭圆曲线的交叉点的以 x 轴对称的点。点乘是点加的累积，因此 $Q=k × {G}$ 就是 G 点通过 k 次点加得后得到的一个新点，即 Q 点。
私钥就是 $k$，公钥就是 Q，已知 Q=kG 和 G，反向求 k 在计算上是不可行的。这其实很好理解，所谓点乘其实是一种 " 变换关系 "，很多时候，这种变换关系是完全不可逆的。一个不大恰当的比喻是，一个人从杭州出发，向东走 100 公里到上海，这是可以计算的。但是如果告诉你起点是杭州，终点是上海，请问行走的路径是怎样的就不知道了。

## 密钥的生成
密钥的生成分两种，一是随机生成，而是通过其他密钥构建。

通过 secp256k1 阶内生成随机私钥（32 字节），然后通过椭圆曲线乘法计算公钥，并存储密钥。
```c++
void MakeNewKey()
{
    if (!EC_KEY_generate_key(pkey))
        throw key_error("CKey::MakeNewKey() : EC_KEY_generate_key failed");
}
```

## 私钥的导入和导出
私钥导入
```cpp
bool SetPrivKey(const CPrivKey& vchPrivKey)
{
    const unsigned char* pbegin = &vchPrivKey[0];
    if (!d2i_ECPrivateKey(&pkey, &pbegin, vchPrivKey.size()))
        return false;
    return true;
}
```
私钥导出
```cpp
CPrivKey GetPrivKey() const
{
    unsigned int nSize = i2d_ECPrivateKey(pkey, NULL);
    if (!nSize)
        throw key_error("CKey::GetPrivKey() : i2d_ECPrivateKey failed");
    CPrivKey vchPrivKey(nSize, 0);
    unsigned char* pbegin = &vchPrivKey[0];
    if (i2d_ECPrivateKey(pkey, &pbegin) != nSize)
        throw key_error("CKey::GetPrivKey() : i2d_ECPrivateKey returned unexpected size");
    return vchPrivKey;
}
```

## 公钥的导入和导出
公钥导入：
```cpp
 /**
     * @brief 从字节向量设置公钥。
     *
     * 使用 DER 格式的公钥数据来初始化 EC_KEY 对象。
     * :param vchPubKey: 包含公钥数据的字节向量。
     * :return: 如果设置成功，返回 true；否则返回 false。
     */
    bool SetPubKey(const vector<unsigned char>& vchPubKey)
    {
        const unsigned char* pbegin = &vchPubKey[0];
        if (!o2i_ECPublicKey(&pkey, &pbegin, vchPubKey.size()))
            return false;
        return true;
    }

    /**
     * @brief 获取 DER 编码的公钥。
     *
     * 将 EC_KEY 对象中的公钥序列化为 DER 格式的字节向量。
     * :return: 包含公钥的字节向量。
     */
    vector<unsigned char> GetPubKey() const
    {
        unsigned int nSize = i2o_ECPublicKey(pkey, NULL);
        if (!nSize)
            throw key_error("CKey::GetPubKey() : i2o_ECPublicKey failed");
        vector<unsigned char> vchPubKey(nSize, 0);
        unsigned char* pbegin = &vchPubKey[0];
        if (i2o_ECPublicKey(pkey, &pbegin) != nSize)
            throw key_error("CKey::GetPubKey() : i2o_ECPublicKey returned unexpected size");
        return vchPubKey;
    }
```

## 签名和验证签名

签名是 Ckey 的内部方法，需要提供等待签名的哈希，以及一个用于存储签名结果的容器。
```cpp
   /**
     * @brief 对给定的哈希进行签名。
     *
     * 使用此对象的私钥生成一个 ECDSA 签名。
     * :param hash: 要签名的 256 位哈希值。
     * :param vchSig: 用于存储生成的签名的字节向量。
     * :return: 如果签名成功，返回 true；否则返回 false。
     */
    bool Sign(uint256 hash, vector<unsigned char>& vchSig)
    {
        vchSig.clear();
        unsigned char pchSig[10000];
        unsigned int nSize = 0;
        if (!ECDSA_sign(0, (unsigned char*)&hash, sizeof(hash), pchSig, &nSize, pkey))
            return false;
        vchSig.resize(nSize);
        memcpy(&vchSig[0], pchSig, nSize);
        return true;
    }
```

验证签名需要提供原始数据哈希，以及签名结果，实际上还需要公钥，但因为在 Ckey 内部所以省略了。
```cpp


    /**
     * @brief 验证给定的哈希和签名。
     *
     * 使用此对象的公钥验证签名是否与哈希匹配。
     * :param hash: 被签名的 256 位哈希值。
     * :param vchSig: 要验证的签名。
     * :return: 如果签名有效，返回 true；否则返回 false。
     */
    bool Verify(uint256 hash, const vector<unsigned char>& vchSig)
    {
        // -1 = 错误, 0 = 签名错误, 1 = 签名正确
        if (ECDSA_verify(0, (unsigned char*)&hash, sizeof(hash), &vchSig[0], vchSig.size(), pkey) != 1)
            return false;
        return true;
    }
```

## 签名和验证签名 2
真正的核心方法其实是下面两个静态方法。
```cpp
    static bool Sign(const CPrivKey& vchPrivKey, uint256 hash, vector<unsigned char>& vchSig)
    {
        CKey key;
        if (!key.SetPrivKey(vchPrivKey))
            return false;
        return key.Sign(hash, vchSig);
    }

    /**
     * @brief 静态方法：使用给定的公钥验证签名。
     *
     * 这是一个便利函数，它会临时创建一个 CKey 对象来执行验证操作。
     * :param vchPubKey: 用于验证的公钥。
     * :param hash: 被签名的 256 位哈希值。
     * :param vchSig: 要验证的签名。
     * :return: 如果签名有效，返回 true；否则返回 false。
     */
    static bool Verify(const vector<unsigned char>& vchPubKey, uint256 hash, const vector<unsigned char>& vchSig)
    {
        CKey key;
        if (!key.SetPubKey(vchPubKey))
            return false;
        return key.Verify(hash, vchSig);
    }
```
这里完整的演示了签名的条件和目标，以及验证的条件和目标。
签名的输入是待签名数据、私钥，输出是签名结果 Sig
验证的输入是待签名数据、公钥，和签名结果 Sig

## 公钥的压缩
公钥其实是曲线上的一个点，但 `key.h` 源码里面没有写公钥要不要压缩。实际上比特币都采用了压缩后的公钥格式。

## 构造和析构
涉及到 c++ 的内存管理，不考虑。
