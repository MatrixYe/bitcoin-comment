// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.


// secp160k1
// const unsigned int PRIVATE_KEY_SIZE = 192;
// const unsigned int PUBLIC_KEY_SIZE  = 41;
// const unsigned int SIGNATURE_SIZE   = 48;
//
// secp192k1
// const unsigned int PRIVATE_KEY_SIZE = 222;
// const unsigned int PUBLIC_KEY_SIZE  = 49;
// const unsigned int SIGNATURE_SIZE   = 57;
//
// secp224k1
// const unsigned int PRIVATE_KEY_SIZE = 250;
// const unsigned int PUBLIC_KEY_SIZE  = 57;
// const unsigned int SIGNATURE_SIZE   = 66;
//
// secp256k1:
// const unsigned int PRIVATE_KEY_SIZE = 279;
// const unsigned int PUBLIC_KEY_SIZE  = 65;
// const unsigned int SIGNATURE_SIZE   = 72;
//
// see www.keylength.com
// script supports up to 75 for single byte push

// 这个头文件的核心是 CKey 类，它为 OpenSSL 库中的 EC_KEY
// （椭圆曲线密钥）提供了一个 C++
// 封装。这个类的主要职责是管理比特币系统中的密钥对（私钥和公钥），并提供使用这些密钥进行数字签名和验证的功能。
/**
 * @brief key_error 异常类，用于报告密钥相关的操作失败。
 *
 * 当底层的 OpenSSL 函数调用返回错误时，会抛出此类型的异常。
 */
class key_error : public std::runtime_error
{
public:
    explicit key_error(const std::string& str) : std::runtime_error(str) {}
};


// secure_allocator 在 serialize.h 中定义。
// CPrivKey 是一个使用安全内存分配器的字节向量，用于存储私钥，
// 以防止私钥数据被操作系统交换到磁盘上。
typedef vector<unsigned char, secure_allocator<unsigned char> > CPrivKey;



/**
 * @brief CKey 类，封装了 OpenSSL 的 EC_KEY，用于管理 ECDSA 密钥对和执行签名/验证操作。
 *
 * 这个类为比特币系统提供了一个高级接口，用于处理基于 secp256k1 曲线的椭圆曲线加密。
 * 它负责密钥的生成、序列化/反序列化以及生命周期管理。
 */
class CKey
{
protected:
    // pkey 是指向 OpenSSL EC_KEY 结构的指针，是实现所有加密操作的核心。
    EC_KEY* pkey;

public:
    /**
     * @brief 构造一个新的 CKey 对象。
     *
     * 初始化一个用于 NID_secp256k1 曲线的 EC_KEY 对象。
     * 如果创建失败，则抛出 key_error 异常。
     */
    CKey()
    {
        pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (pkey == NULL)
            throw key_error("CKey::CKey() : EC_KEY_new_by_curve_name failed");
    }

    /**
     * @brief CKey 的拷贝构造函数。
     *
     * 创建一个现有 CKey 对象的深拷贝。
     * :param b: 要拷贝的源 CKey 对象。
     */
    CKey(const CKey& b)
    {
        pkey = EC_KEY_dup(b.pkey);
        if (pkey == NULL)
            throw key_error("CKey::CKey(const CKey&) : EC_KEY_dup failed");
    }

    /**
     * @brief CKey 的赋值运算符。
     *
     * 将一个 CKey 对象的内容拷贝到另一个对象。
     * :param b: 要赋值的源 CKey 对象。
     * :return: 当前对象的引用。
     */
    CKey& operator=(const CKey& b)
    {
        if (!EC_KEY_copy(pkey, b.pkey))
            throw key_error("CKey::operator=(const CKey&) : EC_KEY_copy failed");
        return (*this);
    }

    /**
     * @brief CKey 的析构函数。
     *
     * 释放 pkey 指向的 EC_KEY 对象，防止内存泄漏。
     */
    ~CKey()
    {
        EC_KEY_free(pkey);
    }

    /**
     * @brief 生成一个新的公私钥对。
     *
     * 如果密钥生成失败，则抛出 key_error 异常。
     */
    void MakeNewKey()
    {
        if (!EC_KEY_generate_key(pkey))
            throw key_error("CKey::MakeNewKey() : EC_KEY_generate_key failed");
    }

    /**
     * @brief 从字节向量设置私钥。
     *
     * 使用 DER 格式的私钥数据来初始化 EC_KEY 对象。
     * :param vchPrivKey: 包含私钥数据的字节向量 (CPrivKey)。
     * :return: 如果设置成功，返回 true；否则返回 false。
     */
    bool SetPrivKey(const CPrivKey& vchPrivKey)
    {
        const unsigned char* pbegin = &vchPrivKey[0];
        if (!d2i_ECPrivateKey(&pkey, &pbegin, vchPrivKey.size()))
            return false;
        return true;
    }

    /**
     * @brief 获取 DER 编码的私钥。
     *
     * 将 EC_KEY 对象中的私钥序列化为 DER 格式的字节向量。
     * :return: 包含私钥的 CPrivKey 字节向量。
     */
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

    /**
     * @brief 静态方法：使用给定的私钥对哈希进行签名。
     *
     * 这是一个便利函数，它会临时创建一个 CKey 对象来执行签名操作。
     * :param vchPrivKey: 用于签名的私钥。
     * :param hash: 要签名的 256 位哈希值。
     * :param vchSig: 用于存储生成的签名的字节向量。
     * :return: 如果签名成功，返回 true；否则返回 false。
     */
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
};
