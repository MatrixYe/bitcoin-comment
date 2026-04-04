// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

// 比特币大数运算封装文件
// 功能：封装OpenSSL的BIGNUM库，提供大数运算支持
// 应用场景：椭圆曲线密码学、数字签名验证、挖矿难度计算等

#include <stdexcept>
#include <vector>
#include <openssl/bn.h>





class bignum_error : public std::runtime_error // 大数运算异常类
{
public:
    explicit bignum_error(const std::string& str) : std::runtime_error(str) {}
};



class CAutoBN_CTX // 自动管理OpenSSL BN_CTX上下文的RAII类
{
protected:
    BN_CTX* pctx; // OpenSSL大数运算上下文
    BN_CTX* operator=(BN_CTX* pnew) { return pctx = pnew; }

public:
    CAutoBN_CTX() // 构造函数：创建BN_CTX上下文
    {
        pctx = BN_CTX_new();
        if (pctx == NULL)
            throw bignum_error("CAutoBN_CTX : BN_CTX_new() returned NULL");
    }

    ~CAutoBN_CTX() // 析构函数：释放BN_CTX上下文
    {
        if (pctx != NULL)
            BN_CTX_free(pctx);
    }

    operator BN_CTX*() { return pctx; } // 转换为BN_CTX指针
    BN_CTX& operator*() { return *pctx; } // 解引用
    BN_CTX** operator&() { return &pctx; } // 取地址
    bool operator!() { return (pctx == NULL); } // 逻辑非运算
};



class CBigNum : public BIGNUM // 大数运算封装类，继承自OpenSSL的BIGNUM
{
public:
    CBigNum() // 默认构造函数
    {
        BN_init(this);
    }

    CBigNum(const CBigNum& b) // 拷贝构造函数
    {
        BN_init(this);
        if (!BN_copy(this, &b))
        {
            BN_clear_free(this);
            throw bignum_error("CBigNum::CBigNum(const CBigNum&) : BN_copy failed");
        }
    }

    explicit CBigNum(const std::string& str) // 从十六进制字符串构造
    {
        BN_init(this);
        SetHex(str);
    }

    CBigNum& operator=(const CBigNum& b) // 赋值运算符
    {
        if (!BN_copy(this, &b))
            throw bignum_error("CBigNum::operator= : BN_copy failed");
        return (*this);
    }

    ~CBigNum() // 析构函数
    {
        BN_clear_free(this);
    }

    // 从各种整数类型构造
    CBigNum(char n)             { BN_init(this); if (n >= 0) setulong(n); else setint64(n); }
    CBigNum(short n)            { BN_init(this); if (n >= 0) setulong(n); else setint64(n); }
    CBigNum(int n)              { BN_init(this); if (n >= 0) setulong(n); else setint64(n); }
    CBigNum(long n)             { BN_init(this); if (n >= 0) setulong(n); else setint64(n); }
    CBigNum(int64 n)            { BN_init(this); setint64(n); }
    CBigNum(unsigned char n)    { BN_init(this); setulong(n); }
    CBigNum(unsigned short n)   { BN_init(this); setulong(n); }
    CBigNum(unsigned int n)     { BN_init(this); setulong(n); }
    CBigNum(unsigned long n)    { BN_init(this); setulong(n); }
    CBigNum(uint64 n)           { BN_init(this); setuint64(n); }
    explicit CBigNum(uint256 n) { BN_init(this); setuint256(n); }

    explicit CBigNum(const std::vector<unsigned char>& vch) // 从字节数组构造
    {
        BN_init(this);
        setvch(vch);
    }

    void setulong(unsigned long n) // 设置为无符号长整型
    {
        if (!BN_set_word(this, n))
            throw bignum_error("CBigNum conversion from unsigned long : BN_set_word failed");
    }

    unsigned long getulong() const // 获取无符号长整型值
    {
        return BN_get_word(this);
    }

    unsigned int getuint() const // 获取无符号整型值
    {
        return BN_get_word(this);
    }

    int getint() const // 获取整型值
    {
        unsigned long n = BN_get_word(this);
        if (!BN_is_negative(this))
            return (n > INT_MAX ? INT_MAX : n);
        else
            return (n > INT_MAX ? INT_MIN : -(int)n);
    }

    void setint64(int64 n) // 设置为64位有符号整数
    {
        unsigned char pch[sizeof(n) + 6];
        unsigned char* p = pch + 4;
        bool fNegative = false;
        if (n < (int64)0)
        {
            n = -n;
            fNegative = true;
        }
        bool fLeadingZeroes = true;
        for (int i = 0; i < 8; i++)
        {
            unsigned char c = (n >> 56) & 0xff;
            n <<= 8;
            if (fLeadingZeroes)
            {
                if (c == 0)
                    continue;
                if (c & 0x80)
                    *p++ = (fNegative ? 0x80 : 0);
                else if (fNegative)
                    c |= 0x80;
                fLeadingZeroes = false;
            }
            *p++ = c;
        }
        unsigned int nSize = p - (pch + 4);
        pch[0] = (nSize >> 24) & 0xff;
        pch[1] = (nSize >> 16) & 0xff;
        pch[2] = (nSize >> 8) & 0xff;
        pch[3] = (nSize) & 0xff;
        BN_mpi2bn(pch, p - pch, this);
    }

    void setuint64(uint64 n) // 设置为64位无符号整数
    {
        unsigned char pch[sizeof(n) + 6];
        unsigned char* p = pch + 4;
        bool fLeadingZeroes = true;
        for (int i = 0; i < 8; i++)
        {
            unsigned char c = (n >> 56) & 0xff;
            n <<= 8;
            if (fLeadingZeroes)
            {
                if (c == 0)
                    continue;
                if (c & 0x80)
                    *p++ = 0;
                fLeadingZeroes = false;
            }
            *p++ = c;
        }
        unsigned int nSize = p - (pch + 4);
        pch[0] = (nSize >> 24) & 0xff;
        pch[1] = (nSize >> 16) & 0xff;
        pch[2] = (nSize >> 8) & 0xff;
        pch[3] = (nSize) & 0xff;
        BN_mpi2bn(pch, p - pch, this);
    }

    void setuint256(uint256 n) // 设置为256位无符号整数
    {
        unsigned char pch[sizeof(n) + 6];
        unsigned char* p = pch + 4;
        bool fLeadingZeroes = true;
        unsigned char* pbegin = (unsigned char*)&n;
        unsigned char* psrc = pbegin + sizeof(n);
        while (psrc != pbegin)
        {
            unsigned char c = *(--psrc);
            if (fLeadingZeroes)
            {
                if (c == 0)
                    continue;
                if (c & 0x80)
                    *p++ = 0;
                fLeadingZeroes = false;
            }
            *p++ = c;
        }
        unsigned int nSize = p - (pch + 4);
        pch[0] = (nSize >> 24) & 0xff;
        pch[1] = (nSize >> 16) & 0xff;
        pch[2] = (nSize >> 8) & 0xff;
        pch[3] = (nSize >> 0) & 0xff;
        BN_mpi2bn(pch, p - pch, this);
    }

    uint256 getuint256() // 获取256位无符号整数值
    {
        unsigned int nSize = BN_bn2mpi(this, NULL);
        if (nSize < 4)
            return 0;
        std::vector<unsigned char> vch(nSize);
        BN_bn2mpi(this, &vch[0]);
        if (vch.size() > 4)
            vch[4] &= 0x7f;
        uint256 n = 0;
        for (int i = 0, j = vch.size()-1; i < sizeof(n) && j >= 4; i++, j--)
            ((unsigned char*)&n)[i] = vch[j];
        return n;
    }

    void setvch(const std::vector<unsigned char>& vch) // 从字节数组设置值
    {
        std::vector<unsigned char> vch2(vch.size() + 4);
        unsigned int nSize = vch.size();
        vch2[0] = (nSize >> 24) & 0xff;
        vch2[1] = (nSize >> 16) & 0xff;
        vch2[2] = (nSize >> 8) & 0xff;
        vch2[3] = (nSize >> 0) & 0xff;
        reverse_copy(vch.begin(), vch.end(), vch2.begin() + 4);
        BN_mpi2bn(&vch2[0], vch2.size(), this);
    }

    std::vector<unsigned char> getvch() const // 获取字节数组表示
    {
        unsigned int nSize = BN_bn2mpi(this, NULL);
        if (nSize < 4)
            return std::vector<unsigned char>();
        std::vector<unsigned char> vch(nSize);
        BN_bn2mpi(this, &vch[0]);
        vch.erase(vch.begin(), vch.begin() + 4);
        reverse(vch.begin(), vch.end());
        return vch;
    }

    CBigNum& SetCompact(unsigned int nCompact) // 从紧凑格式设置值（用于挖矿难度）
    {
        unsigned int nSize = nCompact >> 24;
        std::vector<unsigned char> vch(4 + nSize);
        vch[3] = nSize;
        if (nSize >= 1) vch[4] = (nCompact >> 16) & 0xff;
        if (nSize >= 2) vch[5] = (nCompact >> 8) & 0xff;
        if (nSize >= 3) vch[6] = (nCompact >> 0) & 0xff;
        BN_mpi2bn(&vch[0], vch.size(), this);
        return *this;
    }

    unsigned int GetCompact() const // 获取紧凑格式表示（用于挖矿难度）
    {
        unsigned int nSize = BN_bn2mpi(this, NULL);
        std::vector<unsigned char> vch(nSize);
        nSize -= 4;
        BN_bn2mpi(this, &vch[0]);
        unsigned int nCompact = nSize << 24;
        if (nSize >= 1) nCompact |= (vch[4] << 16);
        if (nSize >= 2) nCompact |= (vch[5] << 8);
        if (nSize >= 3) nCompact |= (vch[6] << 0);
        return nCompact;
    }

    void SetHex(const std::string& str) // 从十六进制字符串设置值
    {
        // skip 0x 跳过0x前缀
        const char* psz = str.c_str();
        while (isspace(*psz))
            psz++;
        bool fNegative = false;
        if (*psz == '-')
        {
            fNegative = true;
            psz++;
        }
        if (psz[0] == '0' && tolower(psz[1]) == 'x')
            psz += 2;
        while (isspace(*psz))
            psz++;

        // hex string to bignum 将十六进制字符串转换为大整数
        static char phexdigit[256] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,1,2,3,4,5,6,7,8,9,0,0,0,0,0,0, 0,0xa,0xb,0xc,0xd,0xe,0xf,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0xa,0xb,0xc,0xd,0xe,0xf,0,0,0,0,0,0,0,0,0 };
        *this = 0;
        while (isxdigit(*psz))
        {
            *this <<= 4;
            int n = phexdigit[*psz++];
            *this += n;
        }
        if (fNegative)
            *this = 0 - *this;
    }

    unsigned int GetSerializeSize(int nType=0, int nVersion=VERSION) const // 获取序列化后的大小
    {
        return ::GetSerializeSize(getvch(), nType, nVersion);
    }

    template<typename Stream>
    void Serialize(Stream& s, int nType=0, int nVersion=VERSION) const // 序列化到流
    {
        ::Serialize(s, getvch(), nType, nVersion);
    }

    template<typename Stream>
    void Unserialize(Stream& s, int nType=0, int nVersion=VERSION) // 从流反序列化
    {
        vector<unsigned char> vch;
        ::Unserialize(s, vch, nType, nVersion);
        setvch(vch);
    }


    bool operator!() const // 逻辑非运算符：检查是否为零
    {
        return BN_is_zero(this);
    }

    CBigNum& operator+=(const CBigNum& b) // 加法赋值运算符
    {
        if (!BN_add(this, this, &b))
            throw bignum_error("CBigNum::operator+= : BN_add failed");
        return *this;
    }

    CBigNum& operator-=(const CBigNum& b) // 减法赋值运算符
    {
        *this = *this - b;
        return *this;
    }

    CBigNum& operator*=(const CBigNum& b) // 乘法赋值运算符
    {
        CAutoBN_CTX pctx;
        if (!BN_mul(this, this, &b, pctx))
            throw bignum_error("CBigNum::operator*= : BN_mul failed");
        return *this;
    }

    CBigNum& operator/=(const CBigNum& b) // 除法赋值运算符
    {
        *this = *this / b;
        return *this;
    }

    CBigNum& operator%=(const CBigNum& b) // 取模赋值运算符
    {
        *this = *this % b;
        return *this;
    }

    CBigNum& operator<<=(unsigned int shift) // 左移赋值运算符
    {
        if (!BN_lshift(this, this, shift))
            throw bignum_error("CBigNum:operator<<= : BN_lshift failed");
        return *this;
    }

    CBigNum& operator>>=(unsigned int shift) // 右移赋值运算符
    {
        if (!BN_rshift(this, this, shift))
            throw bignum_error("CBigNum:operator>>= : BN_rshift failed");
        return *this;
    }


    CBigNum& operator++() // 前置自增运算符
    {
        // prefix operator
        if (!BN_add(this, this, BN_value_one()))
            throw bignum_error("CBigNum::operator++ : BN_add failed");
        return *this;
    }

    const CBigNum operator++(int) // 后置自增运算符
    {
        // postfix operator
        const CBigNum ret = *this;
        ++(*this);
        return ret;
    }

    CBigNum& operator--() // 前置自减运算符
    {
        // prefix operator
        CBigNum r;
        if (!BN_sub(&r, this, BN_value_one()))
            throw bignum_error("CBigNum::operator-- : BN_sub failed");
        *this = r;
        return *this;
    }

    const CBigNum operator--(int) // 后置自减运算符
    {
        // postfix operator
        const CBigNum ret = *this;
        --(*this);
        return ret;
    }


    friend inline const CBigNum operator-(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator/(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator%(const CBigNum& a, const CBigNum& b);
};



inline const CBigNum operator+(const CBigNum& a, const CBigNum& b) // 加法运算符
{
    CBigNum r;
    if (!BN_add(&r, &a, &b))
        throw bignum_error("CBigNum::operator+ : BN_add failed");
    return r;
}

inline const CBigNum operator-(const CBigNum& a, const CBigNum& b) // 减法运算符
{
    CBigNum r;
    if (!BN_sub(&r, &a, &b))
        throw bignum_error("CBigNum::operator- : BN_sub failed");
    return r;
}

inline const CBigNum operator-(const CBigNum& a) // 取负运算符
{
    CBigNum r(a);
    BN_set_negative(&r, !BN_is_negative(&r));
    return r;
}

inline const CBigNum operator*(const CBigNum& a, const CBigNum& b) // 乘法运算符
{
    CAutoBN_CTX pctx;
    CBigNum r;
    if (!BN_mul(&r, &a, &b, pctx))
        throw bignum_error("CBigNum::operator* : BN_mul failed");
    return r;
}

inline const CBigNum operator/(const CBigNum& a, const CBigNum& b) // 除法运算符
{
    CAutoBN_CTX pctx;
    CBigNum r;
    if (!BN_div(&r, NULL, &a, &b, pctx))
        throw bignum_error("CBigNum::operator/ : BN_div failed");
    return r;
}

inline const CBigNum operator%(const CBigNum& a, const CBigNum& b) // 取模运算符
{
    CAutoBN_CTX pctx;
    CBigNum r;
    if (!BN_mod(&r, &a, &b, pctx))
        throw bignum_error("CBigNum::operator% : BN_div failed");
    return r;
}

inline const CBigNum operator<<(const CBigNum& a, unsigned int shift) // 左移运算符
{
    CBigNum r;
    if (!BN_lshift(&r, &a, shift))
        throw bignum_error("CBigNum:operator<< : BN_lshift failed");
    return r;
}

inline const CBigNum operator>>(const CBigNum& a, unsigned int shift) // 右移运算符
{
    CBigNum r;
    if (!BN_rshift(&r, &a, shift))
        throw bignum_error("CBigNum:operator>> : BN_rshift failed");
    return r;
}

inline bool operator==(const CBigNum& a, const CBigNum& b) { return (BN_cmp(&a, &b) == 0); } // 等于比较
inline bool operator!=(const CBigNum& a, const CBigNum& b) { return (BN_cmp(&a, &b) != 0); } // 不等于比较
inline bool operator<=(const CBigNum& a, const CBigNum& b) { return (BN_cmp(&a, &b) <= 0); } // 小于等于比较
inline bool operator>=(const CBigNum& a, const CBigNum& b) { return (BN_cmp(&a, &b) >= 0); } // 大于等于比较
inline bool operator<(const CBigNum& a, const CBigNum& b)  { return (BN_cmp(&a, &b) < 0); } // 小于比较
inline bool operator>(const CBigNum& a, const CBigNum& b)  { return (BN_cmp(&a, &b) > 0); } // 大于比较
