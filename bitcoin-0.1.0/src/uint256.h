// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

// 比特币大整数类型定义文件
// 功能：提供160位和256位无符号整数的实现，用于存储哈希值和地址
// 应用场景：SHA-256哈希值(256位)、RIPEMD-160哈希值(160位)、比特币地址等

#include <limits.h>
#include <string>
#if defined(_MSC_VER) || defined(__BORLANDC__)
typedef __int64 int64;
typedef unsigned __int64 uint64;
#else
typedef long long int64;
typedef unsigned long long uint64;
#endif
#if defined(_MSC_VER) && _MSC_VER < 1300
#define for                                                                    \
  if (false)                                                                   \
    ;                                                                          \
  else for
#endif

inline int Testuint256AdHoc(vector<string> vArg);

// We have to keep a separate base class without constructors
// so the compiler will let us use it in a union
// 我们需要保持一个没有构造函数的独立基类，以便编译器允许我们在联合体中使用它
template <unsigned int BITS> class base_uint {
protected:
  enum { WIDTH = BITS / 32 }; // 计算需要多少个32位整数来存储BITS位的大整数
  unsigned int pn[WIDTH];     // 用数组存储大整数的各个部分，每个元素32位
public:
  bool operator!() const // 逻辑非运算符：检查是否为零
  {
    for (int i = 0; i < WIDTH; i++)
      if (pn[i] != 0)
        return false;
    return true;
  }

  const base_uint operator~() const // 按位取反运算符
  {
    base_uint ret;
    for (int i = 0; i < WIDTH; i++)
      ret.pn[i] = ~pn[i];
    return ret;
  }

  const base_uint operator-() const // 取负运算符（用于实现减法）
  {
    base_uint ret;
    for (int i = 0; i < WIDTH; i++)
      ret.pn[i] = ~pn[i];
    ret++;
    return ret;
  }

  base_uint &operator=(uint64 b) // 从64位整数赋值
  {
    pn[0] = (unsigned int)b;
    pn[1] = (unsigned int)(b >> 32);
    for (int i = 2; i < WIDTH; i++)
      pn[i] = 0;
    return *this;
  }

  base_uint &operator^=(const base_uint &b) // 按位异或赋值
  {
    for (int i = 0; i < WIDTH; i++)
      pn[i] ^= b.pn[i];
    return *this;
  }

  base_uint &operator&=(const base_uint &b) // 按位与赋值
  {
    for (int i = 0; i < WIDTH; i++)
      pn[i] &= b.pn[i];
    return *this;
  }

  base_uint &operator|=(const base_uint &b) // 按位或赋值
  {
    for (int i = 0; i < WIDTH; i++)
      pn[i] |= b.pn[i];
    return *this;
  }

  base_uint &operator^=(uint64 b) // 与64位整数按位异或
  {
    pn[0] ^= (unsigned int)b;
    pn[1] ^= (unsigned int)(b >> 32);
    return *this;
  }

  base_uint &operator&=(uint64 b) // 与64位整数按位与
  {
    pn[0] &= (unsigned int)b;
    pn[1] &= (unsigned int)(b >> 32);
    return *this;
  }

  base_uint &operator|=(uint64 b) // 与64位整数按位或
  {
    pn[0] |= (unsigned int)b;
    pn[1] |= (unsigned int)(b >> 32);
    return *this;
  }

  base_uint &operator<<=(unsigned int shift) // 左移赋值运算符
  {
    base_uint a(*this);
    for (int i = 0; i < WIDTH; i++)
      pn[i] = 0;
    int k = shift / 32; // 计算需要移动多少个32位块
    shift = shift % 32; // 计算剩余的位移量
    for (int i = 0; i < WIDTH; i++) {
      if (i + k + 1 < WIDTH && shift != 0)
        pn[i + k + 1] |= (a.pn[i] >> (32 - shift)); // 处理跨块的高位部分
      if (i + k < WIDTH)
        pn[i + k] |= (a.pn[i] << shift); // 处理低位部分
    }
    return *this;
  }

  base_uint &operator>>=(unsigned int shift) // 右移赋值运算符
  {
    base_uint a(*this);
    for (int i = 0; i < WIDTH; i++)
      pn[i] = 0;
    int k = shift / 32; // 计算需要移动多少个32位块
    shift = shift % 32; // 计算剩余的位移量
    for (int i = 0; i < WIDTH; i++) {
      if (i - k - 1 >= 0 && shift != 0)
        pn[i - k - 1] |= (a.pn[i] << (32 - shift)); // 处理跨块的低位部分
      if (i - k >= 0)
        pn[i - k] |= (a.pn[i] >> shift); // 处理高位部分
    }
    return *this;
  }

  base_uint &operator+=(const base_uint &b) // 加法赋值运算符
  {
    uint64 carry = 0; // 进位标志
    for (int i = 0; i < WIDTH; i++) {
      uint64 n = carry + pn[i] + b.pn[i];
      pn[i] = n & 0xffffffff; // 保留低32位
      carry = n >> 32;        // 计算进位
    }
    return *this;
  }

  base_uint &operator-=(const base_uint &b) // 减法赋值运算符
  {
    *this += -b; // 通过取负后相加实现减法
    return *this;
  }

  base_uint &operator+=(uint64 b64) // 与64位整数相加
  {
    base_uint b;
    b = b64;
    *this += b;
    return *this;
  }

  base_uint &operator-=(uint64 b64) // 与64位整数相减
  {
    base_uint b;
    b = b64;
    *this += -b;
    return *this;
  }

  base_uint &operator++() // 前置自增运算符
  {
    // prefix operator
    int i = 0;
    while (++pn[i] == 0 && i < WIDTH - 1)
      i++;
    return *this;
  }

  const base_uint operator++(int) // 后置自增运算符
  {
    // postfix operator
    const base_uint ret = *this;
    ++(*this);
    return ret;
  }

  base_uint &operator--() // 前置自减运算符
  {
    // prefix operator
    int i = 0;
    while (--pn[i] == -1 && i < WIDTH - 1)
      i++;
    return *this;
  }

  const base_uint operator--(int) // 后置自减运算符
  {
    // postfix operator
    const base_uint ret = *this;
    --(*this);
    return ret;
  }

  friend inline bool operator<(const base_uint &a,
                               const base_uint &b) // 小于比较运算符
  {
    for (int i = base_uint::WIDTH - 1; i >= 0; i--) // 从高位开始比较
    {
      if (a.pn[i] < b.pn[i])
        return true;
      else if (a.pn[i] > b.pn[i])
        return false;
    }
    return false;
  }

  friend inline bool operator<=(const base_uint &a,
                                const base_uint &b) // 小于等于比较运算符
  {
    for (int i = base_uint::WIDTH - 1; i >= 0; i--) {
      if (a.pn[i] < b.pn[i])
        return true;
      else if (a.pn[i] > b.pn[i])
        return false;
    }
    return true;
  }

  friend inline bool operator>(const base_uint &a,
                               const base_uint &b) // 大于比较运算符
  {
    for (int i = base_uint::WIDTH - 1; i >= 0; i--) {
      if (a.pn[i] > b.pn[i])
        return true;
      else if (a.pn[i] < b.pn[i])
        return false;
    }
    return false;
  }

  friend inline bool operator>=(const base_uint &a,
                                const base_uint &b) // 大于等于比较运算符
  {
    for (int i = base_uint::WIDTH - 1; i >= 0; i--) {
      if (a.pn[i] > b.pn[i])
        return true;
      else if (a.pn[i] < b.pn[i])
        return false;
    }
    return true;
  }

  friend inline bool operator==(const base_uint &a,
                                const base_uint &b) // 等于比较运算符
  {
    for (int i = 0; i < base_uint::WIDTH; i++)
      if (a.pn[i] != b.pn[i])
        return false;
    return true;
  }

  friend inline bool operator==(const base_uint &a,
                                uint64 b) // 与64位整数比较是否相等
  {
    if (a.pn[0] != (unsigned int)b)
      return false;
    if (a.pn[1] != (unsigned int)(b >> 32))
      return false;
    for (int i = 2; i < base_uint::WIDTH; i++)
      if (a.pn[i] != 0)
        return false;
    return true;
  }

  friend inline bool operator!=(const base_uint &a,
                                const base_uint &b) // 不等于比较运算符
  {
    return (!(a == b));
  }

  friend inline bool operator!=(const base_uint &a,
                                uint64 b) // 与64位整数比较是否不相等
  {
    return (!(a == b));
  }

  std::string GetHex() const // 获取十六进制字符串表示
  {
    char psz[sizeof(pn) * 2 + 1];
    for (int i = 0; i < sizeof(pn); i++)
      sprintf(
          psz + i * 2, "%02x",
          ((unsigned char *)pn)[sizeof(pn) - i - 1]); // 按大端序转换为十六进制
    return string(psz, psz + sizeof(pn) * 2);
  }

  void SetHex(const std::string &str) // 从十六进制字符串设置值
  {
    for (int i = 0; i < WIDTH; i++)
      pn[i] = 0;

    // skip 0x 跳过0x前缀
    const char *psz = str.c_str();
    while (isspace(*psz))
      psz++;
    if (psz[0] == '0' && tolower(psz[1]) == 'x')
      psz += 2;
    while (isspace(*psz))
      psz++;

    // hex string to uint 将十六进制字符串转换为大整数
    static char phexdigit[256] = {
        0, 0,   0,   0,   0,   0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,   0,   0,   0,   0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,   0,   0,   0,   0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,   2,   3,   4,   5,   6,   7, 8, 9, 0, 0, 0, 0, 0, 0,
        0, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,   0,   0,   0,   0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    const char *pbegin = psz;
    while (phexdigit[*psz] || *psz == '0')
      psz++;
    psz--;
    unsigned char *p1 = (unsigned char *)pn;
    unsigned char *pend = p1 + WIDTH * 4;
    while (psz >= pbegin && p1 < pend) {
      *p1 = phexdigit[(unsigned char)*psz--];
      if (psz >= pbegin) {
        *p1 |= (phexdigit[(unsigned char)*psz--] << 4);
        p1++;
      }
    }
  }

  std::string ToString() const // 转换为字符串
  {
    return (GetHex());
  }

  unsigned char *begin() // 返回数据起始指针
  {
    return (unsigned char *)&pn[0];
  }

  unsigned char *end() // 返回数据结束指针
  {
    return (unsigned char *)&pn[WIDTH];
  }

  unsigned int size() // 返回数据大小
  {
    return sizeof(pn);
  }

  unsigned int
  GetSerializeSize(int nType = 0,
                   int nVersion = VERSION) const // 获取序列化后的大小
  {
    return sizeof(pn);
  }

  template <typename Stream>
  void Serialize(Stream &s, int nType = 0,
                 int nVersion = VERSION) const // 序列化到流
  {
    s.write((char *)pn, sizeof(pn));
  }

  template <typename Stream>
  void Unserialize(Stream &s, int nType = 0,
                   int nVersion = VERSION) // 从流反序列化
  {
    s.read((char *)pn, sizeof(pn));
  }

  friend class uint160;
  friend class uint256;
  friend inline int Testuint256AdHoc(vector<string> vArg);
};

typedef base_uint<160> base_uint160; // 160位无符号整数基类
typedef base_uint<256> base_uint256; // 256位无符号整数基类

//
// uint160 and uint256 could be implemented as templates, but to keep
// compile errors and debugging cleaner, they're copy and pasted.
// It's safe to search and replace 160 with 256 and vice versa.
// uint160和uint256可以用模板实现，但为了保持编译错误和调试更清晰，它们是复制粘贴的
// 可以安全地搜索替换160和256
//

//////////////////////////////////////////////////////////////////////////////
//
// uint160 - 160位无符号整数类
// 用于存储比特币地址（RIPEMD-160哈希值）
//

class uint160 : public base_uint160 {
public:
  typedef base_uint160 basetype;

  uint160() // 默认构造函数
  {}

  uint160(const basetype &b) // 从基类构造
  {
    for (int i = 0; i < WIDTH; i++)
      pn[i] = b.pn[i];
  }

  uint160 &operator=(const basetype &b) // 从基类赋值
  {
    for (int i = 0; i < WIDTH; i++)
      pn[i] = b.pn[i];
    return *this;
  }

  uint160(uint64 b) // 从64位整数构造
  {
    pn[0] = (unsigned int)b;
    pn[1] = (unsigned int)(b >> 32);
    for (int i = 2; i < WIDTH; i++)
      pn[i] = 0;
  }

  uint160 &operator=(uint64 b) // 从64位整数赋值
  {
    pn[0] = (unsigned int)b;
    pn[1] = (unsigned int)(b >> 32);
    for (int i = 2; i < WIDTH; i++)
      pn[i] = 0;
    return *this;
  }

  explicit uint160(const std::string &str) // 从十六进制字符串构造
  {
    SetHex(str);
  }

  explicit uint160(const std::vector<unsigned char> &vch) // 从字节数组构造
  {
    if (vch.size() == sizeof(pn))
      memcpy(pn, &vch[0], sizeof(pn));
    else
      *this = 0;
  }
};

inline bool operator==(const uint160 &a, uint64 b) {
  return (base_uint160)a == b;
}
inline bool operator!=(const uint160 &a, uint64 b) {
  return (base_uint160)a != b;
}
inline const uint160 operator<<(const base_uint160 &a, unsigned int shift) {
  return uint160(a) <<= shift;
}
inline const uint160 operator>>(const base_uint160 &a, unsigned int shift) {
  return uint160(a) >>= shift;
}
inline const uint160 operator<<(const uint160 &a, unsigned int shift) {
  return uint160(a) <<= shift;
}
inline const uint160 operator>>(const uint160 &a, unsigned int shift) {
  return uint160(a) >>= shift;
}

inline const uint160 operator^(const base_uint160 &a, const base_uint160 &b) {
  return uint160(a) ^= b;
}
inline const uint160 operator&(const base_uint160 &a, const base_uint160 &b) {
  return uint160(a) &= b;
}
inline const uint160 operator|(const base_uint160 &a, const base_uint160 &b) {
  return uint160(a) |= b;
}
inline const uint160 operator+(const base_uint160 &a, const base_uint160 &b) {
  return uint160(a) += b;
}
inline const uint160 operator-(const base_uint160 &a, const base_uint160 &b) {
  return uint160(a) -= b;
}

inline bool operator<(const base_uint160 &a, const uint160 &b) {
  return (base_uint160)a < (base_uint160)b;
}
inline bool operator<=(const base_uint160 &a, const uint160 &b) {
  return (base_uint160)a <= (base_uint160)b;
}
inline bool operator>(const base_uint160 &a, const uint160 &b) {
  return (base_uint160)a > (base_uint160)b;
}
inline bool operator>=(const base_uint160 &a, const uint160 &b) {
  return (base_uint160)a >= (base_uint160)b;
}
inline bool operator==(const base_uint160 &a, const uint160 &b) {
  return (base_uint160)a == (base_uint160)b;
}
inline bool operator!=(const base_uint160 &a, const uint160 &b) {
  return (base_uint160)a != (base_uint160)b;
}
inline const uint160 operator^(const base_uint160 &a, const uint160 &b) {
  return (base_uint160)a ^ (base_uint160)b;
}
inline const uint160 operator&(const base_uint160 &a, const uint160 &b) {
  return (base_uint160)a & (base_uint160)b;
}
inline const uint160 operator|(const base_uint160 &a, const uint160 &b) {
  return (base_uint160)a | (base_uint160)b;
}
inline const uint160 operator+(const base_uint160 &a, const uint160 &b) {
  return (base_uint160)a + (base_uint160)b;
}
inline const uint160 operator-(const base_uint160 &a, const uint160 &b) {
  return (base_uint160)a - (base_uint160)b;
}

inline bool operator<(const uint160 &a, const base_uint160 &b) {
  return (base_uint160)a < (base_uint160)b;
}
inline bool operator<=(const uint160 &a, const base_uint160 &b) {
  return (base_uint160)a <= (base_uint160)b;
}
inline bool operator>(const uint160 &a, const base_uint160 &b) {
  return (base_uint160)a > (base_uint160)b;
}
inline bool operator>=(const uint160 &a, const base_uint160 &b) {
  return (base_uint160)a >= (base_uint160)b;
}
inline bool operator==(const uint160 &a, const base_uint160 &b) {
  return (base_uint160)a == (base_uint160)b;
}
inline bool operator!=(const uint160 &a, const base_uint160 &b) {
  return (base_uint160)a != (base_uint160)b;
}
inline const uint160 operator^(const uint160 &a, const base_uint160 &b) {
  return (base_uint160)a ^ (base_uint160)b;
}
inline const uint160 operator&(const uint160 &a, const base_uint160 &b) {
  return (base_uint160)a & (base_uint160)b;
}
inline const uint160 operator|(const uint160 &a, const base_uint160 &b) {
  return (base_uint160)a | (base_uint160)b;
}
inline const uint160 operator+(const uint160 &a, const base_uint160 &b) {
  return (base_uint160)a + (base_uint160)b;
}
inline const uint160 operator-(const uint160 &a, const base_uint160 &b) {
  return (base_uint160)a - (base_uint160)b;
}

inline bool operator<(const uint160 &a, const uint160 &b) {
  return (base_uint160)a < (base_uint160)b;
}
inline bool operator<=(const uint160 &a, const uint160 &b) {
  return (base_uint160)a <= (base_uint160)b;
}
inline bool operator>(const uint160 &a, const uint160 &b) {
  return (base_uint160)a > (base_uint160)b;
}
inline bool operator>=(const uint160 &a, const uint160 &b) {
  return (base_uint160)a >= (base_uint160)b;
}
inline bool operator==(const uint160 &a, const uint160 &b) {
  return (base_uint160)a == (base_uint160)b;
}
inline bool operator!=(const uint160 &a, const uint160 &b) {
  return (base_uint160)a != (base_uint160)b;
}
inline const uint160 operator^(const uint160 &a, const uint160 &b) {
  return (base_uint160)a ^ (base_uint160)b;
}
inline const uint160 operator&(const uint160 &a, const uint160 &b) {
  return (base_uint160)a & (base_uint160)b;
}
inline const uint160 operator|(const uint160 &a, const uint160 &b) {
  return (base_uint160)a | (base_uint160)b;
}
inline const uint160 operator+(const uint160 &a, const uint160 &b) {
  return (base_uint160)a + (base_uint160)b;
}
inline const uint160 operator-(const uint160 &a, const uint160 &b) {
  return (base_uint160)a - (base_uint160)b;
}

//////////////////////////////////////////////////////////////////////////////
//
// uint256 - 256位无符号整数类
// 用于存储SHA-256哈希值、区块哈希、交易哈希等
//

class uint256 : public base_uint256 {
public:
  typedef base_uint256 basetype;

  uint256() // 默认构造函数
  {}

  uint256(const basetype &b) // 从基类构造
  {
    for (int i = 0; i < WIDTH; i++)
      pn[i] = b.pn[i];
  }

  uint256 &operator=(const basetype &b) // 从基类赋值
  {
    for (int i = 0; i < WIDTH; i++)
      pn[i] = b.pn[i];
    return *this;
  }

  uint256(uint64 b) // 从64位整数构造
  {
    pn[0] = (unsigned int)b;
    pn[1] = (unsigned int)(b >> 32);
    for (int i = 2; i < WIDTH; i++)
      pn[i] = 0;
  }

  uint256 &operator=(uint64 b) // 从64位整数赋值
  {
    pn[0] = (unsigned int)b;
    pn[1] = (unsigned int)(b >> 32);
    for (int i = 2; i < WIDTH; i++)
      pn[i] = 0;
    return *this;
  }

  explicit uint256(const std::string &str) // 从十六进制字符串构造
  {
    SetHex(str);
  }

  explicit uint256(const std::vector<unsigned char> &vch) // 从字节数组构造
  {
    if (vch.size() == sizeof(pn))
      memcpy(pn, &vch[0], sizeof(pn));
    else
      *this = 0;
  }
};

inline bool operator==(const uint256 &a, uint64 b) {
  return (base_uint256)a == b;
}
inline bool operator!=(const uint256 &a, uint64 b) {
  return (base_uint256)a != b;
}
inline const uint256 operator<<(const base_uint256 &a, unsigned int shift) {
  return uint256(a) <<= shift;
}
inline const uint256 operator>>(const base_uint256 &a, unsigned int shift) {
  return uint256(a) >>= shift;
}
inline const uint256 operator<<(const uint256 &a, unsigned int shift) {
  return uint256(a) <<= shift;
}
inline const uint256 operator>>(const uint256 &a, unsigned int shift) {
  return uint256(a) >>= shift;
}

inline const uint256 operator^(const base_uint256 &a, const base_uint256 &b) {
  return uint256(a) ^= b;
}
inline const uint256 operator&(const base_uint256 &a, const base_uint256 &b) {
  return uint256(a) &= b;
}
inline const uint256 operator|(const base_uint256 &a, const base_uint256 &b) {
  return uint256(a) |= b;
}
inline const uint256 operator+(const base_uint256 &a, const base_uint256 &b) {
  return uint256(a) += b;
}
inline const uint256 operator-(const base_uint256 &a, const base_uint256 &b) {
  return uint256(a) -= b;
}

inline bool operator<(const base_uint256 &a, const uint256 &b) {
  return (base_uint256)a < (base_uint256)b;
}
inline bool operator<=(const base_uint256 &a, const uint256 &b) {
  return (base_uint256)a <= (base_uint256)b;
}
inline bool operator>(const base_uint256 &a, const uint256 &b) {
  return (base_uint256)a > (base_uint256)b;
}
inline bool operator>=(const base_uint256 &a, const uint256 &b) {
  return (base_uint256)a >= (base_uint256)b;
}
inline bool operator==(const base_uint256 &a, const uint256 &b) {
  return (base_uint256)a == (base_uint256)b;
}
inline bool operator!=(const base_uint256 &a, const uint256 &b) {
  return (base_uint256)a != (base_uint256)b;
}
inline const uint256 operator^(const base_uint256 &a, const uint256 &b) {
  return (base_uint256)a ^ (base_uint256)b;
}
inline const uint256 operator&(const base_uint256 &a, const uint256 &b) {
  return (base_uint256)a & (base_uint256)b;
}
inline const uint256 operator|(const base_uint256 &a, const uint256 &b) {
  return (base_uint256)a | (base_uint256)b;
}
inline const uint256 operator+(const base_uint256 &a, const uint256 &b) {
  return (base_uint256)a + (base_uint256)b;
}
inline const uint256 operator-(const base_uint256 &a, const uint256 &b) {
  return (base_uint256)a - (base_uint256)b;
}

inline bool operator<(const uint256 &a, const base_uint256 &b) {
  return (base_uint256)a < (base_uint256)b;
}
inline bool operator<=(const uint256 &a, const base_uint256 &b) {
  return (base_uint256)a <= (base_uint256)b;
}
inline bool operator>(const uint256 &a, const base_uint256 &b) {
  return (base_uint256)a > (base_uint256)b;
}
inline bool operator>=(const uint256 &a, const base_uint256 &b) {
  return (base_uint256)a >= (base_uint256)b;
}
inline bool operator==(const uint256 &a, const base_uint256 &b) {
  return (base_uint256)a == (base_uint256)b;
}
inline bool operator!=(const uint256 &a, const base_uint256 &b) {
  return (base_uint256)a != (base_uint256)b;
}
inline const uint256 operator^(const uint256 &a, const base_uint256 &b) {
  return (base_uint256)a ^ (base_uint256)b;
}
inline const uint256 operator&(const uint256 &a, const base_uint256 &b) {
  return (base_uint256)a & (base_uint256)b;
}
inline const uint256 operator|(const uint256 &a, const base_uint256 &b) {
  return (base_uint256)a | (base_uint256)b;
}
inline const uint256 operator+(const uint256 &a, const base_uint256 &b) {
  return (base_uint256)a + (base_uint256)b;
}
inline const uint256 operator-(const uint256 &a, const base_uint256 &b) {
  return (base_uint256)a - (base_uint256)b;
}

inline bool operator<(const uint256 &a, const uint256 &b) {
  return (base_uint256)a < (base_uint256)b;
}
inline bool operator<=(const uint256 &a, const uint256 &b) {
  return (base_uint256)a <= (base_uint256)b;
}
inline bool operator>(const uint256 &a, const uint256 &b) {
  return (base_uint256)a > (base_uint256)b;
}
inline bool operator>=(const uint256 &a, const uint256 &b) {
  return (base_uint256)a >= (base_uint256)b;
}
inline bool operator==(const uint256 &a, const uint256 &b) {
  return (base_uint256)a == (base_uint256)b;
}
inline bool operator!=(const uint256 &a, const uint256 &b) {
  return (base_uint256)a != (base_uint256)b;
}
inline const uint256 operator^(const uint256 &a, const uint256 &b) {
  return (base_uint256)a ^ (base_uint256)b;
}
inline const uint256 operator&(const uint256 &a, const uint256 &b) {
  return (base_uint256)a & (base_uint256)b;
}
inline const uint256 operator|(const uint256 &a, const uint256 &b) {
  return (base_uint256)a | (base_uint256)b;
}
inline const uint256 operator+(const uint256 &a, const uint256 &b) {
  return (base_uint256)a + (base_uint256)b;
}
inline const uint256 operator-(const uint256 &a, const uint256 &b) {
  return (base_uint256)a - (base_uint256)b;
}

inline int Testuint256AdHoc(vector<string> vArg) {
  uint256 g(0);

  printf("%s\n", g.ToString().c_str());
  g--;
  printf("g--\n");
  printf("%s\n", g.ToString().c_str());
  g--;
  printf("g--\n");
  printf("%s\n", g.ToString().c_str());
  g++;
  printf("g++\n");
  printf("%s\n", g.ToString().c_str());
  g++;
  printf("g++\n");
  printf("%s\n", g.ToString().c_str());
  g++;
  printf("g++\n");
  printf("%s\n", g.ToString().c_str());
  g++;
  printf("g++\n");
  printf("%s\n", g.ToString().c_str());

  uint256 a(7);
  printf("a=7\n");
  printf("%s\n", a.ToString().c_str());

  uint256 b;
  printf("b undefined\n");
  printf("%s\n", b.ToString().c_str());
  int c = 3;

  a = c;
  a.pn[3] = 15;
  printf("%s\n", a.ToString().c_str());
  uint256 k(c);

  a = 5;
  a.pn[3] = 15;
  printf("%s\n", a.ToString().c_str());
  b = 1;
  b <<= 52;

  a |= b;

  a ^= 0x500;

  printf("a %s\n", a.ToString().c_str());

  a = a | b | (uint256)0x1000;

  printf("a %s\n", a.ToString().c_str());
  printf("b %s\n", b.ToString().c_str());

  a = 0xfffffffe;
  a.pn[4] = 9;

  printf("%s\n", a.ToString().c_str());
  a++;
  printf("%s\n", a.ToString().c_str());
  a++;
  printf("%s\n", a.ToString().c_str());
  a++;
  printf("%s\n", a.ToString().c_str());
  a++;
  printf("%s\n", a.ToString().c_str());

  a--;
  printf("%s\n", a.ToString().c_str());
  a--;
  printf("%s\n", a.ToString().c_str());
  a--;
  printf("%s\n", a.ToString().c_str());
  uint256 d = a--;
  printf("%s\n", d.ToString().c_str());
  printf("%s\n", a.ToString().c_str());
  a--;
  printf("%s\n", a.ToString().c_str());
  a--;
  printf("%s\n", a.ToString().c_str());

  d = a;

  printf("%s\n", d.ToString().c_str());
  for (int i = uint256::WIDTH - 1; i >= 0; i--)
    printf("%08x", d.pn[i]);
  printf("\n");

  uint256 neg = d;
  neg = ~neg;
  printf("%s\n", neg.ToString().c_str());

  uint256 e = uint256("0xABCDEF123abcdef12345678909832180000011111111");
  printf("\n");
  printf("%s\n", e.ToString().c_str());

  printf("\n");
  uint256 x1 = uint256("0xABCDEF123abcdef12345678909832180000011111111");
  uint256 x2;
  printf("%s\n", x1.ToString().c_str());
  for (int i = 0; i < 270; i += 4) {
    x2 = x1 << i;
    printf("%s\n", x2.ToString().c_str());
  }

  printf("\n");
  printf("%s\n", x1.ToString().c_str());
  for (int i = 0; i < 270; i += 4) {
    x2 = x1;
    x2 >>= i;
    printf("%s\n", x2.ToString().c_str());
  }

  for (int i = 0; i < 100; i++) {
    uint256 k = (~uint256(0) >> i);
    printf("%s\n", k.ToString().c_str());
  }

  for (int i = 0; i < 100; i++) {
    uint256 k = (~uint256(0) << i);
    printf("%s\n", k.ToString().c_str());
  }

  return (0);
}
