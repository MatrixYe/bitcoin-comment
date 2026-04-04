// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

// Base58编码与解码模块
// 功能：提供比特币地址的Base58编码和解码功能，支持带校验和的Base58Check编码
// 应用场景：比特币地址生成、地址验证、公钥转换为地址等

//
// Why base-58 instead of standard base-64 encoding?
// - Don't want 0OIl characters that look the same in some fonts and
//      could be used to create visually identical looking account numbers.
// - A string with non-alphanumeric characters is not as easily accepted as an
// account number.
// - E-mail usually won't line-break if there's no punctuation to break at.
// - Doubleclicking selects the whole number as one word if it's all
// alphanumeric.
//

// Base58编码字符集：移除了Base64中的0、O、I、l、+、/等容易混淆的字符
// 字符集包含：数字1-9（不含0）、大写字母A-Z（不含I、O）、小写字母a-z（不含l）
// 总共58个字符，因此称为Base58
static const char *pszBase58 =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * @brief 将字节数据编码为Base58字符串
 * @param pbegin 字节数组的起始指针
 * @param pend 字节数组的结束指针（不包含）
 * @return 编码后的Base58字符串
 * 
 * 编码过程：
 * 1. 将大端序数据转换为小端序（便于大数处理）
 * 2. 将字节数据转换为大整数
 * 3. 使用除基取余法将大整数转换为Base58字符
 * 4. 处理前导零（每个前导零对应一个Base58的'1'字符）
 * 5. 反转字符串得到最终结果
 */
inline string EncodeBase58(const unsigned char *pbegin,
                           const unsigned char *pend) {
  CAutoBN_CTX pctx;                    // OpenSSL大数运算上下文（自动管理内存）
  CBigNum bn58 = 58;                   // 基数58，用于除基取余
  CBigNum bn0 = 0;                     // 零值，用于循环终止判断

  // 将大端序数据转换为小端序
  // 在末尾添加额外的零字节，确保大数库将其解释为正数
  vector<unsigned char> vchTmp(pend - pbegin + 1, 0);
  reverse_copy(pbegin, pend, vchTmp.begin());

  // 将小端序字节数据转换为大整数
  CBigNum bn;
  bn.setvch(vchTmp);

  // 使用除基取余法将大整数转换为Base58字符串
  string str;
  str.reserve((pend - pbegin) * 138 / 100 + 1);  // 预分配空间，提高效率
  CBigNum dv;                          // 存储除法结果的商
  CBigNum rem;                         // 存储除法结果的余数
  while (bn > bn0) {
    // 大数除以58，得到商和余数
    if (!BN_div(&dv, &rem, &bn, &bn58, pctx))
      throw bignum_error("EncodeBase58 : BN_div failed");
    bn = dv;                           // 更新被除数为商，继续循环
    unsigned int c = rem.getulong();   // 获取余数（0-57）
    str += pszBase58[c];               // 将余数映射为Base58字符
  }

  // 处理前导零：原始数据中的每个前导零对应一个Base58的'1'字符
  // 因为'1'是pszBase58[0]，代表值0
  for (const unsigned char *p = pbegin; p < pend && *p == 0; p++)
    str += pszBase58[0];

  // 将结果字符串反转（除基取余法得到的是逆序结果）
  reverse(str.begin(), str.end());
  return str;
}

/**
 * @brief 将vector<unsigned char>字节数据编码为Base58字符串
 * @param vch 输入的字节向量
 * @return 编码后的Base58字符串
 */
inline string EncodeBase58(const vector<unsigned char> &vch) {
  return EncodeBase58(&vch[0], &vch[0] + vch.size());
}

/**
 * @brief 将Base58字符串解码为字节数据
 * @param psz Base58编码字符串（C风格）
 * @param vchRet 输出：解码后的字节向量
 * @return 解码成功返回true，失败返回false
 * 
 * 解码过程：
 * 1. 跳过开头的空白字符
 * 2. 遍历每个Base58字符，转换为大整数（每一步：bn = bn * 58 + value）
 * 3. 将大整数转换为小端序字节数据
 * 4. 移除符号字节（如果存在）
 * 5. 恢复前导零（Base58开头的'1'对应原始数据的零字节）
 * 6. 将小端序数据转换回大端序
 */
inline bool DecodeBase58(const char *psz, vector<unsigned char> &vchRet) {
  CAutoBN_CTX pctx;                    // OpenSSL大数运算上下文
  vchRet.clear();
  CBigNum bn58 = 58;                   // 基数58
  CBigNum bn = 0;                      // 结果大整数初始化为零
  CBigNum bnChar;                      // 当前字符对应的整数值
  while (isspace(*psz))               // 跳过开头空白字符
    psz++;

  // 将大端序的Base58字符串转换为大整数
  // 算法：每一步 bn = bn * 58 + digit_value
  for (const char *p = psz; *p; p++) {
    // 在Base58字符集中查找当前字符
    const char *p1 = strchr(pszBase58, *p);
    if (p1 == NULL) {
      // 字符不在字符集中，跳过后续空白，如果还有非空白字符则解码失败
      while (isspace(*p))
        p++;
      if (*p != '\0')
        return false;
      break;
    }
    // 将字符索引设置到大整数中
    bnChar.setulong(p1 - pszBase58);
    // bn = bn * 58 + bnChar
    if (!BN_mul(&bn, &bn, &bn58, pctx))
      throw bignum_error("DecodeBase58 : BN_mul failed");
    bn += bnChar;
  }

  // 将大整数转换为小端序字节数据
  vector<unsigned char> vchTmp = bn.getvch();

  // 如果存在符号字节，移除它（最高位字节为零且次高位最高位为1，表示正数）
  if (vchTmp.size() >= 2 && vchTmp.end()[-1] == 0 && vchTmp.end()[-2] >= 0x80)
    vchTmp.erase(vchTmp.end() - 1);

  // 恢复前导零：Base58字符串开头的每个'1'对应原始数据的一个零字节
  int nLeadingZeros = 0;
  for (const char *p = psz; *p == pszBase58[0]; p++)
    nLeadingZeros++;
  vchRet.assign(nLeadingZeros + vchTmp.size(), 0);

  // 将小端序数据转换回大端序
  reverse_copy(vchTmp.begin(), vchTmp.end(), vchRet.end() - vchTmp.size());
  return true;
}

/**
 * @brief 将Base58字符串解码为字节数据
 * @param str Base58编码字符串（string类型）
 * @param vchRet 输出：解码后的字节向量
 * @return 解码成功返回true，失败返回false
 */
inline bool DecodeBase58(const string &str, vector<unsigned char> &vchRet) {
  return DecodeBase58(str.c_str(), vchRet);
}

/**
 * @brief 使用Base58Check编码对数据进行编码（添加4字节校验和）
 * @param vchIn 输入的原始字节数据
 * @return Base58Check编码后的字符串
 * 
 * Base58Check编码过程：
 * 1. 计算原始数据的SHA-256哈希
 * 2. 取哈希的前4字节作为校验和
 * 3. 将校验和追加到原始数据末尾
 * 4. 对组合后的数据进行Base58编码
 */
inline string EncodeBase58Check(const vector<unsigned char> &vchIn) {
  // add 4-byte hash check to the end
  vector<unsigned char> vch(vchIn);
  uint256 hash = Hash(vch.begin(), vch.end());
  vch.insert(vch.end(), (unsigned char *)&hash, (unsigned char *)&hash + 4);
  return EncodeBase58(vch);
}

/**
 * @brief 对Base58Check编码的字符串进行解码并验证校验和
 * @param psz Base58Check编码字符串（C风格）
 * @param vchRet 输出：解码后的原始字节数据
 * @return 解码成功且校验和正确返回true，否则返回false
 * 
 * 解码验证过程：
 * 1. 先进行Base58解码
 * 2. 如果长度小于4字节，说明数据不完整，失败
 * 3. 提取数据部分（除了最后4字节）
 * 4. 计算数据部分的SHA-256哈希
 * 5. 将计算出的哈希前4字节与编码中的校验和比较
 * 6. 如果相同则验证成功，否则失败
 */
inline bool DecodeBase58Check(const char *psz, vector<unsigned char> &vchRet) {
  if (!DecodeBase58(psz, vchRet))
    return false;
  if (vchRet.size() < 4) {
    vchRet.clear();
    return false;
  }
  // 重新计算数据部分的哈希，并与编码中的校验和比较
  uint256 hash = Hash(vchRet.begin(), vchRet.end() - 4);
  if (memcmp(&hash, &vchRet.end()[-4], 4) != 0) {
    vchRet.clear();
    return false;
  }
  // 移除校验和，只保留原始数据
  vchRet.resize(vchRet.size() - 4);
  return true;
}

/**
 * @brief 对Base58Check编码的字符串进行解码并验证校验和
 * @param str Base58Check编码字符串（string类型）
 * @param vchRet 输出：解码后的原始字节数据
 * @return 解码成功且校验和正确返回true，否则返回false
 */
inline bool DecodeBase58Check(const string &str,
                              vector<unsigned char> &vchRet) {
  return DecodeBase58Check(str.c_str(), vchRet);
}

// 比特币主网地址版本号
// 主网地址版本号为0，表示普通支付地址
static const unsigned char ADDRESSVERSION = 0;

/**
 * @brief 将160位哈希转换为比特币地址（Base58Check编码）
 * @param hash160 公钥的RIPEMD-160哈希值（20字节）
 * @return 编码后的比特币地址字符串
 * 
 * 地址格式：[1字节版本][20字节哈希][4字节校验] → Base58编码
 * 版本号0表示主网普通地址
 */
inline string Hash160ToAddress(uint160 hash160) {
  // add 1-byte version number to the front
  vector<unsigned char> vch(1, ADDRESSVERSION);
  vch.insert(vch.end(), UBEGIN(hash160), UEND(hash160));
  return EncodeBase58Check(vch);
}

/**
 * @brief 将比特币地址字符串解码为160位哈希
 * @param psz 比特币地址字符串（C风格）
 * @param hash160Ret 输出：解码后的160位哈希
 * @return 解码成功返回true，失败返回false
 * 
 * 验证过程：
 * 1. Base58Check解码验证校验和
 * 2. 检查版本号和长度
 * 3. 从解码后的数据中提取160位哈希
 */
inline bool AddressToHash160(const char *psz, uint160 &hash160Ret) {
  vector<unsigned char> vch;
  if (!DecodeBase58Check(psz, vch))
    return false;
  if (vch.empty())
    return false;
  unsigned char nVersion = vch[0];
  // 检查长度：必须是1字节版本 + 20字节哈希 = 21字节
  if (vch.size() != sizeof(hash160Ret) + 1)
    return false;
  memcpy(&hash160Ret, &vch[1], sizeof(hash160Ret));
  // 验证版本号：只接受主网地址版本
  return (nVersion <= ADDRESSVERSION);
}

/**
 * @brief 将比特币地址字符串解码为160位哈希
 * @param str 比特币地址字符串（string类型）
 * @param hash160Ret 输出：解码后的160位哈希
 * @return 解码成功返回true，失败返回false
 */
inline bool AddressToHash160(const string &str, uint160 &hash160Ret) {
  return AddressToHash160(str.c_str(), hash160Ret);
}

/**
 * @brief 验证比特币地址是否有效
 * @param psz 比特币地址字符串（C风格）
 * @return 地址有效返回true，无效返回false
 */
inline bool IsValidBitcoinAddress(const char *psz) {
  uint160 hash160;
  return AddressToHash160(psz, hash160);
}

/**
 * @brief 验证比特币地址是否有效
 * @param str 比特币地址字符串（string类型）
 * @return 地址有效返回true，无效返回false
 */
inline bool IsValidBitcoinAddress(const string &str) {
  return IsValidBitcoinAddress(str.c_str());
}

/**
 * @brief 将公钥转换为比特币地址
 * @param vchPubKey 公钥的字节数据
 * @return 编码后的比特币地址字符串
 * 
 * 过程：公钥 → SHA-256 → RIPEMD-160 → Base58Check编码 → 地址
 */
inline string PubKeyToAddress(const vector<unsigned char> &vchPubKey) {
  return Hash160ToAddress(Hash160(vchPubKey));
}
