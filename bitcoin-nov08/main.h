// Copyright (c) 2008 Satoshi Nakamoto
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
// SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

// 交易相关的类
class COutPoint;    // 交易输出点，用于引用特定交易的输出
class CInPoint;     // 交易输入点，用于在内存中引用交易输出
class CDiskTxPos;   // 磁盘交易位置，记录交易在磁盘上的存储位置
class CCoinBase;    // coinbase交易，新区块中产生新币的特殊交易
class CTxIn;        // 交易输入，引用之前交易的输出
class CTxOut;       // 交易输出，包含金额和接收地址
class CTransaction; // 交易，包含输入和输出
// 区块相关的类
class CBlock;      // 区块，包含多个交易
class CBlockIndex; // 区块索引，维护区块链的内存索引

// 其他类，包括钱包相关的、密钥管理的、交易数据库的、大整数计算的、私钥的、公钥的
class CWalletTx; // 钱包交易，包含额外钱包信息的交易
class CKeyItem;  // 密钥项，用于钱包密钥管理
class CTxDB;     // 交易数据库类，用于存储交易信息
class CBigNum;   // 大整数类，用于加密计算,可能是考虑到大数的乘法运算
class CPrivKey;  // 私钥类，用于存储私钥
class CPubKey;   // 公钥类，用于存储公钥

// 系统常量定义

static const unsigned int MAX_SIZE =
    0x02000000; // 0x02000000=2*16^6 = 33554432/1024/1024=32MB
static const int64 COIN = 1000000; // 1个比特币的聪数（1 BTC = 1,000,000聪）
static const int64 CENT = 10000;   // 1分比特币的聪数（0.01 BTC = 10,000聪）
static const int64 TRANSACTIONFEE =
    1 *
    CENT; // 交易手续费（1分比特币）,这个值居然是写死的？交易手续费居然不能改变？

/// static const unsigned int MINPROOFOFWORK = 40; /// 初始难度设置的备选值
static const unsigned int MINPROOFOFWORK =
    20; /// 难度目标，初始难度设置的备选值

// 全局变量声明

// 区块索引映射表，通过区块哈希快速查找区块索引
// 这是比特币核心数据结构之一，维护整个区块链的内存索引
extern map<uint256, CBlockIndex *> mapBlockIndex;

// 创世区块的哈希值，整个区块链的起点
extern const uint256 hashGenesisBlock;

// 创世区块的索引指针
extern CBlockIndex *pindexGenesisBlock;

// 当前最佳区块链的高度
extern int nBestHeight;

// 当前最佳区块的索引指针，即最长链的最后一个区块，居然叫最佳区块？而不是最长区块？
extern CBlockIndex *pindexBest;

// 已更新的交易数量计数器，用于统计已处理的交易数量
extern unsigned int nTransactionsUpdated;

// 是否正在生成比特币的标志（挖矿开关）
extern int fGenerateBitcoins;

// 核心功能函数声明

// 打开区块文件，用于读取区块数据
// 参数：nFile - 文件编号，nBlockPos - 区块在文件中的位置，pszMode - 打开模式
FILE *OpenBlockFile(unsigned int nFile, unsigned int nBlockPos,
                    const char *pszMode = "rb");

// 追加区块到区块文件，返回新文件的句柄
// 参数：nFileRet - 输出参数，返回新文件的编号
FILE *AppendBlockFile(unsigned int &nFileRet);

// 添加密钥到钱包
// 参数：key - 要添加的密钥
bool AddKey(const CKey &key);

// 生成新的比特币地址密钥
// 返回：新生成的密钥（公钥）
vector<unsigned char> GenerateNewKey();

// 将交易添加到钱包
// 参数：wtxIn - 要添加的钱包交易
bool AddToWallet(const CWalletTx &wtxIn);

// 重新接受钱包中的交易（用于恢复时）
void ReacceptWalletTransactions();

// 向网络中继钱包中的交易
void RelayWalletTransactions();

// 加载区块索引
// 参数：fAllowNew - 是否允许创建新的区块文件
bool LoadBlockIndex(bool fAllowNew = true);

// 比特币挖矿函数
// 返回：是否成功挖到区块
bool BitcoinMiner();

// 处理来自节点的消息
// 参数：pfrom - 发送消息的节点
bool ProcessMessages(CNode *pfrom);

// 处理特定类型的消息
// 参数：pfrom - 发送消息的节点，strCommand - 消息命令，vRecv - 消息数据
bool ProcessMessage(CNode *pfrom, string strCommand, CDataStream &vRecv);

// 向节点发送消息
// 参数：pto - 接收消息的节点
bool SendMessages(CNode *pto);

// 计算钱包中的总金额
// 返回：钱包中的比特币数量（以聪为单位）
int64 CountMoney();

// 创建交易
// 参数：scriptPubKey - 公钥脚本（接收方地址），nValue - 转账金额，txNew -
// 输出的新交易
bool CreateTransaction(CScript scriptPubKey, int64 nValue, CWalletTx &txNew);

// 发送比特币
// 参数：scriptPubKey - 接收方公钥脚本，nValue - 发送金额，wtxNew -
// 输出的钱包交易
bool SendMoney(CScript scriptPubKey, int64 nValue, CWalletTx &wtxNew);

// 磁盘交易位置类
// 用于记录交易在磁盘上的存储位置，便于快速定位和读取交易数据
class CDiskTxPos {
public:
  unsigned int nFile;     // 区块文件编号
  unsigned int nBlockPos; // 区块在文件中的起始位置
  unsigned int nTxPos;    // 交易在区块中的偏移位置

  // 默认构造函数
  CDiskTxPos() { SetNull(); }

  // 带参数的构造函数
  CDiskTxPos(unsigned int nFileIn, unsigned int nBlockPosIn,
             unsigned int nTxPosIn) {
    nFile = nFileIn;
    nBlockPos = nBlockPosIn;
    nTxPos = nTxPosIn;
  }

  // 序列化和反序列化函数（宏定义实现）
  IMPLEMENT_SERIALIZE(READWRITE(FLATDATA(*this));)

  // 将对象设置为空状态
  void SetNull() {
    nFile = -1; // 用-1表示无效文件编号
    nBlockPos = 0;
    nTxPos = 0;
  }

  // 检查对象是否为空
  bool IsNull() const { return (nFile == -1); }

  // 相等运算符重载
  friend bool operator==(const CDiskTxPos &a, const CDiskTxPos &b) {
    return (a.nFile == b.nFile && a.nBlockPos == b.nBlockPos &&
            a.nTxPos == b.nTxPos);
  }

  // 不等运算符重载
  friend bool operator!=(const CDiskTxPos &a, const CDiskTxPos &b) {
    return !(a == b);
  }

  // 打印函数，用于调试
  void print() const {
    if (IsNull())
      printf("null");
    else
      printf("(nFile=%d, nBlockPos=%d, nTxPos=%d)", nFile, nBlockPos, nTxPos);
  }
};

// 内存交易输入点类
// 用于在内存中直接引用交易输出，主要在交易验证过程中使用
class CInPoint {
public:
  CTransaction *ptx; // 指向交易对象的指针
  unsigned int n;    // 交易输出的索引

  // 默认构造函数
  CInPoint() { SetNull(); }

  // 带参数的构造函数
  CInPoint(CTransaction *ptxIn, unsigned int nIn) {
    ptx = ptxIn;
    n = nIn;
  }

  // 将对象设置为空状态
  void SetNull() {
    ptx = NULL;
    n = -1;
  }

  // 检查对象是否为空
  bool IsNull() const { return (ptx == NULL && n == -1); }
};

// 交易输出引用类
// 用于唯一标识比特币网络中的一个交易输出
// 交易输入通过COutPoint引用之前交易的输出，构成交易链
class COutPoint {
public:
  uint256 hash;   // 引用交易的哈希值
  unsigned int n; // 交易输出的索引（从0开始）

  // 默认构造函数
  COutPoint() { SetNull(); }

  // 带参数的构造函数
  COutPoint(uint256 hashIn, unsigned int nIn) {
    hash = hashIn;
    n = nIn;
  }

  // 序列化和反序列化函数（宏定义实现）
  IMPLEMENT_SERIALIZE(READWRITE(hash, n);)

  // 将对象设置为空状态
  void SetNull() {
    hash = 0;
    n = -1;
  }

  // 检查对象是否为空
  bool IsNull() const { return (hash == 0 && n == -1); }

  // 小于运算符重载，用于排序
  friend bool operator<(const COutPoint &a, const COutPoint &b) {
    return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
  }

  // 相等运算符重载
  friend bool operator==(const COutPoint &a, const COutPoint &b) {
    return (a.hash == b.hash && a.n == b.n);
  }

  // 不等运算符重载
  friend bool operator!=(const COutPoint &a, const COutPoint &b) {
    return !(a == b);
  }

  // 打印函数，用于调试
  void print() const {
    printf("COutPoint(%s, %d)", hash.ToString().c_str(), n);
  }
};

// 交易输入类
// 代表比特币交易中的一个输入
// 每个输入引用之前交易的一个输出，并提供解锁该输出的脚本
class CTxIn {
public:
  COutPoint prevout; // 引用的上一个交易输出
  CScript scriptSig; // 解锁脚本，用于验证交易输入的合法性

  // 默认构造函数
  CTxIn() {}

  // 带参数的构造函数（通过COutPoint）
  CTxIn(COutPoint prevoutIn, CScript scriptSigIn) {
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
  }

  // 带参数的构造函数（直接指定交易哈希和输出索引）
  CTxIn(uint256 hashPrevTx, unsigned int nOut, CScript scriptSigIn) {
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
  }

  // 序列化和反序列化函数（宏定义实现）
  IMPLEMENT_SERIALIZE(READWRITE(prevout); READWRITE(scriptSig);)

  // 检查引用的前一个交易是否在主链中
  bool IsPrevInMainChain() const { return CTxDB("r").ContainsTx(prevout.hash); }

  // 相等运算符重载
  friend bool operator==(const CTxIn &a, const CTxIn &b) {
    return (a.prevout == b.prevout && a.scriptSig == b.scriptSig);
  }

  // 不等运算符重载
  friend bool operator!=(const CTxIn &a, const CTxIn &b) { return !(a == b); }

  // 打印函数，用于调试
  void print() const {
    printf("CTxIn(");
    prevout.print();
    if (prevout.IsNull()) {
      printf(", coinbase %s)\n",
             HexStr(scriptSig.begin(), scriptSig.end(), false).c_str());
    } else {
      if (scriptSig.size() >= 6)
        printf(", scriptSig=%02x%02x", scriptSig[4], scriptSig[5]);
      printf(")\n");
    }
  }

  // 检查此输入是否属于当前钱包
  bool IsMine() const;
  // 获取此输入的支出金额（以聪为单位）
  int64 GetDebit() const;
};

// 交易输出类
// 代表比特币交易中的一个输出
// 每个输出指定了可以接收比特币的地址（通过scriptPubKey）和金额
// 未被花费的交易输出构成UTXO集（未花费交易输出集）
class CTxOut {
public:
  int64 nValue;           // 输出金额（单位：聪，1 BTC = 100,000,000聪）
  unsigned int nSequence; // 序列值，用于交易替换和时间锁定功能
  CScript
      scriptPubKey; // 锁定脚本，定义了后续交易输入需要满足的条件（如公钥哈希）

  // disk only
  CDiskTxPos posNext; //// 仅用于磁盘存储，目前仅作为标志使用，未使用其位置信息

public:
  // 默认构造函数
  CTxOut() {
    nValue = 0;
    nSequence = UINT_MAX;
  }

  // 带参数的构造函数
  CTxOut(int64 nValueIn, CScript scriptPubKeyIn, int nSequenceIn = UINT_MAX) {
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
    nSequence = nSequenceIn;
  }

  // 序列化和反序列化函数（宏定义实现）
  IMPLEMENT_SERIALIZE(READWRITE(nValue); READWRITE(nSequence);
                      READWRITE(scriptPubKey);
                      if (nType & SER_DISK) READWRITE(posNext);)

  // 获取交易输出的哈希值
  uint256 GetHash() const { return SerializeHash(*this); }

  // 检查交易输出是否为最终状态（不可被替换）
  bool IsFinal() const { return (nSequence == UINT_MAX); }

  // 检查此输出是否属于当前钱包
  bool IsMine() const { return ::IsMine(scriptPubKey); }

  // 获取此输出的入账金额（以聪为单位）
  int64 GetCredit() const {
    if (IsMine())
      return nValue;
    return 0;
  }

  // 相等运算符重载
  friend bool operator==(const CTxOut &a, const CTxOut &b) {
    return (a.nValue == b.nValue && a.nSequence == b.nSequence &&
            a.scriptPubKey == b.scriptPubKey);
  }

  // 不等运算符重载
  friend bool operator!=(const CTxOut &a, const CTxOut &b) { return !(a == b); }

  // 打印函数，用于调试
  void print() const {
    if (scriptPubKey.size() >= 6)
      printf(
          "CTxOut(nValue=%I64d, nSequence=%u, scriptPubKey=%02x%02x, posNext=",
          nValue, nSequence, scriptPubKey[4], scriptPubKey[5]);
    posNext.print();
    printf(")\n");
  }
};

// 交易类
// 比特币网络中广播并包含在区块中的基本交易单元
// 一个交易可以包含多个输入和输出，形成价值转移的核心数据结构
class CTransaction {
public:
  vector<CTxIn> vin;      // 交易输入列表
  vector<CTxOut> vout;    // 交易输出列表
  unsigned int nLockTime; // 锁定时间，用于延迟交易确认

  // 默认构造函数
  CTransaction() { SetNull(); }

  // 序列化和反序列化函数（宏定义实现）
  // 注意：在SER_GETHASH模式下不序列化nVersion，确保交易哈希计算的一致性
  IMPLEMENT_SERIALIZE(if (!(nType & SER_GETHASH)) READWRITE(nVersion);

                      // 为写入操作设置流的版本号
                      if (fRead && s.nVersion == -1) s.nVersion = nVersion;

                      READWRITE(vin); READWRITE(vout); READWRITE(nLockTime);)

  // 将交易重置为空状态
  void SetNull() {
    vin.clear();
    vout.clear();
    nLockTime = 0;
  }

  // 检查交易是否为空
  bool IsNull() const { return (vin.empty() && vout.empty()); }

  // 获取交易的哈希值
  uint256 GetHash() const { return SerializeHash(*this); }

  // 检查交易的所有输入是否都在主链中
  bool AllPrevInMainChain() const {
    foreach (const CTxIn &txin, vin)
      if (!txin.IsPrevInMainChain())
        return false;
    return true;
  }

  // 检查交易是否为最终状态（可以被包含在区块中）
  bool IsFinal() const {
    if (nLockTime == 0) // 锁定时间为0表示立即可用
      return true;
    if (nLockTime < GetAdjustedTime()) // 如果锁定时间已过期
      return true;
    foreach (const CTxOut &txout, vout) // 检查所有输出是否为最终状态
      if (!txout.IsFinal())
        return false;
    return true;
  }

  // 检查当前交易是否是另一个交易的更新版本
  // 用于交易替换功能
  bool IsUpdate(const CTransaction &b) const {
    if (vin.size() != b.vin.size() || vout.size() != b.vout.size())
      return false;
    // 检查所有输入引用是否相同
    for (int i = 0; i < vin.size(); i++)
      if (vin[i].prevout != b.vin[i].prevout)
        return false;

    bool fNewer = false;
    unsigned int nLowest = UINT_MAX;
    // 通过nSequence值判断哪个交易更新
    for (int i = 0; i < vout.size(); i++) {
      if (vout[i].nSequence != b.vout[i].nSequence) {
        if (vout[i].nSequence <= nLowest) {
          fNewer = false;
          nLowest = vout[i].nSequence;
        }
        if (b.vout[i].nSequence < nLowest) {
          fNewer = true;
          nLowest = b.vout[i].nSequence;
        }
      }
    }
    return fNewer;
  }

  // 检查交易是否为coinbase交易（挖矿奖励交易）
  // coinbase交易的特点是只有一个输入，且该输入引用为空
  bool IsCoinBase() const {
    return (vin.size() == 1 && vin[0].prevout.IsNull());
  }

  // 验证交易的基本有效性
  // 执行不依赖上下文的基础检查
  bool CheckTransaction() const {
    // 基本检查：交易必须有输入和输出
    if (vin.empty() || vout.empty())
      return false;

    // 检查输出值是否为负数
    int64 nValueOut = 0;
    foreach (const CTxOut &txout, vout) {
      if (txout.nValue < 0)
        return false;
      nValueOut += txout.nValue;
    }

    // 对coinbase交易的特殊检查
    if (IsCoinBase()) {
      // coinbase的解锁脚本不能超过100字节
      if (vin[0].scriptSig.size() > 100)
        return false;
    } else {
      // 非coinbase交易的所有输入必须引用有效输出
      foreach (const CTxIn &txin, vin)
        if (txin.prevout.IsNull())
          return false;
    }

    return true;
  }

  // 检查交易是否包含属于当前钱包的输出
  bool IsMine() const {
    foreach (const CTxOut &txout, vout)
      if (txout.IsMine())
        return true;
    return false;
  }

  // 获取交易的总支出金额（以聪为单位）
  // 即当前钱包为此交易支付的总金额
  int64 GetDebit() const {
    int64 nDebit = 0;
    foreach (const CTxIn &txin, vin)
      nDebit += txin.GetDebit();
    return nDebit;
  }

  // 获取交易对当前钱包的总收入金额（以聪为单位）
  // 即当前钱包从该交易中获得的金额
  int64 GetCredit() const {
    int64 nCredit = 0;
    foreach (const CTxOut &txout, vout)
      nCredit += txout.GetCredit();
    return nCredit;
  }

  // 获取交易的总输出价值（以聪为单位）
  // 即交易中分配出去的比特币总量
  int64 GetValueOut() const {
    int64 nValueOut = 0;
    foreach (const CTxOut &txout, vout) {
      if (txout.nValue < 0)
        throw runtime_error("CTransaction::GetValueOut() : negative value");
      nValueOut += txout.nValue;
    }
    return nValueOut;
  }

  // 从磁盘读取交易
  // pos: 交易在磁盘上的位置
  // pfileRet: 可选参数，返回文件指针
  bool ReadFromDisk(CDiskTxPos pos, FILE **pfileRet = NULL) {
    // 打开区块文件
    CAutoFile filein = OpenBlockFile(pos.nFile, 0, pfileRet ? "rb+" : "rb");
    if (!filein)
      return false;

    // 定位并读取交易
    if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
      return false;
    filein >> *this;

    // 返回文件指针（如果需要）
    if (pfileRet) {
      if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
        return false;
      *pfileRet = filein.release();
    }
    return true;
  }

  // 相等运算符重载
  friend bool operator==(const CTransaction &a, const CTransaction &b) {
    return (a.vin == b.vin && a.vout == b.vout && a.nLockTime == b.nLockTime);
  }

  // 不等运算符重载
  friend bool operator!=(const CTransaction &a, const CTransaction &b) {
    return !(a == b);
  }

  // 打印交易详细信息
  void print() const {
    printf("CTransaction(vin.size=%d, vout.size=%d, nLockTime=%d)\n",
           vin.size(), vout.size(), nLockTime);
    for (int i = 0; i < vin.size(); i++) {
      printf("    ");
      vin[i].print();
    }
    for (int i = 0; i < vout.size(); i++) {
      printf("    ");
      vout[i].print();
    }
  }

  // 测试断开交易输入的连接（用于调试）
  bool TestDisconnectInputs(CTxDB &txdb,
                            map<uint256, CTransaction> &mapTestPool) {
    return DisconnectInputs(txdb, mapTestPool, true);
  }

  // 测试连接交易输入（用于调试）
  bool TestConnectInputs(CTxDB &txdb, map<uint256, CTransaction> &mapTestPool,
                         bool fMemoryTx, bool fIgnoreDiskConflicts,
                         int64 &nFees) {
    return ConnectInputs(txdb, mapTestPool, CDiskTxPos(1, 1, 1), 0, true,
                         fMemoryTx, fIgnoreDiskConflicts, nFees);
  }

  // 断开交易输入的连接
  // 从UTXO集中移除交易产生的输出
  bool DisconnectInputs(CTxDB &txdb) {
    static map<uint256, CTransaction> mapTestPool;
    return DisconnectInputs(txdb, mapTestPool, false);
  }

  // 连接交易输入
  // 验证交易输入的有效性并更新UTXO集
  bool ConnectInputs(CTxDB &txdb, CDiskTxPos posThisTx, int nHeight) {
    static map<uint256, CTransaction> mapTestPool;
    int64 nFees;
    return ConnectInputs(txdb, mapTestPool, posThisTx, nHeight, false, false,
                         false, nFees);
  }

private:
  bool DisconnectInputs(CTxDB &txdb, map<uint256, CTransaction> &mapTestPool,
                        bool fTest);
  bool ConnectInputs(CTxDB &txdb, map<uint256, CTransaction> &mapTestPool,
                     CDiskTxPos posThisTx, int nHeight, bool fTest,
                     bool fMemoryTx, bool fIgnoreDiskConflicts, int64 &nFees);

public:
  bool AcceptTransaction(CTxDB &txdb, bool fCheckInputs = true);
  bool AcceptTransaction() {
    CTxDB txdb("r");
    return AcceptTransaction(txdb);
  }
  bool ClientConnectInputs();
};

// 带默克尔分支的交易类
// 继承自CTransaction，添加了默克尔树信息，用于将交易链接到区块链上
// 默克尔分支允许轻客户端(SPV)验证交易是否包含在区块中，无需下载完整区块
class CMerkleTx : public CTransaction {
public:
  uint256 hashBlock;             // 包含该交易的区块哈希值
  vector<uint256> vMerkleBranch; // 默克尔分支，用于验证交易在区块中的存在性
  int nIndex;                    // 交易在区块中的索引位置

  // 默认构造函数
  CMerkleTx() { Init(); }

  // 从普通交易构造
  CMerkleTx(const CTransaction &txIn) : CTransaction(txIn) { Init(); }

  // 初始化函数
  void Init() {
    hashBlock = 0; // 初始化为无效区块哈希
    nIndex = -1;   // 初始化为无效索引
  }

  // 序列化和反序列化函数（宏定义实现）
  // 注意：在SER_GETHASH模式下只序列化基础交易部分，不包括默克尔分支信息
  IMPLEMENT_SERIALIZE(nSerSize += SerReadWrite(s, *(CTransaction *)this, nType,
                                               nVersion, ser_action);
                      if (!(nType & SER_GETHASH)) READWRITE(nVersion);
                      READWRITE(hashBlock); READWRITE(vMerkleBranch);
                      READWRITE(nIndex);)

  // 设置默克尔分支
  // 从区块中查找交易并构建默克尔分支信息
  int SetMerkleBranch();

  // 检查交易是否在主链中
  // 返回值：0=不在链上，1=在主链上，-1=在分叉链上
  int IsInMainChain() const;

  // 接受交易
  // fCheckInputs: 是否检查输入的有效性
  bool AcceptTransaction(CTxDB &txdb, bool fCheckInputs = true);

  // 接受交易（重载版本，使用只读数据库）
  bool AcceptTransaction() {
    CTxDB txdb("r");
    return AcceptTransaction(txdb);
  }
};

// 钱包交易类
// 继承自CMerkleTx，添加了只有交易所有者关心的额外信息
// 包含将交易链接回区块链所需的任何未记录交易
class CWalletTx : public CMerkleTx {
public:
  vector<CMerkleTx> vtxPrev;               // 前置交易列表，用于链接到区块链
  map<string, string> mapValue;            // 交易元数据键值对
  vector<pair<string, string>> vOrderForm; // 订单表单信息
  unsigned int nTime;                      // 交易时间戳
  char fFromMe;                            // 是否由当前钱包发出
  char fSpent;                             // 是否已花费

  //// 可能需要对订单信息进行签名，以确保来自付款人

  // 默认构造函数
  CWalletTx() { Init(); }

  // 从CMerkleTx构造
  CWalletTx(const CMerkleTx &txIn) : CMerkleTx(txIn) { Init(); }

  // 从CTransaction构造
  CWalletTx(const CTransaction &txIn) : CMerkleTx(txIn) { Init(); }

  // 初始化函数
  void Init() {
    nTime = 0;
    fFromMe = false;
    fSpent = false;
  }

  // 序列化和反序列化函数（宏定义实现）
  IMPLEMENT_SERIALIZE(
      /// 希望它能返回读取的版本号，可能使用引用
      nSerSize +=
      SerReadWrite(s, *(CMerkleTx *)this, nType, nVersion, ser_action);
      if (!(nType & SER_GETHASH)) READWRITE(nVersion); READWRITE(vtxPrev);
      READWRITE(mapValue); READWRITE(vOrderForm); READWRITE(nTime);
      READWRITE(fFromMe); READWRITE(fSpent);)

  // 将钱包交易写入磁盘
  bool WriteToDisk() { return CWalletDB().WriteTx(GetHash(), *this); }

  // 添加支持性交易到钱包
  // 这些是将该交易链接回区块链所需的前置交易
  void AddSupportingTransactions(CTxDB &txdb);
  void AddSupportingTransactions() {
    CTxDB txdb("r");
    AddSupportingTransactions(txdb);
  }

  // 接受钱包交易
  // 验证交易并将其添加到钱包中
  // fCheckInputs: 是否检查输入的有效性
  bool AcceptWalletTransaction(CTxDB &txdb, bool fCheckInputs = true);
  bool AcceptWalletTransaction() {
    CTxDB txdb("r");
    return AcceptWalletTransaction(txdb);
  }

  // 转发钱包交易
  // 将交易广播到P2P网络
  void RelayWalletTransaction(CTxDB &txdb);
  void RelayWalletTransaction() {
    CTxDB txdb("r");
    RelayWalletTransaction(txdb);
  }
};

// 区块类
// 节点收集新交易到区块中，将交易哈希构建成默克尔树（哈希树），
// 并通过扫描nonce值使区块哈希满足工作量证明(PoW)要求。
// 当矿工解决了工作量证明问题后，会将区块广播给所有节点，区块被添加到区块链上。
// 区块中的第一个交易是特殊的coinbase交易，用于创建新区块奖励给区块创建者。
//
// 区块存储在磁盘上的blk0001.dat等文件中，它们的磁盘位置由内存中的CBlockIndex对象索引。
class CBlock {
public:
  // 区块头
  uint256 hashPrevBlock;  // 前一个区块的哈希值，构建区块链的链接
  uint256 hashMerkleRoot; // 区块中所有交易的默克尔树根哈希值
  unsigned int nTime;     // 区块创建的时间戳
  unsigned int nBits;     // 目标难度值，用于工作量证明计算
  unsigned int nNonce;    // 随机数，用于工作量证明搜索

  // 网络和磁盘存储
  vector<CTransaction> vtx; // 区块中包含的交易列表

  // 仅内存中使用
  mutable vector<uint256> vMerkleTree; // 默克尔树，用于快速验证交易包含性

  // 构造函数
  CBlock() { SetNull(); }

  // 序列化和反序列化函数（宏定义实现）
  // 注意：
  // - SER_GETHASH模式下仅序列化区块头，不包含交易
  // - SER_BLOCKHEADERONLY模式下也仅序列化区块头
  // - vtx必须放在最后序列化，因为ConnectBlock依赖此顺序计算偏移量
  IMPLEMENT_SERIALIZE(if (!(nType & SER_GETHASH)) READWRITE(nVersion);
                      READWRITE(hashPrevBlock); READWRITE(hashMerkleRoot);
                      READWRITE(nTime); READWRITE(nBits); READWRITE(nNonce);

                      // ConnectBlock依赖vtx在最后，以便计算偏移量
                      if (!(nType & (SER_GETHASH | SER_BLOCKHEADERONLY)))
                          READWRITE(vtx);
                      else if (fRead) const_cast<CBlock *>(this)->vtx.clear();)

  // 将区块设置为无效状态
  void SetNull() {
    hashPrevBlock = 0;
    hashMerkleRoot = 0;
    nTime = 0;
    nBits = 0;
    nNonce = 0;
    vtx.clear();
    vMerkleTree.clear();
  }

  // 检查区块是否为无效状态
  bool IsNull() const { return (nBits == 0); }

  // 获取区块头的哈希值（用于工作量证明验证）
  uint256 GetHash() const { return Hash(BEGIN(hashPrevBlock), END(nNonce)); }

  // 构建默克尔树并返回根哈希值
  // 默克尔树用于高效验证交易是否包含在区块中
  uint256 BuildMerkleTree() const {
    vMerkleTree.clear();
    // 将所有交易的哈希值作为默克尔树的叶子节点
    foreach (const CTransaction &tx, vtx)
      vMerkleTree.push_back(tx.GetHash());

    int j = 0; // 当前层级的起始索引
    // 从叶子节点开始，构建默克尔树的上层节点
    for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2) {
      for (int i = 0; i < nSize; i += 2) {
        int i2 =
            min(i + 1, nSize - 1); // 如果节点数为奇数，最后一个节点与自身哈希
        // 计算两个相邻节点的父节点哈希值
        vMerkleTree.push_back(
            Hash(BEGIN(vMerkleTree[j + i]), END(vMerkleTree[j + i]),
                 BEGIN(vMerkleTree[j + i2]), END(vMerkleTree[j + i2])));
      }
      j += nSize; // 移动到下一层级的起始索引
    }
    // 返回默克尔树的根哈希值
    return (vMerkleTree.empty() ? 0 : vMerkleTree.back());
  }

  // 获取指定交易索引的默克尔分支
  // 默克尔分支是验证交易是否包含在区块中所需的哈希值集合
  vector<uint256> GetMerkleBranch(int nIndex) const {
    if (vMerkleTree.empty())
      BuildMerkleTree(); // 如果默克尔树尚未构建，则先构建

    vector<uint256> vMerkleBranch;
    int j = 0; // 当前层级的起始索引
    for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2) {
      int i = min(nIndex ^ 1, nSize - 1);          // 找到当前节点的兄弟节点
      vMerkleBranch.push_back(vMerkleTree[j + i]); // 添加兄弟节点到分支
      nIndex >>= 1;                                // 向上移动到父节点的索引
      j += nSize;                                  // 移动到下一层级的起始索引
    }
    return vMerkleBranch;
  }

  // 静态方法：检查默克尔分支是否有效
  // 用于轻客户端验证交易是否包含在区块中
  // 参数：
  //   hash: 要验证的交易哈希
  //   vMerkleBranch: 默克尔分支
  //   nIndex: 交易在区块中的索引
  // 返回值：计算得到的默克尔树根哈希值，如果与区块头中的默克尔树根匹配则验证通过
  static uint256 CheckMerkleBranch(uint256 hash,
                                   const vector<uint256> &vMerkleBranch,
                                   int nIndex) {
    foreach (const uint256 &otherside, vMerkleBranch) {
      // 根据当前索引的奇偶性决定哈希的顺序
      if (nIndex & 1)
        hash = Hash(BEGIN(otherside), END(otherside), BEGIN(hash), END(hash));
      else
        hash = Hash(BEGIN(hash), END(hash), BEGIN(otherside), END(otherside));
      nIndex >>= 1; // 向上移动到父节点的索引
    }
    return hash;
  }

  // 将区块写入磁盘
  // 参数：
  //   fWriteTransactions: 是否写入完整交易
  //   nFileRet: 返回包含区块的文件编号
  //   nBlockPosRet: 返回区块在文件中的位置
  bool WriteToDisk(bool fWriteTransactions, unsigned int &nFileRet,
                   unsigned int &nBlockPosRet) {
    // 打开历史文件进行追加
    CAutoFile fileout = AppendBlockFile(nFileRet);
    if (!fileout)
      return false;

    // 如果不需要写入交易，设置SER_BLOCKHEADERONLY标志
    if (!fWriteTransactions)
      fileout.nType |= SER_BLOCKHEADERONLY;

    // 写入索引头：包含魔数和区块大小
    unsigned int nSize = fileout.GetSerializeSize(*this);
    fileout << FLATDATA(pchMessageStart) << nSize;

    // 记录区块在文件中的位置并写入区块数据
    nBlockPosRet = ftell(fileout);
    if (nBlockPosRet == -1)
      return false;
    fileout << *this;

    return true;
  }

  // 从磁盘读取区块
  // 参数：
  //   nFile: 包含区块的文件编号
  //   nBlockPos: 区块在文件中的位置
  //   fReadTransactions: 是否读取完整交易
  bool ReadFromDisk(unsigned int nFile, unsigned int nBlockPos,
                    bool fReadTransactions) {
    // 先将区块设置为无效状态
    SetNull();

    // 打开历史文件进行读取
    CAutoFile filein = OpenBlockFile(nFile, nBlockPos, "rb");
    if (!filein)
      return false;

    // 如果不需要读取交易，设置SER_BLOCKHEADERONLY标志
    if (!fReadTransactions)
      filein.nType |= SER_BLOCKHEADERONLY;

    // 读取区块数据
    filein >> *this;

    // 验证区块头
    // 检查难度值是否低于最小工作量证明要求，或区块哈希是否满足难度要求
    if (nBits < MINPROOFOFWORK || GetHash() > (~uint256(0) >> nBits))
      return error("CBlock::ReadFromDisk : errors in block header");

    return true;
  }

  // 打印区块信息
  void print() const {
    printf("CBlock(hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%u, "
           "nNonce=%u, vtx=%d)\n",
           hashPrevBlock.ToString().substr(0, 6).c_str(),
           hashMerkleRoot.ToString().substr(0, 6).c_str(), nTime, nBits, nNonce,
           vtx.size());
    // 打印区块中的每笔交易
    for (int i = 0; i < vtx.size(); i++) {
      printf("  ");
      vtx[i].print();
    }
    // 打印默克尔树信息
    printf("  vMerkleTree: ");
    for (int i = 0; i < vMerkleTree.size(); i++)
      printf("%s ", vMerkleTree[i].ToString().substr(0, 6).c_str());
    printf("\n");
  }

  // 从磁盘读取区块（重载版本，使用CBlockIndex）
  bool ReadFromDisk(const CBlockIndex *blockindex, bool fReadTransactions);

  // 测试断开区块连接（用于回滚测试）
  bool TestDisconnectBlock(CTxDB &txdb,
                           map<uint256, CTransaction> &mapTestPool);

  // 测试连接区块（用于验证测试）
  bool TestConnectBlock(CTxDB &txdb, map<uint256, CTransaction> &mapTestPool);

  // 断开区块连接，从区块链中移除区块
  bool DisconnectBlock();

  // 连接区块，将区块添加到区块链中
  // 参数：
  //   nFile: 区块文件编号
  //   nBlockPos: 区块在文件中的位置
  //   nHeight: 区块高度
  bool ConnectBlock(unsigned int nFile, unsigned int nBlockPos, int nHeight);

  // 将区块添加到区块索引
  // 参数：
  //   nFile: 区块文件编号
  //   nBlockPos: 区块在文件中的位置
  //   fWriteDisk: 是否写入磁盘
  bool AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos,
                       bool fWriteDisk);

  // 检查区块是否有效
  bool CheckBlock() const;

  // 接受区块，执行完整的验证和处理
  bool AcceptBlock();
};

// 区块索引类
// 区块链是一个树形结构，从创世区块开始作为根节点，每个区块可能有多个候选区块作为下一个区块。
// pprev和pnext链接通过主链/最长链的路径。一个区块索引可能有多个pprev指向它，
// 但pnext只会指向前方的最长分支，如果区块不是最长链的一部分，pnext将为null。
//
// CBlockIndex用于在内存中维护区块链的结构，提高区块查找和遍历的效率
class CBlockIndex {
public:
  CBlockIndex *pprev;     // 指向链中前一个区块索引的指针
  CBlockIndex *pnext;     // 指向链中后一个区块索引的指针（仅在主链上）
  unsigned int nFile;     // 区块数据存储在哪个文件中
  unsigned int nBlockPos; // 区块在文件中的位置
  int nHeight;            // 区块高度（从创世区块开始的区块数量）

  // 默认构造函数
  CBlockIndex() {
    pprev = NULL;
    pnext = NULL;
    nFile = 0;
    nBlockPos = 0;
    nHeight = 0;
  }

  // 构造函数，指定文件编号和区块位置
  CBlockIndex(unsigned int nFileIn, unsigned int nBlockPosIn) {
    pprev = NULL;
    pnext = NULL;
    nFile = nFileIn;
    nBlockPos = nBlockPosIn;
    nHeight = 0;
  }

  // 检查区块是否在主链中
  // 返回值：true表示在主链中，false表示不在主链中
  bool IsInMainChain() const { return (pnext || this == pindexBest); }

  // 从磁盘上删除区块
  // 将区块内容覆盖为空的null区块
  bool EraseBlockFromDisk() {
    // 打开历史文件
    CAutoFile fileout = OpenBlockFile(nFile, nBlockPos, "rb+");
    if (!fileout)
      return false;

    // 用空的null区块覆盖原区块
    CBlock block;
    block.SetNull();
    fileout << block;

    return true;
  }

  // 测试断开区块连接（用于测试）
  // 参数：
  //   txdb: 交易数据库
  //   mapTestPool: 测试交易池
  // 返回值：true表示测试成功，false表示测试失败
  bool TestDisconnectBlock(CTxDB &txdb,
                           map<uint256, CTransaction> &mapTestPool) {
    CBlock block;
    if (!block.ReadFromDisk(nFile, nBlockPos, true))
      return false;
    return block.TestDisconnectBlock(txdb, mapTestPool);
  }

  // 测试连接区块（用于测试）
  // 参数：
  //   txdb: 交易数据库
  //   mapTestPool: 测试交易池
  // 返回值：true表示测试成功，false表示测试失败
  bool TestConnectBlock(CTxDB &txdb, map<uint256, CTransaction> &mapTestPool) {
    CBlock block;
    if (!block.ReadFromDisk(nFile, nBlockPos, true))
      return false;
    return block.TestConnectBlock(txdb, mapTestPool);
  }

  // 断开区块连接，从区块链中移除区块
  bool DisconnectBlock() {
    CBlock block;
    if (!block.ReadFromDisk(nFile, nBlockPos, true))
      return false;
    return block.DisconnectBlock();
  }

  // 连接区块，将区块添加到区块链中
  bool ConnectBlock() {
    CBlock block;
    if (!block.ReadFromDisk(nFile, nBlockPos, true))
      return false;
    return block.ConnectBlock(nFile, nBlockPos, nHeight);
  }

  // 打印区块索引信息
  void print() const {
    printf("CBlockIndex(nprev=%08x, pnext=%08x, nFile=%d, nBlockPos=%d, "
           "nHeight=%d)\n",
           pprev, pnext, nFile, nBlockPos, nHeight);
  }
};

// 打印时间链信息
void PrintTimechain();

// 区块定位器类
// 用于向其他节点描述区块链中的位置，以便如果其他节点没有相同的分支，
// 它可以找到最近的共同主干。定位器越靠后，它可能离分支点越远。
// CBlockLocator通过存储一系列区块哈希来工作，这些哈希形成了一条通向目标区块的路径
class CBlockLocator {
protected:
  vector<uint256> vHave; // 存储区块哈希的向量，用于定位区块链中的位置

public:
  // 默认构造函数
  CBlockLocator() {}

  // 构造函数，根据区块索引创建定位器
  explicit CBlockLocator(const CBlockIndex *pindex) { Set(pindex); }

  // 构造函数，根据区块哈希创建定位器
  explicit CBlockLocator(uint256 hashBlock) {
    map<uint256, CBlockIndex *>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi != mapBlockIndex.end())
      Set((*mi).second);
  }

  // 序列化和反序列化宏
  IMPLEMENT_SERIALIZE(if (!(nType & SER_GETHASH)) READWRITE(nVersion);
                      READWRITE(vHave);)

  // 根据区块索引设置定位器
  // 参数：pindex - 区块索引指针，从该区块开始构建定位器
  // 该方法会从指定区块开始，以指数增长的步长向后遍历区块链，收集区块哈希
  void Set(const CBlockIndex *pindex) {
    vHave.clear();
    int nStep = 1;
    while (pindex) {
      CBlock block;
      block.ReadFromDisk(pindex, false);
      vHave.push_back(block.GetHash());

      // 以指数增长的步长向后遍历
      for (int i = 0; pindex && i < nStep; i++)
        pindex = pindex->pprev;
      if (vHave.size() > 10)
        nStep *= 2;
    }
  }

  // 获取定位器中第一个在主链上的区块索引
  // 返回值：指向区块索引的指针，如果没有找到则返回创世区块索引
  CBlockIndex *GetBlockIndex() {
    // 找到调用者在主链上拥有的第一个区块
    foreach (const uint256 &hash, vHave) {
      map<uint256, CBlockIndex *>::iterator mi = mapBlockIndex.find(hash);
      if (mi != mapBlockIndex.end()) {
        CBlockIndex *pindex = (*mi).second;
        if (pindex->IsInMainChain())
          return pindex;
      }
    }
    return pindexGenesisBlock;
  }

  // 获取定位器中第一个在主链上的区块哈希
  // 返回值：区块哈希，如果没有找到则返回创世区块哈希
  uint256 GetBlockHash() {
    // 找到调用者在主链上拥有的第一个区块
    foreach (const uint256 &hash, vHave) {
      map<uint256, CBlockIndex *>::iterator mi = mapBlockIndex.find(hash);
      if (mi != mapBlockIndex.end()) {
        CBlockIndex *pindex = (*mi).second;
        if (pindex->IsInMainChain())
          return hash;
      }
    }
    return hashGenesisBlock;
  }

  // 获取定位器中第一个在主链上的区块高度
  // 返回值：区块高度，如果没有找到则返回0
  int GetHeight() {
    CBlockIndex *pindex = GetBlockIndex();
    if (!pindex)
      return 0;
    return pindex->nHeight;
  }
};

// 全局变量定义

extern map<uint256, CTransaction>
    mapTransactions; // 交易映射表，存储所有已知交易
extern map<uint256, CWalletTx>
    mapWallet; // 钱包交易映射表，存储用户钱包中的所有交易
extern vector<pair<uint256, bool>>
    vWalletUpdated; // 钱包更新向量，记录钱包中已更新的交易哈希和更新类型
extern CCriticalSection cs_mapWallet;
extern map<vector<unsigned char>, CPrivKey> mapKeys;
extern map<uint160, vector<unsigned char>> mapPubKeys;
extern CCriticalSection cs_mapKeys;
extern CKey keyUser;