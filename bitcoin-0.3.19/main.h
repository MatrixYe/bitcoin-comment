// Copyright (c) 2009-2010 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

/**
 * Bitcoin 0.3.19 - 主要头文件
 * 
 * 该文件定义了比特币系统的核心数据结构和功能接口，包括：
 * 1. 交易相关类（CTransaction, CTxIn, CTxOut等）
 * 2. 区块相关类（CBlock, CBlockIndex等）
 * 3. 钱包相关类（CWalletTx, CAccount等）
 * 4. 全局常量和变量
 * 5. 核心功能函数声明
 * 
 * 这是比特币系统的核心头文件，几乎所有其他模块都依赖于它。
 */

// 前置类声明，用于减少编译依赖和循环引用
class COutPoint;      // 交易输出引用
class CInPoint;       // 内存中交易输入引用
class CDiskTxPos;     // 磁盘上交易位置
class CCoinBase;      // Coinbase交易（新区块产生的奖励交易）
class CTxIn;          // 交易输入
class CTxOut;         // 交易输出
class CTransaction;   // 完整交易
class CBlock;         // 区块
class CBlockIndex;    // 区块索引
class CWalletTx;      // 钱包交易（包含额外的钱包相关信息）
class CKeyItem;       // 密钥项

/**
 * 系统核心常量定义
 */
static const unsigned int MAX_BLOCK_SIZE = 1000000;        // 最大区块大小 (1MB)
static const unsigned int MAX_BLOCK_SIZE_GEN = MAX_BLOCK_SIZE / 2;  // 生成新区块时的默认最大大小 (0.5MB)
static const int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE / 50;   // 区块中允许的最大签名操作数

static const int64 COIN = 100000000;                       // 1比特币 = 1亿聪 (最小货币单位)
static const int64 CENT = 1000000;                         // 1分比特币 = 100万聪
static const int64 MAX_MONEY = 21000000 * COIN;            // 比特币最大供应量 (2100万比特币)

/**
 * 检查货币值是否在有效范围内
 * @param nValue 要检查的货币值
 * @return 如果值在0到MAX_MONEY之间则返回true，否则返回false
 */
inline bool MoneyRange(int64 nValue) {
  return (nValue >= 0 && nValue <= MAX_MONEY);
}

static const int COINBASE_MATURITY = 100;                  // Coinbase交易成熟度要求 (需要100个确认才能使用)

/**
 * 全局变量声明
 */

// 主关键部分锁，用于保护区块链数据结构的并发访问
extern CCriticalSection cs_main;

// 区块索引映射表，通过区块哈希快速查找区块索引
extern map<uint256, CBlockIndex *> mapBlockIndex;

// 创世区块哈希值
extern uint256 hashGenesisBlock;

// 工作量证明难度上限
extern CBigNum bnProofOfWorkLimit;

// 创世区块的索引指针
extern CBlockIndex *pindexGenesisBlock;

// 当前最佳链的高度
extern int nBestHeight;

// 当前最佳链的总工作量
extern CBigNum bnBestChainWork;

// 当前最佳无效链的总工作量
extern CBigNum bnBestInvalidWork;

// 当前最佳链的哈希值
extern uint256 hashBestChain;

// 当前最佳链的区块索引指针
extern CBlockIndex *pindexBest;

// 交易更新计数器
extern unsigned int nTransactionsUpdated;

// 请求计数映射表，用于跟踪已请求的区块和交易
extern map<uint256, int> mapRequestCount;
extern CCriticalSection cs_mapRequestCount;  // 保护mapRequestCount的互斥锁

// 地址簿映射表，存储用户的地址簿信息
extern map<string, string> mapAddressBook;
extern CCriticalSection cs_mapAddressBook;  // 保护mapAddressBook的互斥锁

// 默认密钥
extern vector<unsigned char> vchDefaultKey;

// 每秒哈希计算能力（用于挖矿）
extern double dHashesPerSec;

// 哈希率计时器起始时间
extern int64 nHPSTimerStart;

// Settings
extern int fGenerateBitcoins;
extern int64 nTransactionFee;
extern CAddress addrIncoming;
extern int fLimitProcessors;
extern int nLimitProcessors;
extern int fMinimizeToTray;
extern int fMinimizeOnClose;

/**
 * 核心功能函数声明
 */

/**
 * 检查磁盘空间是否足够
 * @param nAdditionalBytes 需要的额外字节数
 * @return 如果空间足够则返回true，否则返回false
 */
bool CheckDiskSpace(uint64 nAdditionalBytes = 0);

/**
 * 打开区块文件
 * @param nFile 文件号
 * @param nBlockPos 区块在文件中的位置
 * @param pszMode 打开模式
 * @return 文件指针
 */
FILE *OpenBlockFile(unsigned int nFile, unsigned int nBlockPos,
                    const char *pszMode = "rb");

/**
 * 追加创建新区块文件
 * @param nFileRet 返回新文件号
 * @return 文件指针
 */
FILE *AppendBlockFile(unsigned int &nFileRet);

/**
 * 添加密钥到钱包
 * @param key 要添加的密钥
 * @return 添加成功返回true
 */
bool AddKey(const CKey &key);

/**
 * 生成新密钥
 * @return 新生成的密钥
 */
vector<unsigned char> GenerateNewKey();

/**
 * 添加交易到钱包
 * @param wtxIn 要添加的钱包交易
 * @return 添加成功返回true
 */
bool AddToWallet(const CWalletTx &wtxIn);

/**
 * 更新钱包中已花费的输出
 * @param prevout 已花费的输出引用
 */
void WalletUpdateSpent(const COutPoint &prevout);

/**
 * 重新接受钱包交易
 */
void ReacceptWalletTransactions();

/**
 * 加载区块索引
 * @param fAllowNew 是否允许创建新索引
 * @return 加载成功返回true
 */
bool LoadBlockIndex(bool fAllowNew = true);

/**
 * 打印区块树
 */
void PrintBlockTree();

/**
 * 处理来自节点的消息
 * @param pfrom 发送消息的节点
 * @return 处理成功返回true
 */
bool ProcessMessages(CNode *pfrom);

/**
 * 处理单条消息
 * @param pfrom 发送消息的节点
 * @param strCommand 消息命令
 * @param vRecv 消息数据
 * @return 处理成功返回true
 */
bool ProcessMessage(CNode *pfrom, string strCommand, CDataStream &vRecv);

/**
 * 发送消息到节点
 * @param pto 接收消息的节点
 * @param fSendTrickle 是否使用涓流发送
 * @return 发送成功返回true
 */
bool SendMessages(CNode *pto, bool fSendTrickle);

/**
 * 获取钱包余额
 * @return 钱包余额
 */
int64 GetBalance();

/**
 * 创建新交易
 * @param scriptPubKey 公钥脚本
 * @param nValue 交易金额
 * @param wtxNew 返回创建的新钱包交易
 * @param reservekey 返回用于找零的密钥
 * @param nFeeRet 返回交易费用
 * @return 创建成功返回true
 */
bool CreateTransaction(CScript scriptPubKey, int64 nValue, CWalletTx &wtxNew,
                       CReserveKey &reservekey, int64 &nFeeRet);

/**
 * 提交交易
 * @param wtxNew 要提交的钱包交易
 * @param reservekey 找零密钥
 * @return 提交成功返回true
 */
bool CommitTransaction(CWalletTx &wtxNew, CReserveKey &reservekey);

/**
 * 广播交易
 * @param wtxNew 要广播的钱包交易
 * @return 广播成功返回true
 */
bool BroadcastTransaction(CWalletTx &wtxNew);

/**
 * 发送比特币
 * @param scriptPubKey 公钥脚本
 * @param nValue 发送金额
 * @param wtxNew 返回创建的钱包交易
 * @param fAskFee 是否询问费用
 * @return 操作结果描述
 */
string SendMoney(CScript scriptPubKey, int64 nValue, CWalletTx &wtxNew,
                 bool fAskFee = false);

/**
 * 发送比特币到地址
 * @param strAddress 接收地址
 * @param nValue 发送金额
 * @param wtxNew 返回创建的钱包交易
 * @param fAskFee 是否询问费用
 * @return 操作结果描述
 */
string SendMoneyToBitcoinAddress(string strAddress, int64 nValue,
                                 CWalletTx &wtxNew, bool fAskFee = false);

/**
 * 设置是否生成比特币
 * @param fGenerate 是否生成
 */
void GenerateBitcoins(bool fGenerate);

/**
 * 比特币挖矿线程函数
 * @param parg 线程参数
 */
void ThreadBitcoinMiner(void *parg);

/**
 * 创建新区块
 * @param reservekey 密钥预留
 * @return 新创建的区块
 */
CBlock *CreateNewBlock(CReserveKey &reservekey);

/**
 * 增加额外随机数
 * @param pblock 区块指针
 * @param pindexPrev 前一个区块索引
 * @param nExtraNonce 额外随机数
 * @param nPrevTime 前一个时间
 */
void IncrementExtraNonce(CBlock *pblock, CBlockIndex *pindexPrev,
                         unsigned int &nExtraNonce, int64 &nPrevTime);

/**
 * 格式化哈希缓冲区
 * @param pblock 区块指针
 * @param pmidstate 中间状态
 * @param pdata 数据
 * @param phash1 哈希1
 */
void FormatHashBuffers(CBlock *pblock, char *pmidstate, char *pdata,
                       char *phash1);

/**
 * 检查工作量证明
 * @param pblock 区块指针
 * @param reservekey 密钥预留
 * @return 检查通过返回true
 */
bool CheckWork(CBlock *pblock, CReserveKey &reservekey);

/**
 * 比特币挖矿
 */
void BitcoinMiner();

/**
 * 检查工作量证明
 * @param hash 区块哈希
 * @param nBits 难度目标
 * @return 检查通过返回true
 */
bool CheckProofOfWork(uint256 hash, unsigned int nBits);

/**
 * 检查是否正在进行初始区块下载
 * @return 是返回true
 */
bool IsInitialBlockDownload();

/**
 * 获取警告信息
 * @param strFor 警告对象
 * @return 警告信息
 */
string GetWarnings(string strFor);

/**
 * 磁盘交易位置类
 * 
 * 用于记录交易在磁盘上的存储位置，包括所在文件、所在区块位置和在区块内的位置。
 * 这是比特币数据持久化的关键类之一，用于快速定位和读取磁盘上的交易数据。
 */
class CDiskTxPos {
public:
  unsigned int nFile;       // 交易所在的文件号
  unsigned int nBlockPos;   // 交易所在区块在文件中的起始位置
  unsigned int nTxPos;      // 交易在区块内的偏移位置

  /**
   * 默认构造函数
   * 初始化一个空的交易位置
   */
  CDiskTxPos() { SetNull(); }

  /**
   * 构造函数
   * @param nFileIn 文件号
   * @param nBlockPosIn 区块在文件中的位置
   * @param nTxPosIn 交易在区块内的位置
   */
  CDiskTxPos(unsigned int nFileIn, unsigned int nBlockPosIn,
             unsigned int nTxPosIn) {
    nFile = nFileIn;
    nBlockPos = nBlockPosIn;
    nTxPos = nTxPosIn;
  }

  /**
   * 序列化/反序列化方法
   * 使用FLATDATA进行高效的二进制序列化
   */
  IMPLEMENT_SERIALIZE(READWRITE(FLATDATA(*this));)
  
  /**
   * 将交易位置设置为空状态
   */
  void SetNull() {
    nFile = -1;
    nBlockPos = 0;
    nTxPos = 0;
  }
  
  /**
   * 检查交易位置是否为空
   * @return 如果为空则返回true，否则返回false
   */
  bool IsNull() const { return (nFile == -1); }

  /**
   * 相等运算符重载
   */
  friend bool operator==(const CDiskTxPos &a, const CDiskTxPos &b) {
    return (a.nFile == b.nFile && a.nBlockPos == b.nBlockPos &&
            a.nTxPos == b.nTxPos);
  }

  /**
   * 不相等运算符重载
   */
  friend bool operator!=(const CDiskTxPos &a, const CDiskTxPos &b) {
    return !(a == b);
  }

  /**
   * 转换为字符串表示
   * @return 交易位置的字符串表示
   */
  string ToString() const {
    if (IsNull())
      return strprintf("null");
    else
      return strprintf("(nFile=%d, nBlockPos=%d, nTxPos=%d)", nFile, nBlockPos,
                       nTxPos);
  }

  /**
   * 打印交易位置信息
   */
  void print() const { printf("%s", ToString().c_str()); }
};

class CInPoint {
public:
  CTransaction *ptx;
  unsigned int n;

  CInPoint() { SetNull(); }
  CInPoint(CTransaction *ptxIn, unsigned int nIn) {
    ptx = ptxIn;
    n = nIn;
  }
  void SetNull() {
    ptx = NULL;
    n = -1;
  }
  bool IsNull() const { return (ptx == NULL && n == -1); }
};

/**
 * 交易输出引用类
 * 
 * 用于唯一标识一个交易输出（UTXO），由创建该输出的交易哈希和该交易中的输出索引组成。
 * 这是比特币交易系统的核心组件之一，用于构建交易输入（CTxIn），指向被花费的输出。
 */
class COutPoint {
public:
  uint256 hash;    // 创建该输出的交易哈希
  unsigned int n;  // 交易中的输出索引（从0开始）

  /**
   * 默认构造函数
   * 创建一个空的交易输出引用
   */
  COutPoint() { SetNull(); }
  
  /**
   * 构造函数
   * @param hashIn 创建该输出的交易哈希
   * @param nIn 交易中的输出索引
   */
  COutPoint(uint256 hashIn, unsigned int nIn) {
    hash = hashIn;
    n = nIn;
  }
  
  /**
   * 序列化/反序列化方法
   * 使用FLATDATA进行高效的二进制序列化
   */
  IMPLEMENT_SERIALIZE(READWRITE(FLATDATA(*this));)
  
  /**
   * 将交易输出引用设置为空状态
   */
  void SetNull() {
    hash = 0;
    n = -1;
  }
  
  /**
   * 检查交易输出引用是否为空
   * @return 如果为空则返回true，否则返回false
   */
  bool IsNull() const { return (hash == 0 && n == -1); }

  /**
   * 小于运算符重载
   * 用于支持在容器中排序和比较
   */
  friend bool operator<(const COutPoint &a, const COutPoint &b) {
    return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
  }

  /**
   * 相等运算符重载
   */
  friend bool operator==(const COutPoint &a, const COutPoint &b) {
    return (a.hash == b.hash && a.n == b.n);
  }

  /**
   * 不相等运算符重载
   */
  friend bool operator!=(const COutPoint &a, const COutPoint &b) {
    return !(a == b);
  }

  /**
   * 转换为字符串表示
   * @return 交易输出引用的字符串表示
   */
  string ToString() const {
    return strprintf("COutPoint(%s, %d)", hash.ToString().substr(0, 10).c_str(),
                     n);
  }

  /**
   * 打印交易输出引用信息
   */
  void print() const { printf("%s\n", ToString().c_str()); }
};

/**
 * 交易输入类
 * 
 * 表示交易的输入部分，包含对之前交易输出的引用和用于验证所有权的签名脚本。
 * 每个交易输入必须引用一个未花费的交易输出（UTXO）并提供有效的签名证明所有权。
 */
class CTxIn {
public:
  COutPoint prevout;      // 引用的前一个交易输出
  CScript scriptSig;      // 签名脚本，用于证明对引用输出的所有权
  unsigned int nSequence; // 序列编号，用于交易替换功能和相对时间锁定

  /**
   * 默认构造函数
   */
  CTxIn() { nSequence = UINT_MAX; }

  /**
   * 构造函数
   * @param prevoutIn 前一个交易输出的引用
   * @param scriptSigIn 签名脚本
   * @param nSequenceIn 序列编号
   */
  explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn = CScript(),
                 unsigned int nSequenceIn = UINT_MAX) {
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
  }

  /**
   * 构造函数
   * @param hashPrevTx 前一个交易的哈希
   * @param nOut 前一个交易中的输出索引
   * @param scriptSigIn 签名脚本
   * @param nSequenceIn 序列编号
   */
  CTxIn(uint256 hashPrevTx, unsigned int nOut, CScript scriptSigIn = CScript(),
        unsigned int nSequenceIn = UINT_MAX) {
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
  }

  /**
   * 序列化/反序列化方法
   */
  IMPLEMENT_SERIALIZE(READWRITE(prevout); READWRITE(scriptSig);
                      READWRITE(nSequence);)

  /**
   * 检查交易输入是否为最终状态
   * @return 如果nSequence为UINT_MAX则返回true，表示交易输入不可替换
   */
  bool IsFinal() const { return (nSequence == UINT_MAX); }

  /**
   * 相等运算符重载
   */
  friend bool operator==(const CTxIn &a, const CTxIn &b) {
    return (a.prevout == b.prevout && a.scriptSig == b.scriptSig &&
            a.nSequence == b.nSequence);
  }

  /**
   * 不相等运算符重载
   */
  friend bool operator!=(const CTxIn &a, const CTxIn &b) { return !(a == b); }

  /**
   * 转换为字符串表示
   * @return 交易输入的字符串表示
   */
  string ToString() const {
    string str;
    str += strprintf("CTxIn(");
    str += prevout.ToString();
    if (prevout.IsNull())
      str += strprintf(", coinbase %s", HexStr(scriptSig).c_str());
    else
      str += strprintf(", scriptSig=%s",
                       scriptSig.ToString().substr(0, 24).c_str());
    if (nSequence != UINT_MAX)
      str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
  }

  /**
   * 打印交易输入信息
   */
  void print() const { printf("%s\n", ToString().c_str()); }

  bool IsMine() const;
  int64 GetDebit() const;
};

/**
 * 交易输出类
 * 
 * 表示交易的输出部分，包含转账金额和锁定脚本。
 * 锁定脚本定义了未来的交易输入必须满足的条件才能花费此输出。
 */
class CTxOut {
public:
  int64 nValue;          // 输出金额（以聪为单位）
  CScript scriptPubKey;  // 锁定脚本，定义了花费此输出的条件

  /**
   * 默认构造函数
   */
  CTxOut() { SetNull(); }

  /**
   * 构造函数
   * @param nValueIn 输出金额（以聪为单位）
   * @param scriptPubKeyIn 锁定脚本
   */
  CTxOut(int64 nValueIn, CScript scriptPubKeyIn) {
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
  }

  /**
   * 序列化/反序列化方法
   */
  IMPLEMENT_SERIALIZE(READWRITE(nValue); READWRITE(scriptPubKey);)

  /**
   * 将交易输出设置为空状态
   */
  void SetNull() {
    nValue = -1;
    scriptPubKey.clear();
  }

  /**
   * 检查交易输出是否为空
   * @return 如果为空则返回true，否则返回false
   */
  bool IsNull() { return (nValue == -1); }

  /**
   * 获取交易输出的哈希值
   * @return 交易输出的哈希值
   */
  uint256 GetHash() const { return SerializeHash(*this); }

  /**
   * 检查此输出是否属于当前钱包
   * @return 如果属于当前钱包则返回true，否则返回false
   */
  bool IsMine() const { return ::IsMine(scriptPubKey); }

  /**
   * 获取此输出的信用金额（仅当属于当前钱包时）
   * @return 信用金额（以聪为单位）
   */
  int64 GetCredit() const {
    if (!MoneyRange(nValue))
      throw runtime_error("CTxOut::GetCredit() : value out of range");
    return (IsMine() ? nValue : 0);
  }

  /**
   * 检查此输出是否为找零
   * @return 如果是找零则返回true，否则返回false
   */
  bool IsChange() const {
    // 对于支出交易，如果输出属于当前钱包但不在地址簿中，则视为找零
    vector<unsigned char> vchPubKey;
    if (ExtractPubKey(scriptPubKey, true, vchPubKey))
      CRITICAL_BLOCK(cs_mapAddressBook)
    if (!mapAddressBook.count(PubKeyToAddress(vchPubKey)))
      return true;
    return false;
  }

  /**
   * 获取找零金额
   * @return 找零金额（以聪为单位）
   */
  int64 GetChange() const {
    if (!MoneyRange(nValue))
      throw runtime_error("CTxOut::GetChange() : value out of range");
    return (IsChange() ? nValue : 0);
  }

  /**
   * 相等运算符重载
   */
  friend bool operator==(const CTxOut &a, const CTxOut &b) {
    return (a.nValue == b.nValue && a.scriptPubKey == b.scriptPubKey);
  }

  /**
   * 不相等运算符重载
   */
  friend bool operator!=(const CTxOut &a, const CTxOut &b) { return !(a == b); }

  /**
   * 转换为字符串表示
   * @return 交易输出的字符串表示
   */
  string ToString() const {
    if (scriptPubKey.size() < 6)
      return "CTxOut(error)";
    return strprintf("CTxOut(nValue=%" PRI64d ".%08" PRI64d
                     ", scriptPubKey=%s)",
                     nValue / COIN, nValue % COIN,
                     scriptPubKey.ToString().substr(0, 30).c_str());
  }

  /**
   * 打印交易输出信息
   */
  void print() const { printf("%s\n", ToString().c_str()); }
};

//
/**
 * 交易类
 * 
 * 网络上广播并包含在区块中的基本交易结构。
 * 一个交易可以包含多个输入和输出，实现比特币的价值转移。
 */
class CTransaction {
public:
  int nVersion;              // 交易版本号
  vector<CTxIn> vin;         // 交易输入向量
  vector<CTxOut> vout;       // 交易输出向量
  unsigned int nLockTime;    // 锁定时间（0表示立即执行）

  /**
   * 默认构造函数
   */
  CTransaction() { SetNull(); }

  /**
   * 序列化/反序列化方法
   */
  IMPLEMENT_SERIALIZE(READWRITE(this->nVersion); nVersion = this->nVersion;
                      READWRITE(vin); READWRITE(vout); READWRITE(nLockTime);)

  /**
   * 将交易设置为空状态
   */
  void SetNull() {
    nVersion = 1;
    vin.clear();
    vout.clear();
    nLockTime = 0;
  }

  /**
   * 检查交易是否为空
   * @return 如果交易为空则返回true，否则返回false
   */
  bool IsNull() const { return (vin.empty() && vout.empty()); }

  /**
   * 获取交易的哈希值
   * @return 交易的哈希值
   */
  uint256 GetHash() const { return SerializeHash(*this); }

  /**
   * 检查交易是否已最终确认（可执行）
   * @param nBlockHeight 当前区块高度（默认使用最佳链高度）
   * @param nBlockTime 当前区块时间（默认使用调整后的当前时间）
   * @return 如果交易已最终确认则返回true，否则返回false
   */
  bool IsFinal(int nBlockHeight = 0, int64 nBlockTime = 0) const {
    // Time based nLockTime implemented in 0.1.6
    if (nLockTime == 0)
      return true;
    if (nBlockHeight == 0)
      nBlockHeight = nBestHeight;
    if (nBlockTime == 0)
      nBlockTime = GetAdjustedTime();
    if ((int64)nLockTime <
        (nLockTime < 500000000 ? (int64)nBlockHeight : nBlockTime))
      return true;
    foreach (const CTxIn &txin, vin)
      if (!txin.IsFinal())
        return false;
    return true;
  }

  /**
   * 比较交易是否比另一个更新
   * 用于处理交易替换（double spend）的情况
   * @param old 要比较的旧交易
   * @return 如果当前交易更新则返回true，否则返回false
   */
  bool IsNewerThan(const CTransaction &old) const {
    if (vin.size() != old.vin.size())
      return false;
    for (int i = 0; i < vin.size(); i++)
      if (vin[i].prevout != old.vin[i].prevout)
        return false;

    bool fNewer = false;
    unsigned int nLowest = UINT_MAX;
    for (int i = 0; i < vin.size(); i++) {
      if (vin[i].nSequence != old.vin[i].nSequence) {
        if (vin[i].nSequence <= nLowest) {
          fNewer = false;
          nLowest = vin[i].nSequence;
        }
        if (old.vin[i].nSequence < nLowest) {
          fNewer = true;
          nLowest = old.vin[i].nSequence;
        }
      }
    }
    return fNewer;
  }

  /**
   * 检查交易是否为coinbase交易
   * Coinbase交易是区块中的第一个交易，用于奖励矿工
   * @return 如果是coinbase交易则返回true，否则返回false
   */
  bool IsCoinBase() const {
    return (vin.size() == 1 && vin[0].prevout.IsNull());
  }

  /**
   * 获取交易中的签名操作数量
   * @return 签名操作的总数
   */
  int GetSigOpCount() const {
    int n = 0;
    foreach (const CTxIn &txin, vin)
      n += txin.scriptSig.GetSigOpCount();
    foreach (const CTxOut &txout, vout)
      n += txout.scriptPubKey.GetSigOpCount();
    return n;
  }

  /**
   * 检查交易是否符合标准格式
   * 标准交易更容易被网络节点接受和中继
   * @return 如果交易符合标准则返回true，否则返回false
   */
  bool IsStandard() const {
    foreach (const CTxIn &txin, vin)
      if (!txin.scriptSig.IsPushOnly())
        return error("nonstandard txin: %s", txin.scriptSig.ToString().c_str());
    foreach (const CTxOut &txout, vout)
      if (!::IsStandard(txout.scriptPubKey))
        return error("nonstandard txout: %s",
                     txout.scriptPubKey.ToString().c_str());
    return true;
  }

  /**
   * 检查交易是否包含属于当前钱包的输出
   * @return 如果交易包含属于当前钱包的输出则返回true，否则返回false
   */
  bool IsMine() const {
    foreach (const CTxOut &txout, vout)
      if (txout.IsMine())
        return true;
    return false;
  }

  /**
   * 检查交易是否由当前钱包发出
   * @return 如果交易由当前钱包发出则返回true，否则返回false
   */
  bool IsFromMe() const { return (GetDebit() > 0); }

  /**
   * 获取交易的总支出金额
   * @return 交易的总支出金额（以聪为单位）
   */
  int64 GetDebit() const {
    int64 nDebit = 0;
    foreach (const CTxIn &txin, vin) {
      nDebit += txin.GetDebit();
      if (!MoneyRange(nDebit))
        throw runtime_error("CTransaction::GetDebit() : value out of range");
    }
    return nDebit;
  }

  /**
   * 获取交易的总信用金额（仅计算属于当前钱包的输出）
   * @return 交易的总信用金额（以聪为单位）
   */
  int64 GetCredit() const {
    int64 nCredit = 0;
    foreach (const CTxOut &txout, vout) {
      nCredit += txout.GetCredit();
      if (!MoneyRange(nCredit))
        throw runtime_error("CTransaction::GetCredit() : value out of range");
    }
    return nCredit;
  }

  /**
   * 获取交易的总找零金额
   * @return 交易的总找零金额（以聪为单位）
   */
  int64 GetChange() const {
    if (IsCoinBase())
      return 0;
    int64 nChange = 0;
    foreach (const CTxOut &txout, vout) {
      nChange += txout.GetChange();
      if (!MoneyRange(nChange))
        throw runtime_error("CTransaction::GetChange() : value out of range");
    }
    return nChange;
  }

  /**
   * 获取交易的总输出金额
   * @return 交易的总输出金额（以聪为单位）
   */
  int64 GetValueOut() const {
    int64 nValueOut = 0;
    foreach (const CTxOut &txout, vout) {
      nValueOut += txout.nValue;
      if (!MoneyRange(txout.nValue) || !MoneyRange(nValueOut))
        throw runtime_error("CTransaction::GetValueOut() : value out of range");
    }
    return nValueOut;
  }

  /**
   * 计算交易的最低手续费
   * @param nBlockSize 当前区块大小（1表示新区块）
   * @param fAllowFree 是否允许免费交易
   * @return 交易的最低手续费（以聪为单位）
   */
  int64 GetMinFee(unsigned int nBlockSize = 1, bool fAllowFree = true) const {
    // Base fee is 1 cent per kilobyte
    unsigned int nBytes = ::GetSerializeSize(*this, SER_NETWORK);
    unsigned int nNewBlockSize = nBlockSize + nBytes;
    int64 nMinFee = (1 + (int64)nBytes / 1000) * CENT;

    if (fAllowFree) {
      if (nBlockSize == 1) {
        // Transactions under 10K are free
        // (about 4500bc if made of 50bc inputs)
        if (nBytes < 10000)
          nMinFee = 0;
      } else {
        // Free transaction area
        if (nNewBlockSize < 27000)
          nMinFee = 0;
      }
    }

    // To limit dust spam, require a 0.01 fee if any output is less than 0.01
    if (nMinFee < CENT)
      foreach (const CTxOut &txout, vout)
        if (txout.nValue < CENT)
          nMinFee = CENT;

    // Raise the price as the block approaches full
    if (nBlockSize != 1 && nNewBlockSize >= MAX_BLOCK_SIZE_GEN / 2) {
      if (nNewBlockSize >= MAX_BLOCK_SIZE_GEN)
        return MAX_MONEY;
      nMinFee *= MAX_BLOCK_SIZE_GEN / (MAX_BLOCK_SIZE_GEN - nNewBlockSize);
    }

    if (!MoneyRange(nMinFee))
      nMinFee = MAX_MONEY;
    return nMinFee;
  }

  /**
   * 从磁盘读取交易
   * @param pos 交易在磁盘上的位置
   * @param pfileRet 返回文件指针（可选）
   * @return 读取成功则返回true，否则返回false
   */
  bool ReadFromDisk(CDiskTxPos pos, FILE **pfileRet = NULL) {
    CAutoFile filein = OpenBlockFile(pos.nFile, 0, pfileRet ? "rb+" : "rb");
    if (!filein)
      return error("CTransaction::ReadFromDisk() : OpenBlockFile failed");

    // Read transaction
    if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
      return error("CTransaction::ReadFromDisk() : fseek failed");
    filein >> *this;

    // Return file pointer
    if (pfileRet) {
      if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
        return error("CTransaction::ReadFromDisk() : second fseek failed");
      *pfileRet = filein.release();
    }
    return true;
  }

  /**
   * 相等运算符重载
   */
  friend bool operator==(const CTransaction &a, const CTransaction &b) {
    return (a.nVersion == b.nVersion && a.vin == b.vin && a.vout == b.vout &&
            a.nLockTime == b.nLockTime);
  }

  /**
   * 不相等运算符重载
   */
  friend bool operator!=(const CTransaction &a, const CTransaction &b) {
    return !(a == b);
  }

  /**
   * 转换为字符串表示
   * @return 交易的字符串表示
   */
  string ToString() const {
    string str;
    str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%d, vout.size=%d, "
                     "nLockTime=%d)\n",
                     GetHash().ToString().substr(0, 10).c_str(), nVersion,
                     vin.size(), vout.size(), nLockTime);
    for (int i = 0; i < vin.size(); i++)
      str += "    " + vin[i].ToString() + "\n";
    for (int i = 0; i < vout.size(); i++)
      str += "    " + vout[i].ToString() + "\n";
    return str;
  }

  /**
   * 打印交易信息
   */
  void print() const { printf("%s", ToString().c_str()); }

  /**
   * 从磁盘读取交易（通过交易数据库和输出点）
   * @param txdb 交易数据库
   * @param prevout 引用此交易的输出点
   * @param txindexRet 返回的交易索引信息
   * @return 读取成功则返回true，否则返回false
   */
  bool ReadFromDisk(CTxDB &txdb, COutPoint prevout, CTxIndex &txindexRet);
  /**
   * 从磁盘读取交易（通过交易数据库和输出点）
   * @param txdb 交易数据库
   * @param prevout 引用此交易的输出点
   * @return 读取成功则返回true，否则返回false
   */
  bool ReadFromDisk(CTxDB &txdb, COutPoint prevout);
  /**
   * 从磁盘读取交易（通过输出点）
   * @param prevout 引用此交易的输出点
   * @return 读取成功则返回true，否则返回false
   */
  bool ReadFromDisk(COutPoint prevout);
  /**
   * 断开交易输入（用于区块回滚）
   * @param txdb 交易数据库
   * @return 断开成功则返回true，否则返回false
   */
  bool DisconnectInputs(CTxDB &txdb);
  /**
   * 连接交易输入（验证交易有效性）
   * @param txdb 交易数据库
   * @param mapTestPool 测试交易池
   * @param posThisTx 此交易在磁盘上的位置
   * @param pindexBlock 包含此交易的区块索引
   * @param nFees 返回的交易手续费
   * @param fBlock 是否为区块中的交易
   * @param fMiner 是否为矿工交易
   * @param nMinFee 最低手续费要求
   * @return 连接成功则返回true，否则返回false
   */
  bool ConnectInputs(CTxDB &txdb, map<uint256, CTxIndex> &mapTestPool,
                     CDiskTxPos posThisTx, CBlockIndex *pindexBlock,
                     int64 &nFees, bool fBlock, bool fMiner, int64 nMinFee = 0);
  /**
   * 客户端连接交易输入（简化版，不修改数据库）
   * @return 连接成功则返回true，否则返回false
   */
  bool ClientConnectInputs();
  /**
   * 检查交易本身的有效性
   * @return 如果交易有效则返回true，否则返回false
   */
  bool CheckTransaction() const;
  /**
   * 接受交易到内存池
   * @param txdb 交易数据库
   * @param fCheckInputs 是否检查输入
   * @param pfMissingInputs 返回缺失的输入信息
   * @return 接受成功则返回true，否则返回false
   */
  bool AcceptToMemoryPool(CTxDB &txdb, bool fCheckInputs = true,
                          bool *pfMissingInputs = NULL);
  /**
   * 接受交易到内存池（重载版本）
   * @param fCheckInputs 是否检查输入
   * @param pfMissingInputs 返回缺失的输入信息
   * @return 接受成功则返回true，否则返回false
   */
  bool AcceptToMemoryPool(bool fCheckInputs = true,
                          bool *pfMissingInputs = NULL) {
    CTxDB txdb("r");
    return AcceptToMemoryPool(txdb, fCheckInputs, pfMissingInputs);
  }

protected:
  /**
   * 不检查直接添加交易到内存池
   * @return 添加成功则返回true，否则返回false
   */
  bool AddToMemoryPoolUnchecked();

public:
  /**
   * 从内存池中移除交易
   * @return 移除成功则返回true，否则返回false
   */
  bool RemoveFromMemoryPool();
};

/**
 * Merkle交易类
 * 
 * 继承自CTransaction，添加了merkle分支信息，用于将交易链接到区块链上。
 * 包含merkle证明所需的所有信息，用于验证交易是否包含在某个区块中。
 */
class CMerkleTx : public CTransaction {
public:
  uint256 hashBlock;          // 包含此交易的区块哈希
  vector<uint256> vMerkleBranch;  // Merkle分支，用于验证交易在区块中的位置
  int nIndex;                 // 交易在区块中的索引位置

  // memory only
  mutable char fMerkleVerified;  // Merkle验证状态（仅内存中使用）

  /**
   * 默认构造函数
   */
  CMerkleTx() { Init(); }

  /**
   * 从CTransaction构造CMerkleTx
   * @param txIn 原始交易对象
   */
  CMerkleTx(const CTransaction &txIn) : CTransaction(txIn) { Init(); }

  /**
   * 初始化CMerkleTx对象
   */
  void Init() {
    hashBlock = 0;
    nIndex = -1;
    fMerkleVerified = false;
  }

  /**
   * 序列化/反序列化方法
   */
  IMPLEMENT_SERIALIZE(nSerSize += SerReadWrite(s, *(CTransaction *)this, nType,
                                               nVersion, ser_action);
                      nVersion = this->nVersion; READWRITE(hashBlock);
                      READWRITE(vMerkleBranch); READWRITE(nIndex);)

  /**
   * 设置Merkle分支信息
   * @param pblock 包含此交易的区块（可选）
   * @return 成功则返回0，否则返回错误代码
   */
  int SetMerkleBranch(const CBlock *pblock = NULL);
  /**
   * 获取交易在主链中的深度
   * @param nHeightRet 返回包含此交易的区块高度
   * @return 交易在主链中的深度
   */
  int GetDepthInMainChain(int &nHeightRet) const;
  /**
   * 获取交易在主链中的深度（重载版本）
   * @return 交易在主链中的深度
   */
  int GetDepthInMainChain() const {
    int nHeight;
    return GetDepthInMainChain(nHeight);
  }
  /**
   * 检查交易是否在主链中
   * @return 如果交易在主链中则返回true，否则返回false
   */
  bool IsInMainChain() const { return GetDepthInMainChain() > 0; }
  /**
   * 获取交易到成熟所需的区块数
   * @return 到成熟所需的区块数
   */
  int GetBlocksToMaturity() const;
  /**
   * 接受Merkle交易到内存池
   * @param txdb 交易数据库
   * @param fCheckInputs 是否检查输入
   * @return 接受成功则返回true，否则返回false
   */
  bool AcceptToMemoryPool(CTxDB &txdb, bool fCheckInputs = true);
  /**
   * 接受Merkle交易到内存池（重载版本）
   * @return 接受成功则返回true，否则返回false
   */
  bool AcceptToMemoryPool() {
    CTxDB txdb("r");
    return AcceptToMemoryPool(txdb);
  }
};

/**
 * 钱包交易类
 * 
 * 继承自CMerkleTx，包含了钱包用户关心的额外信息。
 * 它包括将交易链接回区块链所需的任何未记录交易。
 */
class CWalletTx : public CMerkleTx {
public:
  vector<CMerkleTx> vtxPrev;           // 交易的前置交易列表
  map<string, string> mapValue;        // 键值对形式的交易额外信息
  vector<pair<string, string>> vOrderForm; // 订单表单数据
  unsigned int fTimeReceivedIsTxTime;  // 接收时间是否为交易时间的标志
  unsigned int nTimeReceived;          // 该节点接收到交易的时间
  char fFromMe;                        // 是否是由当前钱包发出的交易
  char fSpent;                         // 交易是否已被花费
  string strFromAccount;               // 发起交易的账户名称

  // memory only
  mutable char fDebitCached;    // 支出金额缓存标志
  mutable char fCreditCached;   // 收入金额缓存标志
  mutable char fChangeCached;   // 找零金额缓存标志
  mutable int64 nDebitCached;   // 缓存的支出金额
  mutable int64 nCreditCached;  // 缓存的收入金额
  mutable int64 nChangeCached;  // 缓存的找零金额

  // memory only UI hints
  mutable unsigned int nTimeDisplayed;   // 上次显示的时间
  mutable int nLinesDisplayed;           // 显示的行数
  mutable char fConfirmedDisplayed;      // 确认状态显示标志

  /**
   * 默认构造函数
   */
  CWalletTx() { Init(); }

  /**
   * 从CMerkleTx构造CWalletTx
   * @param txIn 原始Merkle交易对象
   */
  CWalletTx(const CMerkleTx &txIn) : CMerkleTx(txIn) { Init(); }

  /**
   * 从CTransaction构造CWalletTx
   * @param txIn 原始交易对象
   */
  CWalletTx(const CTransaction &txIn) : CMerkleTx(txIn) { Init(); }

  /**
   * 初始化CWalletTx对象
   */
  void Init() {
    vtxPrev.clear();
    mapValue.clear();
    vOrderForm.clear();
    fTimeReceivedIsTxTime = false;
    nTimeReceived = 0;
    fFromMe = false;
    fSpent = false;
    strFromAccount.clear();
    fDebitCached = false;
    fCreditCached = false;
    fChangeCached = false;
    nDebitCached = 0;
    nCreditCached = 0;
    nChangeCached = 0;
    nTimeDisplayed = 0;
    nLinesDisplayed = 0;
    fConfirmedDisplayed = false;
  }

  /**
   * 序列化/反序列化方法
   */
  IMPLEMENT_SERIALIZE(CWalletTx *pthis = const_cast<CWalletTx *>(this);
                      if (fRead) pthis->Init();
                      nSerSize += SerReadWrite(s, *(CMerkleTx *)this, nType,
                                               nVersion, ser_action);
                      READWRITE(vtxPrev);

                      pthis->mapValue["fromaccount"] = pthis->strFromAccount;
                      READWRITE(mapValue);
                      pthis->strFromAccount = pthis->mapValue["fromaccount"];
                      pthis->mapValue.erase("fromaccount");
                      pthis->mapValue.erase("version");

                      READWRITE(vOrderForm); READWRITE(fTimeReceivedIsTxTime);
                      READWRITE(nTimeReceived); READWRITE(fFromMe);
                      READWRITE(fSpent);)

  /**
   * 获取交易的支出金额
   * @return 支出金额（以聪为单位）
   */
  int64 GetDebit() const {
    if (vin.empty())
      return 0;
    if (fDebitCached)
      return nDebitCached;
    nDebitCached = CTransaction::GetDebit();
    fDebitCached = true;
    return nDebitCached;
  }

  /**
   * 获取交易的收入金额
   * @param fUseCache 是否使用缓存值
   * @return 收入金额（以聪为单位）
   */
  int64 GetCredit(bool fUseCache = true) const {
    // Must wait until coinbase is safely deep enough in the chain before
    // valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
      return 0;

    // GetBalance can assume transactions in mapWallet won't change
    if (fUseCache && fCreditCached)
      return nCreditCached;
    nCreditCached = CTransaction::GetCredit();
    fCreditCached = true;
    return nCreditCached;
  }

  /**
   * 获取交易的找零金额
   * @return 找零金额（以聪为单位）
   */
  int64 GetChange() const {
    if (fChangeCached)
      return nChangeCached;
    nChangeCached = CTransaction::GetChange();
    fChangeCached = true;
    return nChangeCached;
  }

  /**
   * 获取账户相关的金额统计
   * @param strAccount 账户名称
   * @param setPubKey 公钥集合
   * @param nGenerated 生成的比特币数量（挖矿奖励）
   * @param nReceived 收到的比特币数量
   * @param nSent 发送的比特币数量
   * @param nFee 交易手续费
   */
  void GetAccountAmounts(string strAccount, const set<CScript> &setPubKey,
                         int64 &nGenerated, int64 &nReceived, int64 &nSent,
                         int64 &nFee) const {
    nGenerated = nReceived = nSent = nFee = 0;

    // Generated blocks count to account ""
    if (IsCoinBase()) {
      if (strAccount == "" && GetBlocksToMaturity() == 0)
        nGenerated = GetCredit();
      return;
    }

    // Received
    foreach (const CTxOut &txout, vout)
      if (setPubKey.count(txout.scriptPubKey))
        nReceived += txout.nValue;

    // Sent
    if (strFromAccount == strAccount) {
      int64 nDebit = GetDebit();
      if (nDebit > 0) {
        int64 nValueOut = GetValueOut();
        nFee = nDebit - nValueOut;
        nSent = nValueOut - GetChange();
      }
    }
  }

  /**
   * 检查交易是否由当前钱包发出
   * @return 如果是由当前钱包发出则返回true，否则返回false
   */
  bool IsFromMe() const { return (GetDebit() > 0); }

  /**
   * 检查交易是否已确认
   * 
   * 对于来自自身的交易，如果没有确认但所有依赖都已确认，也会被视为已确认。
   * @return 如果交易已确认则返回true，否则返回false
   */
  bool IsConfirmed() const {
    // Quick answer in most cases
    if (!IsFinal())
      return false;
    if (GetDepthInMainChain() >= 1)
      return true;
    if (!IsFromMe()) // using wtx's cached debit
      return false;

    // If no confirmations but it's from us, we can still
    // consider it confirmed if all dependencies are confirmed
    map<uint256, const CMerkleTx *> mapPrev;
    vector<const CMerkleTx *> vWorkQueue;
    vWorkQueue.reserve(vtxPrev.size() + 1);
    vWorkQueue.push_back(this);
    for (int i = 0; i < vWorkQueue.size(); i++) {
      const CMerkleTx *ptx = vWorkQueue[i];

      if (!ptx->IsFinal())
        return false;
      if (ptx->GetDepthInMainChain() >= 1)
        return true;
      if (!ptx->IsFromMe())
        return false;

      if (mapPrev.empty())
        foreach (const CMerkleTx &tx, vtxPrev)
          mapPrev[tx.GetHash()] = &tx;

      foreach (const CTxIn &txin, ptx->vin) {
        if (!mapPrev.count(txin.prevout.hash))
          return false;
        vWorkQueue.push_back(mapPrev[txin.prevout.hash]);
      }
    }
    return true;
  }

  /**
   * 将钱包交易写入磁盘
   * @return 写入成功则返回true，否则返回false
   */
  bool WriteToDisk() { return CWalletDB().WriteTx(GetHash(), *this); }

  /**
   * 获取交易时间
   * @return 交易时间戳
   */
  int64 GetTxTime() const;
  /**
   * 获取请求计数
   * @return 请求计数
   */
  int GetRequestCount() const;

  /**
   * 添加支持性交易
   * @param txdb 交易数据库
   */
  void AddSupportingTransactions(CTxDB &txdb);

  /**
   * 接受钱包交易
   * @param txdb 交易数据库
   * @param fCheckInputs 是否检查输入
   * @return 接受成功则返回true，否则返回false
   */
  bool AcceptWalletTransaction(CTxDB &txdb, bool fCheckInputs = true);
  /**
   * 接受钱包交易（重载版本）
   * @return 接受成功则返回true，否则返回false
   */
  bool AcceptWalletTransaction() {
    CTxDB txdb("r");
    return AcceptWalletTransaction(txdb);
  }

  /**
   * 中继钱包交易（广播到网络）
   * @param txdb 交易数据库
   */
  void RelayWalletTransaction(CTxDB &txdb);
  /**
   * 中继钱包交易（重载版本）
   */
  void RelayWalletTransaction() {
    CTxDB txdb("r");
    RelayWalletTransaction(txdb);
  }
};

/**
 * 交易索引类
 * 
 * 包含交易在磁盘上的位置以及花费其输出的交易的位置记录。
 * vSpent主要用作标志，但记录位置对于调试非常有帮助。
 */
class CTxIndex {
public:
  CDiskTxPos pos;             // 交易在磁盘上的位置
  vector<CDiskTxPos> vSpent;  // 花费该交易输出的交易的磁盘位置列表

  /**
   * 默认构造函数
   */
  CTxIndex() { SetNull(); }

  /**
   * 带参数的构造函数
   * @param posIn 交易在磁盘上的位置
   * @param nOutputs 交易输出的数量
   */
  CTxIndex(const CDiskTxPos &posIn, unsigned int nOutputs) {
    pos = posIn;
    vSpent.resize(nOutputs);
  }

  /**
   * 序列化/反序列化方法
   */
  IMPLEMENT_SERIALIZE(if (!(nType & SER_GETHASH)) READWRITE(nVersion);
                      READWRITE(pos); READWRITE(vSpent);)

  /**
   * 将交易索引设置为空状态
   */
  void SetNull() {
    pos.SetNull();
    vSpent.clear();
  }

  /**
   * 检查交易索引是否为空
   * @return 如果交易索引为空则返回true，否则返回false
   */
  bool IsNull() { return pos.IsNull(); }

  /**
   * 相等运算符重载
   * @param a 第一个交易索引
   * @param b 第二个交易索引
   * @return 如果两个交易索引相等则返回true，否则返回false
   */
  friend bool operator==(const CTxIndex &a, const CTxIndex &b) {
    return (a.pos == b.pos && a.vSpent == b.vSpent);
  }

  /**
   * 不相等运算符重载
   * @param a 第一个交易索引
   * @param b 第二个交易索引
   * @return 如果两个交易索引不相等则返回true，否则返回false
   */
  friend bool operator!=(const CTxIndex &a, const CTxIndex &b) {
    return !(a == b);
  }
};

/**
 * 区块类
 * 
 * 节点将新交易收集到区块中，将它们哈希到哈希树中，并扫描nonce值使区块哈希满足工作量证明要求。
 * 当它们解决了工作量证明后，会将区块广播给所有人，然后区块被添加到区块链中。
 * 区块中的第一笔交易是特殊的，它会创建一个新的比特币，归区块创建者所有。
 * 
 * 区块被追加到磁盘上的blk0001.dat文件中。它们在磁盘上的位置由内存中的CBlockIndex对象索引。
 */
class CBlock {
public:
  // header
  int nVersion;            // 区块版本号
  uint256 hashPrevBlock;   // 前一个区块的哈希值
  uint256 hashMerkleRoot;  // 交易默克尔树根的哈希值
  unsigned int nTime;      // 区块创建时间戳
  unsigned int nBits;      // 区块难度目标
  unsigned int nNonce;     // 工作量证明的随机数

  // network and disk
  vector<CTransaction> vtx;  // 区块中包含的交易列表

  // memory only
  mutable vector<uint256> vMerkleTree;  // 默克尔树（仅内存中使用）

  /**
   * 默认构造函数
   */
  CBlock() { SetNull(); }

  /**
   * 序列化/反序列化方法
   */
  IMPLEMENT_SERIALIZE(
      READWRITE(this->nVersion); nVersion = this->nVersion;
      READWRITE(hashPrevBlock); READWRITE(hashMerkleRoot); READWRITE(nTime);
      READWRITE(nBits); READWRITE(nNonce);

      // ConnectBlock depends on vtx being last so it can calculate offset
      if (!(nType & (SER_GETHASH | SER_BLOCKHEADERONLY))) READWRITE(vtx);
      else if (fRead) const_cast<CBlock *>(this)->vtx.clear();)

  /**
   * 将区块设置为空状态
   */
  void SetNull() {
    nVersion = 1;
    hashPrevBlock = 0;
    hashMerkleRoot = 0;
    nTime = 0;
    nBits = 0;
    nNonce = 0;
    vtx.clear();
    vMerkleTree.clear();
  }

  /**
   * 检查区块是否为空
   * @return 如果区块为空则返回true，否则返回false
   */
  bool IsNull() const { return (nBits == 0); }

  /**
   * 获取区块的哈希值
   * @return 区块的哈希值
   */
  uint256 GetHash() const { return Hash(BEGIN(nVersion), END(nNonce)); }

  /**
   * 获取区块时间
   * @return 区块创建时间戳
   */
  int64 GetBlockTime() const { return (int64)nTime; }

  /**
   * 获取区块中签名操作的总数
   * @return 签名操作的总数
   */
  int GetSigOpCount() const {
    int n = 0;
    foreach (const CTransaction &tx, vtx)
      n += tx.GetSigOpCount();
    return n;
  }

  /**
   * 构建默克尔树
   * @return 默克尔树根的哈希值
   */
  uint256 BuildMerkleTree() const {
    vMerkleTree.clear();
    foreach (const CTransaction &tx, vtx)
      vMerkleTree.push_back(tx.GetHash());
    int j = 0;
    for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2) {
      for (int i = 0; i < nSize; i += 2) {
        int i2 = min(i + 1, nSize - 1);
        vMerkleTree.push_back(
            Hash(BEGIN(vMerkleTree[j + i]), END(vMerkleTree[j + i]),
                 BEGIN(vMerkleTree[j + i2]), END(vMerkleTree[j + i2])));
      }
      j += nSize;
    }
    return (vMerkleTree.empty() ? 0 : vMerkleTree.back());
  }

  /**
   * 获取默克尔分支
   * 
   * 默克尔分支用于证明特定交易包含在区块中，而无需提供完整的区块内容。
   * @param nIndex 交易在区块中的索引位置
   * @return 默克尔分支（包含证明所需的哈希值列表）
   */
  vector<uint256> GetMerkleBranch(int nIndex) const {
    if (vMerkleTree.empty())
      BuildMerkleTree();
    vector<uint256> vMerkleBranch;
    int j = 0;
    for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2) {
      int i = min(nIndex ^ 1, nSize - 1);
      vMerkleBranch.push_back(vMerkleTree[j + i]);
      nIndex >>= 1;
      j += nSize;
    }
    return vMerkleBranch;
  }

  /**
   * 检查默克尔分支是否有效
   * 
   * 使用给定的哈希和默克尔分支计算默克尔树根，用于验证交易是否包含在区块中。
   * @param hash 交易的哈希值
   * @param vMerkleBranch 默克尔分支
   * @param nIndex 交易在区块中的索引位置
   * @return 计算得到的默克尔树根哈希值
   */
  static uint256 CheckMerkleBranch(uint256 hash,
                                   const vector<uint256> &vMerkleBranch,
                                   int nIndex) {
    if (nIndex == -1)
      return 0;
    foreach (const uint256 &otherside, vMerkleBranch) {
      if (nIndex & 1)
        hash = Hash(BEGIN(otherside), END(otherside), BEGIN(hash), END(hash));
      else
        hash = Hash(BEGIN(hash), END(hash), BEGIN(otherside), END(otherside));
      nIndex >>= 1;
    }
    return hash;
  }

  /**
   * 将区块写入磁盘
   * 
   * 打开区块文件并将区块数据追加到文件末尾。
   * @param nFileRet 返回区块文件的编号
   * @param nBlockPosRet 返回区块在文件中的位置
   * @return 写入成功则返回true，否则返回false
   */
  bool WriteToDisk(unsigned int &nFileRet, unsigned int &nBlockPosRet) {
    // Open history file to append
    CAutoFile fileout = AppendBlockFile(nFileRet);
    if (!fileout)
      return error("CBlock::WriteToDisk() : AppendBlockFile failed");

    // Write index header
    unsigned int nSize = fileout.GetSerializeSize(*this);
    fileout << FLATDATA(pchMessageStart) << nSize;

    // Write block
    nBlockPosRet = ftell(fileout);
    if (nBlockPosRet == -1)
      return error("CBlock::WriteToDisk() : ftell failed");
    fileout << *this;

    // Flush stdio buffers and commit to disk before returning
    fflush(fileout);
    if (!IsInitialBlockDownload() || (nBestHeight + 1) % 500 == 0) {
#ifdef __WXMSW__
      _commit(_fileno(fileout));
#else
      fsync(fileno(fileout));
#endif
    }

    return true;
  }

  /**
   * 从磁盘读取区块
   * 
   * 打开指定的区块文件并读取区块数据。
   * @param nFile 区块文件的编号
   * @param nBlockPos 区块在文件中的位置
   * @param fReadTransactions 是否读取交易数据（默认为true）
   * @return 读取成功则返回true，否则返回false
   */
  bool ReadFromDisk(unsigned int nFile, unsigned int nBlockPos,
                    bool fReadTransactions = true) {
    SetNull();

    // Open history file to read
    CAutoFile filein = OpenBlockFile(nFile, nBlockPos, "rb");
    if (!filein)
      return error("CBlock::ReadFromDisk() : OpenBlockFile failed");
    if (!fReadTransactions)
      filein.nType |= SER_BLOCKHEADERONLY;

    // Read block
    filein >> *this;

    // Check the header
    if (!CheckProofOfWork(GetHash(), nBits))
      return error("CBlock::ReadFromDisk() : errors in block header");

    return true;
  }

  /**
   * 打印区块信息
   * 
   * 输出区块的基本信息，包括哈希值、版本、前区块哈希、默克尔树根、时间戳、难度目标、随机数等，以及区块中的所有交易信息。
   */
  void print() const {
    printf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, "
           "nTime=%u, nBits=%08x, nNonce=%u, vtx=%d)\n",
           GetHash().ToString().substr(0, 20).c_str(), nVersion,
           hashPrevBlock.ToString().substr(0, 20).c_str(),
           hashMerkleRoot.ToString().substr(0, 10).c_str(), nTime, nBits,
           nNonce, vtx.size());
    for (int i = 0; i < vtx.size(); i++) {
      printf("  ");
      vtx[i].print();
    }
    printf("  vMerkleTree: ");
    for (int i = 0; i < vMerkleTree.size(); i++)
      printf("%s ", vMerkleTree[i].ToString().substr(0, 10).c_str());
    printf("\n");
  }

  /**
   * 断开区块连接
   * 
   * 将区块从当前区块链中移除，回滚所有交易效果。
   * @param txdb 交易数据库对象
   * @param pindex 区块索引指针
   * @return 断开成功则返回true，否则返回false
   */
  bool DisconnectBlock(CTxDB &txdb, CBlockIndex *pindex);
  
  /**
   * 连接区块
   * 
   * 将区块添加到当前区块链中，应用所有交易效果。
   * @param txdb 交易数据库对象
   * @param pindex 区块索引指针
   * @return 连接成功则返回true，否则返回false
   */
  bool ConnectBlock(CTxDB &txdb, CBlockIndex *pindex);
  
  /**
   * 从磁盘读取区块（通过区块索引）
   * 
   * 使用区块索引从磁盘读取区块数据。
   * @param pindex 区块索引指针
   * @param fReadTransactions 是否读取交易数据（默认为true）
   * @return 读取成功则返回true，否则返回false
   */
  bool ReadFromDisk(const CBlockIndex *pindex, bool fReadTransactions = true);
  
  /**
   * 设置最佳链
   * 
   * 将给定的区块索引设置为最佳链的末端。
   * @param txdb 交易数据库对象
   * @param pindexNew 新的最佳链末端区块索引
   * @return 设置成功则返回true，否则返回false
   */
  bool SetBestChain(CTxDB &txdb, CBlockIndex *pindexNew);
  
  /**
   * 添加到区块索引
   * 
   * 将区块添加到区块索引中。
   * @param nFile 区块文件的编号
   * @param nBlockPos 区块在文件中的位置
   * @return 添加成功则返回true，否则返回false
   */
  bool AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos);
  
  /**
   * 检查区块
   * 
   * 检查区块是否符合所有规则（除工作量证明外）。
   * @return 检查通过则返回true，否则返回false
   */
  bool CheckBlock() const;
  
  /**
   * 接受区块
   * 
   * 接受区块到内存中，准备添加到区块链。
   * @return 接受成功则返回true，否则返回false
   */
  bool AcceptBlock();
};

/**
 * 区块索引类
 * 
 * 区块链是一个树形结构，从创世区块开始，每个区块可能有多个候选区块作为下一个区块。
 * pprev和pnext链接了主链/最长链的路径。一个区块索引可能有多个pprev指向它，
 * 但pnext只会指向前方的最长分支，如果区块不属于最长链，则pnext为null。
 */
class CBlockIndex {
public:
  const uint256 *phashBlock;  // 区块哈希指针
  CBlockIndex *pprev;         // 前一个区块索引指针
  CBlockIndex *pnext;         // 下一个区块索引指针（主链）
  unsigned int nFile;         // 区块文件编号
  unsigned int nBlockPos;     // 区块在文件中的位置
  int nHeight;                // 区块高度（从创世区块开始计数）
  CBigNum bnChainWork;        // 链工作量（从创世区块到当前区块的总工作量）

  // block header
  int nVersion;               // 区块版本号
  uint256 hashMerkleRoot;     // 交易默克尔树根哈希
  unsigned int nTime;         // 区块创建时间戳
  unsigned int nBits;         // 区块难度目标
  unsigned int nNonce;        // 工作量证明随机数

  /**
   * 默认构造函数
   */
  CBlockIndex() {
    phashBlock = NULL;
    pprev = NULL;
    pnext = NULL;
    nFile = 0;
    nBlockPos = 0;
    nHeight = 0;
    bnChainWork = 0;

    nVersion = 0;
    hashMerkleRoot = 0;
    nTime = 0;
    nBits = 0;
    nNonce = 0;
  }

  /**
   * 带参数的构造函数
   * 
   * @param nFileIn 区块文件编号
   * @param nBlockPosIn 区块在文件中的位置
   * @param block 区块对象
   */
  CBlockIndex(unsigned int nFileIn, unsigned int nBlockPosIn, CBlock &block) {
    phashBlock = NULL;
    pprev = NULL;
    pnext = NULL;
    nFile = nFileIn;
    nBlockPos = nBlockPosIn;
    nHeight = 0;
    bnChainWork = 0;

    nVersion = block.nVersion;
    hashMerkleRoot = block.hashMerkleRoot;
    nTime = block.nTime;
    nBits = block.nBits;
    nNonce = block.nNonce;
  }

  /**
   * 获取区块头
   * 
   * 从区块索引信息中构建并返回区块头对象。
   * @return 区块头对象
   */
  CBlock GetBlockHeader() const {
    CBlock block;
    block.nVersion = nVersion;
    if (pprev)
      block.hashPrevBlock = pprev->GetBlockHash();
    block.hashMerkleRoot = hashMerkleRoot;
    block.nTime = nTime;
    block.nBits = nBits;
    block.nNonce = nNonce;
    return block;
  }

  /**
   * 获取区块哈希
   * @return 区块哈希值
   */
  uint256 GetBlockHash() const { return *phashBlock; }

  /**
   * 获取区块时间
   * @return 区块创建时间戳
   */
  int64 GetBlockTime() const { return (int64)nTime; }

  /**
   * 获取区块工作量
   * 
   * 计算区块的工作量，基于区块的难度目标。
   * @return 区块工作量
   */
  CBigNum GetBlockWork() const {
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);
    if (bnTarget <= 0)
      return 0;
    return (CBigNum(1) << 256) / (bnTarget + 1);
  }

  /**
   * 检查是否在主链中
   * 
   * 判断当前区块索引是否属于最长链（主链）。
   * @return 如果在主链中则返回true，否则返回false
   */
  bool IsInMainChain() const { return (pnext || this == pindexBest); }

  /**
   * 检查区块索引
   * 
   * 验证区块的工作量证明是否有效。
   * @return 如果工作量证明有效则返回true，否则返回false
   */
  bool CheckIndex() const { return CheckProofOfWork(GetBlockHash(), nBits); }

  /**
   * 从磁盘中删除区块
   * 
   * 用空块覆盖磁盘上的区块数据。
   * @return 删除成功则返回true，否则返回false
   */
  bool EraseBlockFromDisk() {
    // Open history file
    CAutoFile fileout = OpenBlockFile(nFile, nBlockPos, "rb+");
    if (!fileout)
      return false;

    // Overwrite with empty null block
    CBlock block;
    block.SetNull();
    fileout << block;

    return true;
  }

  enum { nMedianTimeSpan = 11 };  // 计算中位数时间的区块数量

  /**
   * 获取过去区块时间的中位数
   * 
   * 计算过去11个区块（包括当前区块）的时间戳中位数。
   * 用于确定区块时间戳的有效性，防止时间戳被恶意设置得过大。
   * @return 过去区块时间的中位数
   */
  int64 GetMedianTimePast() const {
    int64 pmedian[nMedianTimeSpan];
    int64 *pbegin = &pmedian[nMedianTimeSpan];
    int64 *pend = &pmedian[nMedianTimeSpan];

    const CBlockIndex *pindex = this;
    for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
      *(--pbegin) = pindex->GetBlockTime();

    sort(pbegin, pend);
    return pbegin[(pend - pbegin) / 2];
  }

  /**
   * 获取当前区块的中位数时间
   * 
   * 计算当前区块的中位数时间，可能用于确定区块的有效性。
   * @return 当前区块的中位数时间
   */
  int64 GetMedianTime() const {
    const CBlockIndex *pindex = this;
    for (int i = 0; i < nMedianTimeSpan / 2; i++) {
      if (!pindex->pnext)
        return GetBlockTime();
      pindex = pindex->pnext;
    }
    return pindex->GetMedianTimePast();
  }

  /**
   * 转换为字符串表示
   * 
   * 将区块索引信息转换为可读的字符串格式。
   * @return 区块索引的字符串表示
   */
  string ToString() const {
    return strprintf("CBlockIndex(nprev=%08x, pnext=%08x, nFile=%d, "
                     "nBlockPos=%-6d nHeight=%d, merkle=%s, hashBlock=%s)",
                     pprev, pnext, nFile, nBlockPos, nHeight,
                     hashMerkleRoot.ToString().substr(0, 10).c_str(),
                     GetBlockHash().ToString().substr(0, 20).c_str());
  }

  /**
   * 打印区块索引信息
   * 
   * 将区块索引信息输出到控制台。
   */
  void print() const { printf("%s\n", ToString().c_str()); }
};

/**
 * 磁盘区块索引类
 * 
 * 用于将指针转换为哈希值以便在数据库中存储。
 * 继承自CBlockIndex类，添加了用于磁盘存储的哈希字段。
 */
class CDiskBlockIndex : public CBlockIndex {
public:
  uint256 hashPrev;  // 前一个区块的哈希值
  uint256 hashNext;  // 下一个区块的哈希值

  /**
   * 默认构造函数
   */
  CDiskBlockIndex() {
    hashPrev = 0;
    hashNext = 0;
  }

  /**
   * 带参数的构造函数
   * 
   * @param pindex 区块索引指针
   */
  explicit CDiskBlockIndex(CBlockIndex *pindex) : CBlockIndex(*pindex) {
    hashPrev = (pprev ? pprev->GetBlockHash() : 0);
    hashNext = (pnext ? pnext->GetBlockHash() : 0);
  }

  /**
   * 序列化/反序列化方法
   */
  IMPLEMENT_SERIALIZE(if (!(nType & SER_GETHASH)) READWRITE(nVersion);

                      READWRITE(hashNext); READWRITE(nFile);
                      READWRITE(nBlockPos); READWRITE(nHeight);

                      // block header
                      READWRITE(this->nVersion); READWRITE(hashPrev);
                      READWRITE(hashMerkleRoot); READWRITE(nTime);
                      READWRITE(nBits); READWRITE(nNonce);)

  /**
   * 获取区块哈希
   * 
   * 从磁盘存储的区块头信息计算区块哈希。
   * @return 区块哈希值
   */
  uint256 GetBlockHash() const {
    CBlock block;
    block.nVersion = nVersion;
    block.hashPrevBlock = hashPrev;
    block.hashMerkleRoot = hashMerkleRoot;
    block.nTime = nTime;
    block.nBits = nBits;
    block.nNonce = nNonce;
    return block.GetHash();
  }

  /**
   * 转换为字符串表示
   * 
   * 将磁盘区块索引信息转换为可读的字符串格式。
   * @return 磁盘区块索引的字符串表示
   */
  string ToString() const {
    string str = "CDiskBlockIndex(";
    str += CBlockIndex::ToString();
    str +=
        strprintf("\n                hashBlock=%s, hashPrev=%s, hashNext=%s)",
                  GetBlockHash().ToString().c_str(),
                  hashPrev.ToString().substr(0, 20).c_str(),
                  hashNext.ToString().substr(0, 20).c_str());
    return str;
  }

  /**
   * 打印磁盘区块索引信息
   * 
   * 将磁盘区块索引信息输出到控制台。
   */
  void print() const { printf("%s\n", ToString().c_str()); }
};

//
// Describes a place in the block chain to another node such that if the
// other node doesn't have the same branch, it can find a recent common trunk.
// The further back it is, the further before the fork it may be.
//
class CBlockLocator {
protected:
  vector<uint256> vHave;

public:
  CBlockLocator() {}

  explicit CBlockLocator(const CBlockIndex *pindex) { Set(pindex); }

  explicit CBlockLocator(uint256 hashBlock) {
    map<uint256, CBlockIndex *>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi != mapBlockIndex.end())
      Set((*mi).second);
  }

  IMPLEMENT_SERIALIZE(if (!(nType & SER_GETHASH)) READWRITE(nVersion);
                      READWRITE(vHave);)

  void SetNull() { vHave.clear(); }

  bool IsNull() { return vHave.empty(); }

  void Set(const CBlockIndex *pindex) {
    vHave.clear();
    int nStep = 1;
    while (pindex) {
      vHave.push_back(pindex->GetBlockHash());

      // Exponentially larger steps back
      for (int i = 0; pindex && i < nStep; i++)
        pindex = pindex->pprev;
      if (vHave.size() > 10)
        nStep *= 2;
    }
    vHave.push_back(hashGenesisBlock);
  }

  int GetDistanceBack() {
    // Retrace how far back it was in the sender's branch
    int nDistance = 0;
    int nStep = 1;
    foreach (const uint256 &hash, vHave) {
      map<uint256, CBlockIndex *>::iterator mi = mapBlockIndex.find(hash);
      if (mi != mapBlockIndex.end()) {
        CBlockIndex *pindex = (*mi).second;
        if (pindex->IsInMainChain())
          return nDistance;
      }
      nDistance += nStep;
      if (nDistance > 10)
        nStep *= 2;
    }
    return nDistance;
  }

  CBlockIndex *GetBlockIndex() {
    // Find the first block the caller has in the main chain
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

  uint256 GetBlockHash() {
    // Find the first block the caller has in the main chain
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

  int GetHeight() {
    CBlockIndex *pindex = GetBlockIndex();
    if (!pindex)
      return 0;
    return pindex->nHeight;
  }
};

//
// Private key that includes an expiration date in case it never gets used.
//
class CWalletKey {
public:
  CPrivKey vchPrivKey;
  int64 nTimeCreated;
  int64 nTimeExpires;
  string strComment;
  //// todo: add something to note what created it (user, getnewaddress, change)
  ////   maybe should have a map<string, string> property map

  CWalletKey(int64 nExpires = 0) {
    nTimeCreated = (nExpires ? GetTime() : 0);
    nTimeExpires = nExpires;
  }

  IMPLEMENT_SERIALIZE(if (!(nType & SER_GETHASH)) READWRITE(nVersion);
                      READWRITE(vchPrivKey); READWRITE(nTimeCreated);
                      READWRITE(nTimeExpires); READWRITE(strComment);)
};

//
// Account information.
// Stored in wallet with key "acc"+string account name
//
class CAccount {
public:
  vector<unsigned char> vchPubKey;

  CAccount() { SetNull(); }

  void SetNull() { vchPubKey.clear(); }

  IMPLEMENT_SERIALIZE(if (!(nType & SER_GETHASH)) READWRITE(nVersion);
                      READWRITE(vchPubKey);)
};

//
// Internal transfers.
// Database key is acentry<account><counter>
//
class CAccountingEntry {
public:
  int64 nCreditDebit;
  int64 nTime;
  string strOtherAccount;
  string strComment;

  CAccountingEntry() { SetNull(); }

  void SetNull() {
    nCreditDebit = 0;
    nTime = 0;
    strOtherAccount.clear();
    strComment.clear();
  }

  IMPLEMENT_SERIALIZE(if (!(nType & SER_GETHASH)) READWRITE(nVersion);
                      READWRITE(nCreditDebit); READWRITE(nTime);
                      READWRITE(strOtherAccount); READWRITE(strComment);)
};

//
// Alert messages are broadcast as a vector of signed data.  Unserializing may
// not read the entire buffer if the alert is for a newer version, but older
// versions can still relay the original data.
//
class CUnsignedAlert {
public:
  int nVersion;
  int64 nRelayUntil; // when newer nodes stop relaying to newer nodes
  int64 nExpiration;
  int nID;
  int nCancel;
  set<int> setCancel;
  int nMinVer;           // lowest version inclusive
  int nMaxVer;           // highest version inclusive
  set<string> setSubVer; // empty matches all
  int nPriority;

  // Actions
  string strComment;
  string strStatusBar;
  string strReserved;

  IMPLEMENT_SERIALIZE(READWRITE(this->nVersion); nVersion = this->nVersion;
                      READWRITE(nRelayUntil); READWRITE(nExpiration);
                      READWRITE(nID); READWRITE(nCancel); READWRITE(setCancel);
                      READWRITE(nMinVer); READWRITE(nMaxVer);
                      READWRITE(setSubVer); READWRITE(nPriority);

                      READWRITE(strComment); READWRITE(strStatusBar);
                      READWRITE(strReserved);)

  void SetNull() {
    nVersion = 1;
    nRelayUntil = 0;
    nExpiration = 0;
    nID = 0;
    nCancel = 0;
    setCancel.clear();
    nMinVer = 0;
    nMaxVer = 0;
    setSubVer.clear();
    nPriority = 0;

    strComment.clear();
    strStatusBar.clear();
    strReserved.clear();
  }

  string ToString() const {
    string strSetCancel;
    foreach (int n, setCancel)
      strSetCancel += strprintf("%d ", n);
    string strSetSubVer;
    foreach (string str, setSubVer)
      strSetSubVer += "\"" + str + "\" ";
    return strprintf("CAlert(\n"
                     "    nVersion     = %d\n"
                     "    nRelayUntil  = %" PRI64d "\n"
                     "    nExpiration  = %" PRI64d "\n"
                     "    nID          = %d\n"
                     "    nCancel      = %d\n"
                     "    setCancel    = %s\n"
                     "    nMinVer      = %d\n"
                     "    nMaxVer      = %d\n"
                     "    setSubVer    = %s\n"
                     "    nPriority    = %d\n"
                     "    strComment   = \"%s\"\n"
                     "    strStatusBar = \"%s\"\n"
                     ")\n",
                     nVersion, nRelayUntil, nExpiration, nID, nCancel,
                     strSetCancel.c_str(), nMinVer, nMaxVer,
                     strSetSubVer.c_str(), nPriority, strComment.c_str(),
                     strStatusBar.c_str());
  }

  void print() const { printf("%s", ToString().c_str()); }
};

class CAlert : public CUnsignedAlert {
public:
  vector<unsigned char> vchMsg;
  vector<unsigned char> vchSig;

  CAlert() { SetNull(); }

  IMPLEMENT_SERIALIZE(READWRITE(vchMsg); READWRITE(vchSig);)

  void SetNull() {
    CUnsignedAlert::SetNull();
    vchMsg.clear();
    vchSig.clear();
  }

  bool IsNull() const { return (nExpiration == 0); }

  uint256 GetHash() const { return SerializeHash(*this); }

  bool IsInEffect() const { return (GetAdjustedTime() < nExpiration); }

  bool Cancels(const CAlert &alert) const {
    if (!IsInEffect())
      return false; // this was a no-op before 31403
    return (alert.nID <= nCancel || setCancel.count(alert.nID));
  }

  bool AppliesTo(int nVersion, string strSubVerIn) const {
    return (IsInEffect() && nMinVer <= nVersion && nVersion <= nMaxVer &&
            (setSubVer.empty() || setSubVer.count(strSubVerIn)));
  }

  bool AppliesToMe() const { return AppliesTo(VERSION, ::pszSubVer); }

  bool RelayTo(CNode *pnode) const {
    if (!IsInEffect())
      return false;
    // returns true if wasn't already contained in the set
    if (pnode->setKnown.insert(GetHash()).second) {
      if (AppliesTo(pnode->nVersion, pnode->strSubVer) || AppliesToMe() ||
          GetAdjustedTime() < nRelayUntil) {
        pnode->PushMessage("alert", *this);
        return true;
      }
    }
    return false;
  }

  bool CheckSignature() {
    CKey key;
    if (!key.SetPubKey(ParseHex("04fc9702847840aaf195de8442ebecedf5b095cdbb9bc7"
                                "16bda9110971b28a49e0ead8564ff0db22209e0374782c"
                                "093bb899692d524e9d6a6956e7c5ecbcd68284")))
      return error("CAlert::CheckSignature() : SetPubKey failed");
    if (!key.Verify(Hash(vchMsg.begin(), vchMsg.end()), vchSig))
      return error("CAlert::CheckSignature() : verify signature failed");

    // Now unserialize the data
    CDataStream sMsg(vchMsg);
    sMsg >> *(CUnsignedAlert *)this;
    return true;
  }

  bool ProcessAlert();
};

extern map<uint256, CTransaction> mapTransactions;
extern map<uint256, CWalletTx> mapWallet;
extern vector<uint256> vWalletUpdated;
extern CCriticalSection cs_mapWallet;
extern map<vector<unsigned char>, CPrivKey> mapKeys;
extern map<uint160, vector<unsigned char>> mapPubKeys;
extern CCriticalSection cs_mapKeys;
extern CKey keyUser;
