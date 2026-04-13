// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

class COutPoint;
class CInPoint;
class CDiskTxPos;
class CCoinBase;
class CTxIn;
class CTxOut;
class CTransaction;
class CBlock class CBlockIndex;
class CWalletTx;
class CKeyItem;

static const unsigned int MAX_SIZE = 0x02000000;
static const int64 COIN = 100000000;
static const int64 CENT = 1000000;
static const int COINBASE_MATURITY = 100;

static const CBigNum bnProofOfWorkLimit(~uint256(0) >> 32);

extern CCriticalSection cs_main;
extern map<uint256, CBlockIndex *> mapBlockIndex;
extern const uint256 hashGenesisBlock;
extern CBlockIndex *pindexGenesisBlock;
extern int nBestHeight;
extern uint256 hashBestChain;
extern CBlockIndex *pindexBest;
extern unsigned int nTransactionsUpdated;
extern string strSetDataDir;
extern int nDropMessagesTest;

// Settings
extern int fGenerateBitcoins;
extern int64 nTransactionFee;
extern CAddress addrIncoming;

string GetAppDir();
FILE *OpenBlockFile(unsigned int nFile, unsigned int nBlockPos,
                    const char *pszMode = "rb");
FILE *AppendBlockFile(unsigned int &nFileRet);
bool AddKey(const CKey &key);
vector<unsigned char> GenerateNewKey();
bool AddToWallet(const CWalletTx &wtxIn);
void ReacceptWalletTransactions();
void RelayWalletTransactions();
bool LoadBlockIndex(bool fAllowNew = true);
void PrintBlockTree();
bool BitcoinMiner();
bool ProcessMessages(CNode *pfrom);
bool ProcessMessage(CNode *pfrom, string strCommand, CDataStream &vRecv);
bool SendMessages(CNode *pto);
int64 GetBalance();
bool CreateTransaction(CScript scriptPubKey, int64 nValue, CWalletTx &txNew,
                       int64 &nFeeRequiredRet);
bool CommitTransactionSpent(const CWalletTx &wtxNew);
bool SendMoney(CScript scriptPubKey, int64 nValue, CWalletTx &wtxNew);

class CDiskTxPos {
public:
  unsigned int nFile;
  unsigned int nBlockPos;
  unsigned int nTxPos;

  CDiskTxPos() { SetNull(); }

  CDiskTxPos(unsigned int nFileIn, unsigned int nBlockPosIn,
             unsigned int nTxPosIn) {
    nFile = nFileIn;
    nBlockPos = nBlockPosIn;
    nTxPos = nTxPosIn;
  }

  IMPLEMENT_SERIALIZE(READWRITE(FLATDATA(*this));)
  void SetNull() {
    nFile = -1;
    nBlockPos = 0;
    nTxPos = 0;
  }
  bool IsNull() const { return (nFile == -1); }

  friend bool operator==(const CDiskTxPos &a, const CDiskTxPos &b) {
    return (a.nFile == b.nFile && a.nBlockPos == b.nBlockPos &&
            a.nTxPos == b.nTxPos);
  }

  friend bool operator!=(const CDiskTxPos &a, const CDiskTxPos &b) {
    return !(a == b);
  }

  string ToString() const {
    if (IsNull())
      return strprintf("null");
    else
      return strprintf("(nFile=%d, nBlockPos=%d, nTxPos=%d)", nFile, nBlockPos,
                       nTxPos);
  }

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

class COutPoint {
public:
  uint256 hash;
  unsigned int n;

  COutPoint() { SetNull(); }
  COutPoint(uint256 hashIn, unsigned int nIn) {
    hash = hashIn;
    n = nIn;
  }
  IMPLEMENT_SERIALIZE(READWRITE(FLATDATA(*this));)
  void SetNull() {
    hash = 0;
    n = -1;
  }
  bool IsNull() const { return (hash == 0 && n == -1); }

  friend bool operator<(const COutPoint &a, const COutPoint &b) {
    return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
  }

  friend bool operator==(const COutPoint &a, const COutPoint &b) {
    return (a.hash == b.hash && a.n == b.n);
  }

  friend bool operator!=(const COutPoint &a, const COutPoint &b) {
    return !(a == b);
  }

  string ToString() const {
    return strprintf("COutPoint(%s, %d)", hash.ToString().substr(0, 6).c_str(),
                     n);
  }

  void print() const { printf("%s\n", ToString().c_str()); }
};

//
// An input of a transaction.  It contains the location of the previous
// transaction's output that it claims and a signature that matches the
// output's public key.
// 一笔交易的输入信息。
// 它包含了该交易所声称使用的前一笔交易输出的地址，以及与该输出公钥相匹配的签名。//
class CTxIn {
public:
  COutPoint prevout;
  CScript scriptSig;
  unsigned int nSequence;

  CTxIn() { nSequence = UINT_MAX; }

  explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn = CScript(),
                 unsigned int nSequenceIn = UINT_MAX) {
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
  }

  CTxIn(uint256 hashPrevTx, unsigned int nOut, CScript scriptSigIn = CScript(),
        unsigned int nSequenceIn = UINT_MAX) {
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
  }

  IMPLEMENT_SERIALIZE(READWRITE(prevout); READWRITE(scriptSig);
                      READWRITE(nSequence);)

  bool IsFinal() const { return (nSequence == UINT_MAX); }

  friend bool operator==(const CTxIn &a, const CTxIn &b) {
    return (a.prevout == b.prevout && a.scriptSig == b.scriptSig &&
            a.nSequence == b.nSequence);
  }

  friend bool operator!=(const CTxIn &a, const CTxIn &b) { return !(a == b); }

  string ToString() const {
    string str;
    str += strprintf("CTxIn(");
    str += prevout.ToString();
    if (prevout.IsNull())
      str +=
          strprintf(", coinbase %s",
                    HexStr(scriptSig.begin(), scriptSig.end(), false).c_str());
    else
      str += strprintf(", scriptSig=%s",
                       scriptSig.ToString().substr(0, 24).c_str());
    if (nSequence != UINT_MAX)
      str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
  }

  void print() const { printf("%s\n", ToString().c_str()); }

  bool IsMine() const;
  int64 GetDebit() const;
};

//
// An output of a transaction.  It contains the public key that the next input
// must be able to sign with to claim it.
// 一笔交易的输出项。
// 它包含一个公钥，下一个输入项必须能够用该公钥进行签名，才能获得该输出项
class CTxOut {
public:
  int64 nValue;
  CScript scriptPubKey;

public:
  CTxOut() { SetNull(); }

  CTxOut(int64 nValueIn, CScript scriptPubKeyIn) {
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
  }

  IMPLEMENT_SERIALIZE(READWRITE(nValue); READWRITE(scriptPubKey);)

  void SetNull() {
    nValue = -1;
    scriptPubKey.clear();
  }

  bool IsNull() { return (nValue == -1); }

  uint256 GetHash() const { return SerializeHash(*this); }

  bool IsMine() const { return ::IsMine(scriptPubKey); }

  int64 GetCredit() const {
    if (IsMine())
      return nValue;
    return 0;
  }

  friend bool operator==(const CTxOut &a, const CTxOut &b) {
    return (a.nValue == b.nValue && a.scriptPubKey == b.scriptPubKey);
  }

  friend bool operator!=(const CTxOut &a, const CTxOut &b) { return !(a == b); }

  string ToString() const {
    if (scriptPubKey.size() < 6)
      return "CTxOut(error)";
    return strprintf("CTxOut(nValue=%I64d.%08I64d, scriptPubKey=%s)",
                     nValue / COIN, nValue % COIN,
                     scriptPubKey.ToString().substr(0, 24).c_str());
  }

  void print() const { printf("%s\n", ToString().c_str()); }
};

//
// The basic transaction that is broadcasted on the network and contained in
// blocks.  A transaction can contain multiple inputs and outputs.
// 网络中广播的、包含在区块中的基本交易。一笔交易可以包含多个输入和输出。
class CTransaction {
public:
  int nVersion;        // 交易版本号，用于协议升级
  vector<CTxIn> vin;   // 交易输入列表
  vector<CTxOut> vout; // 交易输出列表
  int nLockTime;       // 锁定时间，交易生效的区块高度或时间戳

  /**
   * 构造函数
   * 初始化交易对象，调用SetNull()设置默认值
   */
  CTransaction() { SetNull(); }

  /**
   * 序列化方法
   * 用于网络传输和磁盘存储时的序列化/反序列化
   */
  IMPLEMENT_SERIALIZE(READWRITE(this->nVersion); nVersion = this->nVersion;
                      READWRITE(vin); READWRITE(vout); READWRITE(nLockTime);)

  /**
   * 设置交易为默认状态
   * 将版本号设为1，清空输入输出列表，锁定时间设为0
   */
  void SetNull() {
    nVersion = 1;
    vin.clear();
    vout.clear();
    nLockTime = 0;
  }

  /**
   * 检查交易是否为空
   * @return 如果输入和输出列表都为空，返回true，否则返回false
   */
  bool IsNull() const { return (vin.empty() && vout.empty()); }

  /**
   * 获取交易的哈希值
   * 通过序列化交易并计算哈希得到唯一标识符
   * @return 交易的256位哈希值
   */
  uint256 GetHash() const { return SerializeHash(*this); }

  /**
   * 检查交易是否为最终状态
   * 当锁定时间为0或小于当前最佳区块高度时，交易为最终状态
   * 否则需要检查所有输入是否为最终状态
   * @return 如果交易为最终状态，返回true，否则返回false
   */
  bool IsFinal() const {
    if (nLockTime == 0 || nLockTime < nBestHeight)
      return true;
    foreach (const CTxIn &txin, vin)
      if (!txin.IsFinal())
        return false;
    return true;
  }

  /**
   * 检查当前交易是否比另一个交易更新
   * 基于交易输入的nSequence字段进行比较
   * @param old 要比较的旧交易
   * @return 如果当前交易更新，返回true，否则返回false
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
   * 检查交易是否为币基交易
   * 币基交易是区块中的第一个交易，用于创建新的比特币
   * @return 如果是币基交易，返回true，否则返回false
   */
  bool IsCoinBase() const {
    return (vin.size() == 1 && vin[0].prevout.IsNull());
  }

  /**
   * 检查交易的基本有效性
   * 不依赖于上下文的基本检查，包括：
   * 1. 输入和输出列表不能为空
   * 2. 输出金额不能为负值
   * 3. 币基交易的脚本大小必须在2-100字节之间
   * 4. 非币基交易的输入不能引用空的输出点
   * @return 如果交易有效，返回true，否则返回false
   */
  bool CheckTransaction() const {
    // 基本检查，不依赖于任何上下文
    if (vin.empty() || vout.empty())
      return error("CTransaction::CheckTransaction() : vin or vout empty");

    // 检查是否有负值
    foreach (const CTxOut &txout, vout)
      if (txout.nValue < 0)
        return error(
            "CTransaction::CheckTransaction() : txout.nValue negative");

    if (IsCoinBase()) {
      if (vin[0].scriptSig.size() < 2 || vin[0].scriptSig.size() > 100)
        return error("CTransaction::CheckTransaction() : coinbase script size");
    } else {
      foreach (const CTxIn &txin, vin)
        if (txin.prevout.IsNull())
          return error("CTransaction::CheckTransaction() : prevout is null");
    }

    return true;
  }

  /**
   * 检查交易是否与当前钱包相关
   * 即检查交易的输出是否属于当前钱包
   * @return 如果交易与当前钱包相关，返回true，否则返回false
   */
  bool IsMine() const {
    foreach (const CTxOut &txout, vout)
      if (txout.IsMine())
        return true;
    return false;
  }

  /**
   * 获取交易的总借记金额
   * 即交易所有输入的金额总和
   * @return 交易的总借记金额，单位为聪
   */
  int64 GetDebit() const {
    int64 nDebit = 0;
    foreach (const CTxIn &txin, vin)
      nDebit += txin.GetDebit();
    return nDebit;
  }

  /**
   * 获取交易的总贷记金额
   * 即交易所有属于当前钱包的输出金额总和
   * @return 交易的总贷记金额，单位为聪
   */
  int64 GetCredit() const {
    int64 nCredit = 0;
    foreach (const CTxOut &txout, vout)
      nCredit += txout.GetCredit();
    return nCredit;
  }

  /**
   * 获取交易的总输出金额
   * 即交易所有输出的金额总和
   * @return 交易的总输出金额，单位为聪
   * @throws runtime_error 如果任何输出金额为负值
   */
  int64 GetValueOut() const {
    int64 nValueOut = 0;
    foreach (const CTxOut &txout, vout) {
      if (txout.nValue < 0)
        throw runtime_error("CTransaction::GetValueOut() : negative value");
      nValueOut += txout.nValue;
    }
    return nValueOut;
  }

  /**
   * 计算交易的最低手续费
   * 根据交易大小计算，每1000字节收取1聪的手续费
   * @param fDiscount 是否应用折扣（小于10000字节的交易免费）
   * @return 交易的最低手续费，单位为聪
   */
  int64 GetMinFee(bool fDiscount = false) const {
    unsigned int nBytes = ::GetSerializeSize(*this, SER_NETWORK);
    if (fDiscount && nBytes < 10000)
      return 0;
    return (1 + (int64)nBytes / 1000) * CENT;
  }

  /**
   * 从磁盘读取交易
   * @param pos 交易在磁盘上的位置
   * @param pfileRet 可选的文件指针返回值
   * @return 如果成功读取，返回true，否则返回false
   */
  bool ReadFromDisk(CDiskTxPos pos, FILE **pfileRet = NULL) {
    CAutoFile filein = OpenBlockFile(pos.nFile, 0, pfileRet ? "rb+" : "rb");
    if (!filein)
      return error("CTransaction::ReadFromDisk() : OpenBlockFile failed");

    // 读取交易
    if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
      return error("CTransaction::ReadFromDisk() : fseek failed");
    filein >> *this;

    // 返回文件指针
    if (pfileRet) {
      if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
        return error("CTransaction::ReadFromDisk() : second fseek failed");
      *pfileRet = filein.release();
    }
    return true;
  }

  /**
   * 等于运算符重载
   * 比较两个交易是否相等
   * @param a 第一个交易
   * @param b 第二个交易
   * @return 如果两个交易相等，返回true，否则返回false
   */
  friend bool operator==(const CTransaction &a, const CTransaction &b) {
    return (a.nVersion == b.nVersion && a.vin == b.vin && a.vout == b.vout &&
            a.nLockTime == b.nLockTime);
  }

  /**
   * 不等于运算符重载
   * 比较两个交易是否不相等
   * @param a 第一个交易
   * @param b 第二个交易
   * @return 如果两个交易不相等，返回true，否则返回false
   */
  friend bool operator!=(const CTransaction &a, const CTransaction &b) {
    return !(a == b);
  }

  /**
   * 将交易转换为字符串表示
   * 包含交易哈希、版本、输入输出数量、锁定时间等信息
   * @return 交易的字符串表示
   */
  string ToString() const {
    string str;
    str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%d, vout.size=%d, "
                     "nLockTime=%d)\n",
                     GetHash().ToString().substr(0, 6).c_str(), nVersion,
                     vin.size(), vout.size(), nLockTime);
    for (int i = 0; i < vin.size(); i++)
      str += "    " + vin[i].ToString() + "\n";
    for (int i = 0; i < vout.size(); i++)
      str += "    " + vout[i].ToString() + "\n";
    return str;
  }

  /**
   * 打印交易信息
   * 调用ToString()方法并打印结果
   */
  void print() const { printf("%s", ToString().c_str()); }

  /**
   * 断开交易输入的连接
   * 用于区块回滚时，将交易的输入标记为未花费
   * @param txdb 交易数据库
   * @return 如果成功断开连接，返回true，否则返回false
   */
  bool DisconnectInputs(CTxDB &txdb);

  /**
   * 连接交易输入
   * 验证交易输入的有效性，并将输入标记为已花费
   * @param txdb 交易数据库
   * @param mapTestPool 测试池映射
   * @param posThisTx 当前交易在磁盘上的位置
   * @param nHeight 区块高度
   * @param nFees 交易手续费
   * @param fBlock 是否在区块中
   * @param fMiner 是否为矿工
   * @param nMinFee 最低手续费
   * @return 如果成功连接，返回true，否则返回false
   */
  bool ConnectInputs(CTxDB &txdb, map<uint256, CTxIndex> &mapTestPool,
                     CDiskTxPos posThisTx, int nHeight, int64 &nFees,
                     bool fBlock, bool fMiner, int64 nMinFee = 0);

  /**
   * 客户端连接交易输入
   * 用于客户端验证交易
   * @return 如果成功连接，返回true，否则返回false
   */
  bool ClientConnectInputs();

  /**
   * 接受交易
   * 验证交易并将其添加到内存池
   * @param txdb 交易数据库
   * @param fCheckInputs 是否检查输入
   * @param pfMissingInputs 可选的缺失输入标记
   * @return 如果成功接受，返回true，否则返回false
   */
  bool AcceptTransaction(CTxDB &txdb, bool fCheckInputs = true,
                         bool *pfMissingInputs = NULL);

  /**
   * 接受交易（重载）
   * 创建只读交易数据库并调用重载版本
   * @param fCheckInputs 是否检查输入
   * @param pfMissingInputs 可选的缺失输入标记
   * @return 如果成功接受，返回true，否则返回false
   */
  bool AcceptTransaction(bool fCheckInputs = true,
                         bool *pfMissingInputs = NULL) {
    CTxDB txdb("r");
    return AcceptTransaction(txdb, fCheckInputs, pfMissingInputs);
  }

protected:
  /**
   * 添加交易到内存池
   * @return 如果成功添加，返回true，否则返回false
   */
  bool AddToMemoryPool();

public:
  /**
   * 从内存池移除交易
   * @return 如果成功移除，返回true，否则返回false
   */
  bool RemoveFromMemoryPool();
};

//
// A transaction with a merkle branch linking it to the block chain
// 一种与区块链存在关联的、通过默克尔分支进行连接的交易操作
class CMerkleTx : public CTransaction {
public:
  uint256 hashBlock;             // 交易所在区块的哈希值
  vector<uint256> vMerkleBranch; // 默克尔分支，用于验证交易存在性
  int nIndex;                    // 交易在区块中的索引位置

  // memory only
  mutable bool fMerkleVerified; // 默克尔验证状态（仅内存中使用）

  /**
   * 构造函数
   * 初始化默克尔交易对象，调用Init()设置默认值
   */
  CMerkleTx() { Init(); }

  /**
   * 构造函数（从CTransaction构造）
   * @param txIn 基础交易对象
   */
  CMerkleTx(const CTransaction &txIn) : CTransaction(txIn) { Init(); }

  /**
   * 初始化默克尔交易的默认值
   * 将区块哈希设为0，索引设为-1，验证状态设为false
   */
  void Init() {
    hashBlock = 0;
    nIndex = -1;
    fMerkleVerified = false;
  }

  /**
   * 获取交易的贷记金额
   * 对于币基交易，需要等待足够的确认数才能计入余额
   * @return 交易的贷记金额，单位为聪
   */
  int64 GetCredit() const {
    // 必须等待币基交易在链中足够深后才能计入价值
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
      return 0;
    return CTransaction::GetCredit();
  }

  /**
   * 序列化方法
   * 用于网络传输和磁盘存储时的序列化/反序列化
   */
  IMPLEMENT_SERIALIZE(nSerSize += SerReadWrite(s, *(CTransaction *)this, nType,
                                               nVersion, ser_action);
                      nVersion = this->nVersion; READWRITE(hashBlock);
                      READWRITE(vMerkleBranch); READWRITE(nIndex);)

  /**
   * 设置默克尔分支
   * 为交易设置默克尔分支信息，用于验证交易存在性
   * @param pblock 可选的区块指针
   * @return 成功返回0，失败返回错误码
   */
  int SetMerkleBranch(const CBlock *pblock = NULL);

  /**
   * 获取交易在主链中的深度
   * 即交易所在区块到最长链 tip 的距离
   * @return 交易在主链中的深度
   */
  int GetDepthInMainChain() const;

  /**
   * 检查交易是否在主链中
   * @return 如果交易在主链中，返回true，否则返回false
   */
  bool IsInMainChain() const { return GetDepthInMainChain() > 0; }

  /**
   * 获取币基交易到成熟所需的区块数
   * 币基交易需要100个确认才能成熟
   * @return 到成熟所需的区块数
   */
  int GetBlocksToMaturity() const;

  /**
   * 接受默克尔交易
   * 验证交易并将其添加到钱包
   * @param txdb 交易数据库
   * @param fCheckInputs 是否检查输入
   * @return 如果成功接受，返回true，否则返回false
   */
  bool AcceptTransaction(CTxDB &txdb, bool fCheckInputs = true);

  /**
   * 接受默克尔交易（重载）
   * 创建只读交易数据库并调用重载版本
   * @return 如果成功接受，返回true，否则返回false
   */
  bool AcceptTransaction() {
    CTxDB txdb("r");
    return AcceptTransaction(txdb);
  }
};

//
// A transaction with a bunch of additional info that only the owner cares
// about.  It includes any unrecorded transactions needed to link it back
// to the block chain.
// 一种包含大量附加信息的交易，这些信息只有交易的拥有者才关心。
// 它包含了任何用于将该交易链接回区块链所需的未记录交易信息。
class CWalletTx : public CMerkleTx {
public:
  vector<CMerkleTx> vtxPrev;               // 前序交易列表，用于构建交易链
  map<string, string> mapValue;            // 键值对数据，存储交易相关信息
  vector<pair<string, string>> vOrderForm; // 订单表单，用于交易附加信息
  unsigned int fTimeReceivedIsTxTime;      // 接收时间是否为交易时间
  unsigned int nTimeReceived;              // 节点接收交易的时间
  char fFromMe;                            // 是否由当前钱包发送
  char fSpent;                             // 交易是否已花费
  //// probably need to sign the order info so know it came from payer
  // 可能需要签署订单信息以确认其确实来自付款方
  //  memory only 内存中仅使用
  mutable unsigned int nTimeDisplayed; // 交易显示时间（仅内存中使用）

  /**
   * 构造函数
   * 初始化钱包交易对象，调用Init()设置默认值
   */
  CWalletTx() { Init(); }

  /**
   * 构造函数（从CMerkleTx构造）
   * @param txIn 默克尔交易对象
   */
  CWalletTx(const CMerkleTx &txIn) : CMerkleTx(txIn) { Init(); }

  /**
   * 构造函数（从CTransaction构造）
   * @param txIn 基础交易对象
   */
  CWalletTx(const CTransaction &txIn) : CMerkleTx(txIn) { Init(); }

  /**
   * 初始化钱包交易的默认值
   * 设置时间和状态标志为默认值
   */
  void Init() {
    fTimeReceivedIsTxTime = false;
    nTimeReceived = 0;
    fFromMe = false;
    fSpent = false;
    nTimeDisplayed = 0;
  }

  /**
   * 序列化方法
   * 用于网络传输和磁盘存储时的序列化/反序列化
   */
  IMPLEMENT_SERIALIZE(nSerSize += SerReadWrite(s, *(CMerkleTx *)this, nType,
                                               nVersion, ser_action);
                      nVersion = this->nVersion; READWRITE(vtxPrev);
                      READWRITE(mapValue); READWRITE(vOrderForm);
                      READWRITE(fTimeReceivedIsTxTime);
                      READWRITE(nTimeReceived); READWRITE(fFromMe);
                      READWRITE(fSpent);)

  /**
   * 将交易写入磁盘
   * @return 如果成功写入，返回true，否则返回false
   */
  bool WriteToDisk() { return CWalletDB().WriteTx(GetHash(), *this); }

  /**
   * 获取交易时间
   * @return 交易时间戳
   */
  int64 GetTxTime() const;

  /**
   * 添加支持交易
   * 添加交易所需的前序交易，用于构建完整的交易链
   * @param txdb 交易数据库
   */
  void AddSupportingTransactions(CTxDB &txdb);

  /**
   * 接受钱包交易
   * 验证交易并将其添加到钱包
   * @param txdb 交易数据库
   * @param fCheckInputs 是否检查输入
   * @return 如果成功接受，返回true，否则返回false
   */
  bool AcceptWalletTransaction(CTxDB &txdb, bool fCheckInputs = true);

  /**
   * 接受钱包交易（重载）
   * 创建只读交易数据库并调用重载版本
   * @return 如果成功接受，返回true，否则返回false
   */
  bool AcceptWalletTransaction() {
    CTxDB txdb("r");
    return AcceptWalletTransaction(txdb);
  }

  /**
   * 中继钱包交易
   * 将交易广播到网络
   * @param txdb 交易数据库
   */
  void RelayWalletTransaction(CTxDB &txdb);

  /**
   * 中继钱包交易（重载）
   * 创建只读交易数据库并调用重载版本
   */
  void RelayWalletTransaction() {
    CTxDB txdb("r");
    RelayWalletTransaction(txdb);
  }
};

//
// A txdb record that contains the disk location of a transaction and the
// locations of transactions that spend its outputs.  vSpent is really only
// used as a flag, but having the location is very helpful for debugging.
//
// 一个 txdb 记录包含了交易的磁盘位置以及使用其输出的其他交易的存储位置。
// vSpent 实际上只是用作一个标志，但拥有这些位置对于调试非常有帮助。//
class CTxIndex {
public:
  CDiskTxPos pos;
  vector<CDiskTxPos> vSpent;

  CTxIndex() { SetNull(); }

  CTxIndex(const CDiskTxPos &posIn, unsigned int nOutputs) {
    pos = posIn;
    vSpent.resize(nOutputs);
  }

  IMPLEMENT_SERIALIZE(if (!(nType & SER_GETHASH)) READWRITE(nVersion);
                      READWRITE(pos); READWRITE(vSpent);)

  void SetNull() {
    pos.SetNull();
    vSpent.clear();
  }

  bool IsNull() { return pos.IsNull(); }

  friend bool operator==(const CTxIndex &a, const CTxIndex &b) {
    if (a.pos != b.pos || a.vSpent.size() != b.vSpent.size())
      return false;
    for (int i = 0; i < a.vSpent.size(); i++)
      if (a.vSpent[i] != b.vSpent[i])
        return false;
    return true;
  }

  friend bool operator!=(const CTxIndex &a, const CTxIndex &b) {
    return !(a == b);
  }
};

//
// Nodes collect new transactions into a block, hash them into a hash tree,
// and scan through nonce values to make the block's hash satisfy proof-of-work
// requirements.  When they solve the proof-of-work, they broadcast the block
// to everyone and the block is added to the block chain.  The first transaction
// in the block is a special one that creates a new coin owned by the creator
// of the block.
//
// Blocks are appended to blk0001.dat files on disk.  Their location on disk
// is indexed by CBlockIndex objects in memory.
//
//
// 节点将新的交易汇集到一个区块中，将它们进行哈希运算生成一个哈希树，
// 并遍历 nonce
// 值以使区块的哈希值满足工作量证明的要求。当它们解决工作量证明问题时，
// 他们会将该区块广播给所有人，然后该区块会被添加到区块链中。
// 区块中的第一个交易是一个特殊的交易，它创建了一个由区块的创建者所拥有的新货币。//
// 块会被附加到磁盘上的 blk0001.dat 文件中。这些块在磁盘上的位置是由内存中的
// CBlockIndex 对象进行索引管理的。//

class CBlock {
public:
  // header
  int nVersion;
  uint256 hashPrevBlock;
  uint256 hashMerkleRoot;
  unsigned int nTime;
  unsigned int nBits;
  unsigned int nNonce;

  // network and disk
  vector<CTransaction> vtx;

  // memory only
  mutable vector<uint256> vMerkleTree;

  CBlock() { SetNull(); }

  IMPLEMENT_SERIALIZE(
      READWRITE(this->nVersion); nVersion = this->nVersion;
      READWRITE(hashPrevBlock); READWRITE(hashMerkleRoot); READWRITE(nTime);
      READWRITE(nBits); READWRITE(nNonce);

      // ConnectBlock depends on vtx being last so it can calculate offset
      if (!(nType & (SER_GETHASH | SER_BLOCKHEADERONLY))) READWRITE(vtx);
      else if (fRead) const_cast<CBlock *>(this)->vtx.clear();)

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

  bool IsNull() const { return (nBits == 0); }

  uint256 GetHash() const { return Hash(BEGIN(nVersion), END(nNonce)); }

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

  bool WriteToDisk(bool fWriteTransactions, unsigned int &nFileRet,
                   unsigned int &nBlockPosRet) {
    // Open history file to append
    CAutoFile fileout = AppendBlockFile(nFileRet);
    if (!fileout)
      return error("CBlock::WriteToDisk() : AppendBlockFile failed");
    if (!fWriteTransactions)
      fileout.nType |= SER_BLOCKHEADERONLY;

    // Write index header
    unsigned int nSize = fileout.GetSerializeSize(*this);
    fileout << FLATDATA(pchMessageStart) << nSize;

    // Write block
    nBlockPosRet = ftell(fileout);
    if (nBlockPosRet == -1)
      return error("CBlock::WriteToDisk() : ftell failed");
    fileout << *this;

    return true;
  }

  bool ReadFromDisk(unsigned int nFile, unsigned int nBlockPos,
                    bool fReadTransactions) {
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
    if (CBigNum().SetCompact(nBits) > bnProofOfWorkLimit)
      return error("CBlock::ReadFromDisk() : nBits errors in block header");
    if (GetHash() > CBigNum().SetCompact(nBits).getuint256())
      return error("CBlock::ReadFromDisk() : GetHash() errors in block header");

    return true;
  }

  void print() const {
    printf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, "
           "nTime=%u, nBits=%08x, nNonce=%u, vtx=%d)\n",
           GetHash().ToString().substr(0, 14).c_str(), nVersion,
           hashPrevBlock.ToString().substr(0, 14).c_str(),
           hashMerkleRoot.ToString().substr(0, 6).c_str(), nTime, nBits, nNonce,
           vtx.size());
    for (int i = 0; i < vtx.size(); i++) {
      printf("  ");
      vtx[i].print();
    }
    printf("  vMerkleTree: ");
    for (int i = 0; i < vMerkleTree.size(); i++)
      printf("%s ", vMerkleTree[i].ToString().substr(0, 6).c_str());
    printf("\n");
  }

  int64 GetBlockValue(int64 nFees) const;
  bool DisconnectBlock(CTxDB &txdb, CBlockIndex *pindex);
  bool ConnectBlock(CTxDB &txdb, CBlockIndex *pindex);
  bool ReadFromDisk(const CBlockIndex *blockindex, bool fReadTransactions);
  bool AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos);
  bool CheckBlock() const;
  bool AcceptBlock();
};

//
// The block chain is a tree shaped structure starting with the
// genesis block at the root, with each block potentially having multiple
// candidates to be the next block.  pprev and pnext link a path through the
// main/longest chain.  A blockindex may have multiple pprev pointing back
// to it, but pnext will only point forward to the longest branch, or will
// be null if the block is not part of the longest chain.
//
//
// 区块链是一种树状结构，起始点是创世区块，位于根部。
// 每个区块都有可能有多个成为下一区块的候选者。
// pprev 和 pnext 构成了贯穿主链/最长链的路径。
// 一个区块索引可能有多个指向它的 pprev，但 pnext
// 只会指向最长分支，或者如果该区块不属于最长链，则 pnext 会为空。//

class CBlockIndex {
public:
  const uint256 *phashBlock;
  CBlockIndex *pprev;
  CBlockIndex *pnext;
  unsigned int nFile;
  unsigned int nBlockPos;
  int nHeight;

  // block header
  int nVersion;
  uint256 hashMerkleRoot;
  unsigned int nTime;
  unsigned int nBits;
  unsigned int nNonce;

  CBlockIndex() {
    phashBlock = NULL;
    pprev = NULL;
    pnext = NULL;
    nFile = 0;
    nBlockPos = 0;
    nHeight = 0;

    nVersion = 0;
    hashMerkleRoot = 0;
    nTime = 0;
    nBits = 0;
    nNonce = 0;
  }

  CBlockIndex(unsigned int nFileIn, unsigned int nBlockPosIn, CBlock &block) {
    phashBlock = NULL;
    pprev = NULL;
    pnext = NULL;
    nFile = nFileIn;
    nBlockPos = nBlockPosIn;
    nHeight = 0;

    nVersion = block.nVersion;
    hashMerkleRoot = block.hashMerkleRoot;
    nTime = block.nTime;
    nBits = block.nBits;
    nNonce = block.nNonce;
  }

  uint256 GetBlockHash() const { return *phashBlock; }

  bool IsInMainChain() const { return (pnext || this == pindexBest); }

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

  enum { nMedianTimeSpan = 11 };

  /**
   * 获取过去nMedianTimeSpan个区块的中位数时间
   *
   * 计算最近nMedianTimeSpan个区块的时间戳的中位数，用于时间同步和验证
   * 中位数时间可以抵抗个别节点的时间偏移，提供更稳定的时间参考
   *
   * @return 返回最近nMedianTimeSpan个区块的中位数时间戳
   */
  int64 GetMedianTimePast() const {
    // 创建一个数组pmedian来存储最近nMedianTimeSpan个区块的时间戳
    unsigned int pmedian[nMedianTimeSpan];
    // 将pbegin指向数组pmedian的最后一个元素
    unsigned int *pbegin = &pmedian[nMedianTimeSpan];
    // 将pend指向数组pmedian的最后一个元素
    unsigned int *pend = &pmedian[nMedianTimeSpan];
    const CBlockIndex *pindex = this;
    // 从当前区块开始，向前遍历 11 个区块，将它们的时间戳存入数组
    for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
      *(--pbegin) = pindex->nTime;
    // 对时间戳数组排序，找到中位数
    sort(pbegin, pend);
    // 返回中位数
    return pbegin[(pend - pbegin) / 2];
  }

  int64 GetMedianTime() const {
    const CBlockIndex *pindex = this;
    for (int i = 0; i < nMedianTimeSpan / 2; i++) {
      if (!pindex->pnext)
        return nTime;
      pindex = pindex->pnext;
    }
    return pindex->GetMedianTimePast();
  }

  string ToString() const {
    return strprintf("CBlockIndex(nprev=%08x, pnext=%08x, nFile=%d, "
                     "nBlockPos=%-6d nHeight=%d, merkle=%s, hashBlock=%s)",
                     pprev, pnext, nFile, nBlockPos, nHeight,
                     hashMerkleRoot.ToString().substr(0, 6).c_str(),
                     GetBlockHash().ToString().substr(0, 14).c_str());
  }

  void print() const { printf("%s\n", ToString().c_str()); }
};

//
// Used to marshal pointers into hashes for db storage.
// 用于将指针转换为哈希表以便进行数据库存储。
//
class CDiskBlockIndex : public CBlockIndex {
public:
  uint256 hashPrev;
  uint256 hashNext;

  CDiskBlockIndex() {
    hashPrev = 0;
    hashNext = 0;
  }

  explicit CDiskBlockIndex(CBlockIndex *pindex) : CBlockIndex(*pindex) {
    hashPrev = (pprev ? pprev->GetBlockHash() : 0);
    hashNext = (pnext ? pnext->GetBlockHash() : 0);
  }

  IMPLEMENT_SERIALIZE(if (!(nType & SER_GETHASH)) READWRITE(nVersion);

                      READWRITE(hashNext); READWRITE(nFile);
                      READWRITE(nBlockPos); READWRITE(nHeight);

                      // block header
                      READWRITE(this->nVersion); READWRITE(hashPrev);
                      READWRITE(hashMerkleRoot); READWRITE(nTime);
                      READWRITE(nBits); READWRITE(nNonce);)

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

  string ToString() const {
    string str = "CDiskBlockIndex(";
    str += CBlockIndex::ToString();
    str +=
        strprintf("\n                hashBlock=%s, hashPrev=%s, hashNext=%s)",
                  GetBlockHash().ToString().c_str(),
                  hashPrev.ToString().substr(0, 14).c_str(),
                  hashNext.ToString().substr(0, 14).c_str());
    return str;
  }

  void print() const { printf("%s\n", ToString().c_str()); }
};

//
// Describes a place in the block chain to another node such that if the
// other node doesn't have the same branch, it can find a recent common trunk.
// The further back it is, the further before the fork it may be.
// 该描述用于将区块链中的某个位置传递给另一节点，
// 以便如果该节点没有相同的分支，它能够找到最近的共同主干。
// 时间越久远，就越可能是在分叉事件发生之前较早的阶段。
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

extern map<uint256, CTransaction> mapTransactions;
extern map<uint256, CWalletTx> mapWallet;
extern vector<pair<uint256, bool>> vWalletUpdated;
extern CCriticalSection cs_mapWallet;
extern map<vector<unsigned char>, CPrivKey> mapKeys;
extern map<uint160, vector<unsigned char>> mapPubKeys;
extern CCriticalSection cs_mapKeys;
extern CKey keyUser;
