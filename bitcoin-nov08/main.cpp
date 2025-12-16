// Copyright (c) 2008 Satoshi Nakamoto
//
// 版权声明：允许任何人免费获得本软件及其相关文档文件（"软件"）的副本
// 可以无限制地使用、复制、修改、合并、发布、分发、再许可和/或出售软件副本
// 以及允许被提供本软件的人这样做，但须符合以下条件：
//
// 上述版权声明和本许可声明应包含在软件的所有副本或实质性部分中
//
// 本软件按"原样"提供，不附带任何形式的保证，无论是明示的还是暗示的
// 包括但不限于对适销性、特定用途适用性、标题和非侵权性的保证
// 在任何情况下，作者或版权持有人均不对任何索赔、损害或其他责任负责
// 无论是在合同行为、侵权行为或其他方面，与软件或软件的使用或其他交易有关

#include "headers.h" // 包含比特币的头文件
#include "sha.h"     // 包含SHA哈希函数实现

//
// 全局状态变量定义
//

// 存储交易的映射表，键为交易哈希，值为交易对象
map<uint256, CTransaction> mapTransactions;
// 用于保护mapTransactions的临界区锁
CCriticalSection cs_mapTransactions;
// 跟踪交易更新的计数器
unsigned int nTransactionsUpdated = 0;
/// mapNextTx现在仅用于跟踪内存交易使用的磁盘交易输出点
map<COutPoint, CInPoint> mapNextTx;

// 区块索引映射表，键为区块哈希，值为区块索引指针
map<uint256, CBlockIndex *> mapBlockIndex;
// 创世区块哈希值定义
const uint256 hashGenesisBlock(
    "0x000006b15d1327d67e971d1de9116bd60a3a01556c91b6ebaa416ebc0cfaa646");
// 创世区块索引指针，初始为NULL
CBlockIndex *pindexGenesisBlock = NULL;
// 当前最佳区块链的高度，初始为-1
int nBestHeight = -1;
// 时间链最佳区块哈希，初始为0
uint256 hashTimeChainBest = 0;
// 最佳区块索引指针，初始为NULL
CBlockIndex *pindexBest = NULL;

// 存储孤立区块的映射表，键为区块哈希，值为区块指针
map<uint256, CBlock *> mapOrphanBlocks;
// 按前一个区块哈希索引的孤立区块多重映射
multimap<uint256, CBlock *> mapOrphanBlocksByPrev;

// 钱包交易映射表，键为交易哈希，值为钱包交易对象
map<uint256, CWalletTx> mapWallet;
// 钱包更新记录，存储更新的交易哈希和是否为新交易的标志
vector<pair<uint256, bool>> vWalletUpdated;
// 用于保护mapWallet的临界区锁
CCriticalSection cs_mapWallet;

// 密钥映射表，键为公钥，值为私钥
map<vector<unsigned char>, CPrivKey> mapKeys;
// 公钥映射表，键为哈希后的公钥，值为原始公钥
map<uint160, vector<unsigned char>> mapPubKeys;
// 用于保护mapKeys的临界区锁
CCriticalSection cs_mapKeys;
// 用户密钥对象
CKey keyUser;

// 控制是否生成比特币的标志
int fGenerateBitcoins;

//////////////////////////////////////////////////////////////////////////////
//
// mapKeys - 密钥管理函数
//

// 添加密钥到密钥映射表
bool AddKey(const CKey &key) {
  CRITICAL_BLOCK(cs_mapKeys) // 在临界区内操作，确保线程安全
  {
    // 将公钥作为键，私钥作为值存储到mapKeys中
    mapKeys[key.GetPubKey()] = key.GetPrivKey();
    // 将哈希后的公钥作为键，原始公钥作为值存储到mapPubKeys中
    mapPubKeys[Hash160(key.GetPubKey())] = key.GetPubKey();
  }
  // 将密钥写入数据库
  return CWalletDB().WriteKey(key.GetPubKey(), key.GetPrivKey());
}

// 生成新的密钥对
vector<unsigned char> GenerateNewKey() {
  CKey key;         // 创建新的密钥对象
  key.MakeNewKey(); // 生成新的密钥对
  if (!AddKey(key)) // 如果添加密钥失败，抛出运行时错误
    throw runtime_error("GenerateNewKey() : AddKey failed\n");
  return key.GetPubKey(); // 返回生成的公钥
}

//////////////////////////////////////////////////////////////////////////////
//
// mapWallet - 钱包管理函数
//

// 将交易添加到钱包中
bool AddToWallet(const CWalletTx &wtxIn) {
  uint256 hash = wtxIn.GetHash(); // 获取交易的哈希值
  CRITICAL_BLOCK(cs_mapWallet)    // 在临界区内操作，确保线程安全
  {
    // 尝试将交易插入到钱包中，如果已存在则返回现有交易，否则插入新交易
    pair<map<uint256, CWalletTx>::iterator, bool> ret =
        mapWallet.insert(make_pair(hash, wtxIn));
    CWalletTx &wtx = (*ret.first).second; // 获取实际存储的交易引用
    bool fInsertedNew = ret.second;       // 标记是否是新插入的交易

    //// 调试输出
    printf("AddToWallet %s  %d\n", wtxIn.GetHash().ToString().c_str(),
           fInsertedNew);

    if (!fInsertedNew) // 如果交易已存在
    {
      // 合并更新信息
      bool fUpdated = false; // 标记是否有更新
      // 如果新交易的区块哈希不为0且与现有交易不同，则更新
      if (wtxIn.hashBlock != 0 && wtxIn.hashBlock != wtx.hashBlock) {
        wtx.hashBlock = wtxIn.hashBlock;
        fUpdated = true;
      }
      // 如果新交易标记为从我发出且与现有交易不同，则更新
      if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe) {
        wtx.fFromMe = wtxIn.fFromMe;
        fUpdated = true;
      }
      // 如果新交易标记为已花费且与现有交易不同，则更新
      if (wtxIn.fSpent && wtxIn.fSpent != wtx.fSpent) {
        wtx.fSpent = wtxIn.fSpent;
        fUpdated = true;
      }
      if (!fUpdated) // 如果没有任何更新，直接返回成功
        return true;
    }

    // 将交易写入磁盘
    if (!wtx.WriteToDisk())
      return false;

    // 通知UI有更新
    vWalletUpdated.push_back(make_pair(hash, fInsertedNew));
  }

  // 刷新UI显示
  MainFrameRepaint();
  return true;
}

// 如果交易属于我，则添加到钱包
bool AddToWalletIfMine(const CTransaction &tx, const CBlock *pblock) {
  if (tx.IsMine()) // 检查交易是否属于我
  {
    CWalletTx wtx(tx); // 创建钱包交易对象
    if (pblock)        // 如果提供了区块信息
    {
      wtx.hashBlock = pblock->GetHash(); // 设置区块哈希
      wtx.nTime = pblock->nTime;         // 设置区块时间戳
    } else                               // 如果没有区块信息
    {
      wtx.nTime = GetAdjustedTime(); // 使用当前调整后的时间
    }
    return AddToWallet(wtx); // 添加到钱包
  }
  return true; // 如果不属于我，直接返回成功
}

// 重新接受钱包中的交易
void ReacceptWalletTransactions() {
  // 重新接受任何属于我们但尚未在区块中的交易
  CRITICAL_BLOCK(cs_mapWallet) // 在临界区内操作
  {
    CTxDB txdb("r"); // 以只读模式打开交易数据库
    foreach (PAIRTYPE(const uint256, CWalletTx) & item,
             mapWallet) // 遍历钱包中的所有交易
    {
      CWalletTx &wtx = item.second; // 获取交易引用
      if (!txdb.ContainsTx(
              wtx.GetHash())) // 如果交易不在数据库中（即不在区块中）
        wtx.AcceptWalletTransaction(txdb, false); // 重新接受交易
    }
  }
}

// 中继钱包中的交易
void RelayWalletTransactions() {
  static int64 nLastTime;              // 上次中继时间
  if (GetTime() - nLastTime < 15 * 60) // 如果距离上次中继不足15分钟，不执行
    return;
  nLastTime = GetTime(); // 更新上次中继时间

  // 重新广播任何属于我们但尚未在区块中的交易
  CRITICAL_BLOCK(cs_mapWallet) // 在临界区内操作
  {
    CTxDB txdb("r"); // 以只读模式打开交易数据库
    foreach (PAIRTYPE(const uint256, CWalletTx) & item,
             mapWallet)                         // 遍历钱包中的所有交易
      item.second.RelayWalletTransaction(txdb); // 中继交易
  }
}

//////////////////////////////////////////////////////////////////////////////
//
// CTransaction - 交易相关函数
//

// 检查交易输入是否属于我
bool CTxIn::IsMine() const {
  // 在钱包中查找前一个交易
  map<uint256, CWalletTx>::iterator mi = mapWallet.find(prevout.hash);
  if (mi != mapWallet.end()) // 如果找到前一个交易
  {
    const CWalletTx &prev = (*mi).second;
    if (prevout.n < prev.vout.size())    // 检查输出索引是否有效
      if (prev.vout[prevout.n].IsMine()) // 检查该输出是否属于我
        return true;
  }
  return false;
}

// 获取交易输入的金额
int64 CTxIn::GetDebit() const {
  // 在钱包中查找前一个交易
  map<uint256, CWalletTx>::iterator mi = mapWallet.find(prevout.hash);
  if (mi != mapWallet.end()) // 如果找到前一个交易
  {
    const CWalletTx &prev = (*mi).second;
    if (prevout.n < prev.vout.size())       // 检查输出索引是否有效
      if (prev.vout[prevout.n].IsMine())    // 检查该输出是否属于我
        return prev.vout[prevout.n].nValue; // 返回金额
  }
  return 0; // 如果找不到或不属于我，返回0
}

// 设置默克尔分支，用于验证交易是否在区块中
int CMerkleTx::SetMerkleBranch() {
  if (fClient) // 如果是客户端模式
  {
    if (hashBlock == 0) // 如果没有区块哈希，返回0
      return 0;
  } else // 如果是服务器模式
  {
    // 加载交易所在的区块
    CDiskTxPos pos;
    if (!CTxDB("r").ReadTxPos(GetHash(), pos)) // 读取交易位置
      return 0;
    CBlock block;
    if (!block.ReadFromDisk(pos.nFile, pos.nBlockPos, true)) // 从磁盘读取区块
      return 0;

    // 更新交易的区块哈希
    hashBlock = block.GetHash();

    // 在区块中定位交易
    for (nIndex = 0; nIndex < block.vtx.size(); nIndex++)
      if (block.vtx[nIndex] == *(CTransaction *)this) // 比较交易是否匹配
        break;
    if (nIndex == block.vtx.size()) // 如果未找到交易
    {
      vMerkleBranch.clear(); // 清空默克尔分支
      nIndex = -1;
      printf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
      return 0;
    }

    // 填充默克尔分支
    vMerkleBranch = block.GetMerkleBranch(nIndex);
  }

  // 检查交易所在区块是否在主链中
  map<uint256, CBlockIndex *>::iterator mi = mapBlockIndex.find(hashBlock);
  if (mi == mapBlockIndex.end()) // 如果未找到区块索引
    return 0;
  CBlockIndex *pindex = (*mi).second;
  if (!pindex || !pindex->IsInMainChain()) // 如果区块不在主链中
    return 0;

  // 返回交易的确认数（当前最佳区块高度减去交易所在区块高度加1）
  return pindexBest->nHeight - pindex->nHeight + 1;
}

// 添加支持性交易，用于验证当前交易
void CWalletTx::AddSupportingTransactions(CTxDB &txdb) {
  vtxPrev.clear(); // 清空之前的支持交易列表

  const int COPY_DEPTH = 3;           // 复制深度为3层
  if (SetMerkleBranch() < COPY_DEPTH) // 如果交易确认数小于复制深度
  {
    vector<uint256> vWorkQueue;                // 工作队列，存储待处理的交易哈希
    foreach (const CTxIn &txin, vin)           // 遍历交易的所有输入
      vWorkQueue.push_back(txin.prevout.hash); // 添加前一个交易的哈希到队列

    map<uint256, const CMerkleTx *> mapWalletPrev; // 存储钱包中已处理的交易
    set<uint256> setAlreadyDone; // 存储已处理过的交易哈希，避免重复
    for (int i = 0; i < vWorkQueue.size(); i++) // 处理工作队列
    {
      uint256 hash = vWorkQueue[i];   // 获取当前处理的交易哈希
      if (setAlreadyDone.count(hash)) // 如果已经处理过，跳过
        continue;
      setAlreadyDone.insert(hash); // 标记为已处理

      CMerkleTx tx;              // 创建交易对象
      if (mapWallet.count(hash)) // 如果在钱包中找到交易
      {
        tx = mapWallet[hash]; // 获取钱包中的交易
        // 将钱包交易的支持交易也添加到mapWalletPrev中
        foreach (const CMerkleTx &txWalletPrev, mapWallet[hash].vtxPrev)
          mapWalletPrev[txWalletPrev.GetHash()] = &txWalletPrev;
      } else if (mapWalletPrev.count(hash)) // 如果在之前处理的钱包交易中找到
      {
        tx = *mapWalletPrev[hash];
      } else if (!fClient &&
                 txdb.ReadDiskTx(
                     hash, tx)) // 如果在磁盘中找到交易（且不是客户端模式）
      {
        ;    // 空语句，交易已读取到tx中
      } else // 如果找不到支持交易
      {
        printf(
            "ERROR: AddSupportingTransactions() : unsupported transaction\n");
        continue;
      }

      int nDepth = tx.SetMerkleBranch(); // 设置交易的默克尔分支
      vtxPrev.push_back(tx);             // 添加到支持交易列表

      if (nDepth < COPY_DEPTH) // 如果该交易的确认数也小于复制深度
        foreach (const CTxIn &txin,
                 tx.vin) // 遍历其输入，将前一个交易哈希也加入队列
          vWorkQueue.push_back(txin.prevout.hash);
    }
  }

  reverse(vtxPrev.begin(), vtxPrev.end()); // 反转支持交易列表顺序
}

// 断开交易输入连接，用于回滚交易
bool CTransaction::DisconnectInputs(CTxDB &txdb,
                                    map<uint256, CTransaction> &mapTestPool,
                                    bool fTest) {
  // 放弃前一个交易的posNext指针
  if (!IsCoinBase()) // 如果不是 coinbase 交易
  {
    foreach (const CTxIn &txin, vin) // 遍历交易的所有输入
    {
      COutPoint prevout = txin.prevout; // 获取前一个输出点

      CAutoFile fileout = NULL; // 文件输出对象
      CTransaction txPrevBuf;   // 前一个交易的缓冲区
      // 如果是测试模式，从测试池中获取前一个交易，否则从缓冲区获取
      CTransaction &txPrev = (fTest ? mapTestPool[prevout.hash] : txPrevBuf);
      if (txPrev.IsNull()) // 如果前一个交易为空
      {
        // 从磁盘获取前一个交易
        // 版本-1表示unserialize会设置版本，以便我们写回相同的版本
        fileout.SetVersion(-1);
        if (!txdb.ReadDiskTx(prevout.hash, txPrev, &fileout)) // 读取失败
          return false;
      }

      if (prevout.n >= txPrev.vout.size()) // 检查输出索引是否有效
        return false;

      // 放弃posNext指针
      txPrev.vout[prevout.n].posNext.SetNull();

      // 写回修改
      if (!fTest) // 如果不是测试模式
        fileout << txPrev;
    }
  }

  if (fTest) // 如果是测试模式
  {
    // 将此交易的一个阻塞副本放入测试池
    CTransaction &txPool = mapTestPool[GetHash()]; // 获取测试池中的交易引用
    txPool = *this;                                // 复制当前交易
    foreach (CTxOut &txout, txPool.vout)           // 遍历所有输出
      txout.posNext = CDiskTxPos(1, 1, 1);         // 设置一个特殊值标记为已使用
  } else                                           // 如果不是测试模式
  {
    // 从索引中移除交易
    if (!txdb.EraseTxPos(*this)) // 移除失败
      return false;

    // 恢复单个交易对象
    if (!IsCoinBase())                // 如果不是coinbase交易
      AcceptTransaction(txdb, false); // 重新接受交易
  }

  return true;
}

// 连接交易输入，用于验证和添加交易
bool CTransaction::ConnectInputs(CTxDB &txdb,
                                 map<uint256, CTransaction> &mapTestPool,
                                 CDiskTxPos posThisTx, int nHeight, bool fTest,
                                 bool fMemoryTx, bool fIgnoreDiskConflicts,
                                 int64 &nFees) {
  // 接管前一个交易的posNext指针
  if (!IsCoinBase()) // 如果不是coinbase交易
  {
    int64 nValueIn = 0;                  // 输入总金额
    for (int i = 0; i < vin.size(); i++) // 遍历所有输入
    {
      COutPoint prevout = vin[i].prevout; // 获取前一个输出点

      CAutoFile fileout = NULL; // 文件输出对象
      CTransaction txPrevBuf;   // 前一个交易的缓冲区
      // 如果是测试模式，从测试池中获取前一个交易，否则从缓冲区获取
      CTransaction &txPrev = (fTest ? mapTestPool[prevout.hash] : txPrevBuf);
      if (txPrev.IsNull() && fTest && fMemoryTx &&
          mapTransactions.count(prevout.hash)) // 如果是测试模式且是内存交易
      {
        // 从内存中的单个交易获取前一个交易
        txPrev = mapTransactions[prevout.hash];
      } else if (txPrev.IsNull()) // 如果前一个交易为空
      {
        // 从磁盘获取前一个交易
        // 版本-1表示unserialize会设置版本，以便我们写回相同的版本
        fileout.SetVersion(-1);
        if (!txdb.ReadDiskTx(prevout.hash, txPrev, &fileout)) // 读取失败
          return error(
              "ConnectInputs() : prev tx not found"); // 返回错误，前一个交易未找到

        // 如果交易只会在重组中连接，
        // 那么这些输出点将在那时被检查
        if (fIgnoreDiskConflicts)              // 如果忽略磁盘冲突
          foreach (CTxOut &txout, txPrev.vout) // 遍历所有输出
            txout.posNext.SetNull();           // 清空posNext指针
      }

      if (prevout.n >= txPrev.vout.size()) // 检查输出索引是否有效
        return false;

      // 验证签名
      if (!VerifySignature(txPrev, *this, i)) // 签名验证失败
        return error(
            "ConnectInputs() : VerifySignature failed"); // 返回错误，签名验证失败

      // 检查冲突
      if (!txPrev.vout[prevout.n].posNext.IsNull()) // 如果输出已被使用
        return error(
            "ConnectInputs() : prev tx already used"); // 返回错误，前一个交易已被使用

      // 标记输出点为已使用
      txPrev.vout[prevout.n].posNext = posThisTx; // 设置为当前交易的位置

      // 写回修改
      if (!fTest)          // 如果不是测试模式
        fileout << txPrev; // 写回前一个交易

      nValueIn += txPrev.vout[prevout.n].nValue; // 累加输入金额
    }

    // 计算交易费用
    int64 nTransactionFee =
        nValueIn - GetValueOut(); // 输入金额减去输出金额即为交易费
    if (nTransactionFee < 0)      // 如果交易费为负（输入小于输出），返回失败
      return false;
    nFees += nTransactionFee; // 累加到总费用
  }

  if (fTest) // 如果是测试模式
  {
    // 将交易添加到测试池
    mapTestPool[GetHash()] = *this; // 复制当前交易到测试池
  } else                            // 如果不是测试模式
  {
    // 将交易添加到磁盘索引
    if (!txdb.WriteTxPos(*this, posThisTx, nHeight)) // 写入失败
      return false;

    // 删除冗余的单个交易对象
    CRITICAL_BLOCK(cs_mapTransactions) // 在临界区内操作
    {
      foreach (const CTxIn &txin, vin)  // 遍历所有输入
        mapNextTx.erase(txin.prevout);  // 从mapNextTx中删除对应的输出点
      mapTransactions.erase(GetHash()); // 从mapTransactions中删除当前交易
    }
  }

  return true;
}

// 接受交易到内存池
bool CTransaction::AcceptTransaction(CTxDB &txdb, bool fCheckInputs) {
  // Coinbase交易只在区块中有效，不能作为孤立交易
  if (IsCoinBase()) // 如果是coinbase交易
    return error(
        "AcceptTransaction() : coinbase as individual tx"); // 返回错误，coinbase不能作为独立交易

  if (!CheckTransaction()) // 检查交易是否有效
    return error(
        "AcceptTransaction() : CheckTransaction failed"); // 返回错误，交易检查失败

  uint256 hash = GetHash();        // 获取交易哈希
  if (mapTransactions.count(hash)) // 如果交易已在内存池中
    return false;                  // 返回失败，避免重复添加

  // 检查与内存中交易的冲突
  // 允许用同一交易的新版本替换
  CTransaction *ptxOld = NULL;         // 存储旧版本交易指针
  for (int i = 0; i < vin.size(); i++) // 遍历所有交易输入
  {
    COutPoint outpoint = vin[i].prevout; // 获取前一个输出点
    if (mapNextTx.count(outpoint))       // 如果该输出点已被使用
    {
      if (ptxOld == NULL) // 如果还未找到旧版本交易
      {
        ptxOld = mapNextTx[outpoint].ptx; // 获取使用该输出点的交易
        if (!IsUpdate(*ptxOld))           // 检查是否是同一交易的更新版本
          return false;                   // 返回失败，不是更新版本
      } else if (ptxOld != mapNextTx[outpoint]
                               .ptx) // 如果找到多个不同的旧交易使用相同输入
        return false;                // 返回失败，冲突
    }
  }

  // 检查与之前交易的冲突
  map<uint256, CTransaction> mapTestPool; // 测试池，用于模拟连接
  int64 nFees = 0;                        // 交易费用
  if (fCheckInputs)                       // 如果需要检查输入
    if (!TestConnectInputs(txdb, mapTestPool, true, false,
                           nFees)) // 测试连接输入
      return error(
          "AcceptTransaction() : TestConnectInputs failed"); // 返回错误，测试连接失败

  // 将交易存储在内存中
  CRITICAL_BLOCK(cs_mapTransactions) // 在临界区内操作
  {
    if (ptxOld) // 如果有旧版本交易
    {
      printf("mapTransaction.erase(%s) replacing with new version\n",
             ptxOld->GetHash().ToString().c_str());
      mapTransactions.erase(ptxOld->GetHash()); // 从内存池中删除旧版本
    }
    // printf("mapTransaction.insert(%s)\n  ", hash.ToString().c_str());
    // print();
    mapTransactions[hash] = *this;       // 添加新交易到内存池
    for (int i = 0; i < vin.size(); i++) // 遍历所有输入
      mapNextTx[vin[i].prevout] =
          CInPoint(&mapTransactions[hash], i); // 更新mapNextTx映射
  }

  // 如果是更新，从钱包中删除旧交易
  if (ptxOld)                         // 如果有旧版本交易
    CRITICAL_BLOCK(cs_mapWallet)      // 在临界区内操作钱包
  mapWallet.erase(ptxOld->GetHash()); // 删除旧交易

  nTransactionsUpdated++; // 增加交易更新计数
  return true;
}

// 检查交易是否在主链中
int CMerkleTx::IsInMainChain() const {
  if (hashBlock == 0) // 如果没有区块哈希
    return 0;         // 返回0，表示不在主链中

  // 查找交易声称所在的区块
  map<uint256, CBlockIndex *>::iterator mi = mapBlockIndex.find(hashBlock);
  if (mi == mapBlockIndex.end()) // 如果找不到区块索引
    return 0;                    // 返回0
  CBlockIndex *pindex = (*mi).second;
  if (!pindex || !pindex->IsInMainChain()) // 如果区块不在主链中
    return 0;                              // 返回0

  // 获取默克尔根
  CBlock block;                           // 创建区块对象
  if (!block.ReadFromDisk(pindex, false)) // 从磁盘读取区块
    return 0;                             // 返回0

  // 确保默克尔分支连接到这个区块
  if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) !=
      block.hashMerkleRoot) // 验证默克尔分支
    return 0;               // 返回0，表示默克尔分支不匹配

  // 返回确认数（当前最佳区块高度减去交易所在区块高度加1）
  return pindexBest->nHeight - pindex->nHeight + 1;
}

// 接受交易到内存池（默克尔交易版本）
bool CMerkleTx::AcceptTransaction(CTxDB &txdb, bool fCheckInputs) {
  if (fClient) // 如果是客户端模式
  {
    // 如果不在主链中且客户端连接输入失败
    if (!IsInMainChain() && !ClientConnectInputs())
      return false;
    // 接受交易，但不检查输入
    return CTransaction::AcceptTransaction(txdb, false);
  } else // 如果是服务器模式
  {
    // 调用基类方法，根据fCheckInputs决定是否检查输入
    return CTransaction::AcceptTransaction(txdb, fCheckInputs);
  }
}

// 接受钱包交易到内存池
bool CWalletTx::AcceptWalletTransaction(CTxDB &txdb, bool fCheckInputs) {
  foreach (CMerkleTx &tx, vtxPrev) // 遍历支持交易
  {
    uint256 hash = tx.GetHash(); // 获取交易哈希
    // 如果交易不在内存池也不在数据库中
    if (!mapTransactions.count(hash) && !txdb.ContainsTx(hash))
      tx.AcceptTransaction(txdb, fCheckInputs); // 接受支持交易
  }
  // 接受当前交易
  return AcceptTransaction(txdb, fCheckInputs);
}

// 中继钱包交易到网络
void CWalletTx::RelayWalletTransaction(CTxDB &txdb) {
  foreach (CMerkleTx &tx, vtxPrev) // 遍历支持交易
  {
    uint256 hash = tx.GetHash(); // 获取交易哈希
    if (!txdb.ContainsTx(hash))  // 如果交易不在数据库中（即不在区块中）
      RelayMessage(CInv(MSG_TX, hash), (CTransaction)tx); // 中继交易
  }
  uint256 hash = GetHash();   // 获取当前交易哈希
  if (!txdb.ContainsTx(hash)) // 如果交易不在数据库中
    RelayMessage(CInv(MSG_TX, hash), (CTransaction) * this); // 中继当前交易
}

//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex - 区块和区块索引相关函数
//

// 从磁盘读取区块（使用区块索引）
bool CBlock::ReadFromDisk(const CBlockIndex *pblockindex,
                          bool fReadTransactions) {
  // 调用另一个版本的ReadFromDisk，传入文件号和位置
  return ReadFromDisk(pblockindex->nFile, pblockindex->nBlockPos,
                      fReadTransactions);
}

// 计算区块奖励金额
int64 GetBlockValue(int64 nFees) {
  int64 nSubsidy = 10000 * CENT; // 基础奖励为10000分（即100比特币）
  // 每100000个区块减半一次奖励
  for (int i = 100000; i <= nBestHeight; i += 100000)
    nSubsidy /= 2;         // 奖励减半
  return nSubsidy + nFees; // 返回区块奖励（基础奖励+交易费）
}

// 计算下一个区块的工作量证明难度目标
unsigned int GetNextWorkRequired(const CBlockIndex *pindexLast) {
  const unsigned int nTargetTimespan = 30 * 24 * 60 * 60; // 目标时间跨度：30天
  const unsigned int nTargetSpacing = 15 * 60; // 目标出块间隔：15分钟
  const unsigned int nIntervals = nTargetTimespan / nTargetSpacing; // 间隔数量

  // 缓存最近计算的结果
  static const CBlockIndex *pindexLastCache;       // 缓存的最后区块索引
  static unsigned int nBitsCache;                  // 缓存的难度目标
  static CCriticalSection cs_cache;                // 缓存的临界区锁
  CRITICAL_BLOCK(cs_cache)                         // 在临界区内检查缓存
  if (pindexLast && pindexLast == pindexLastCache) // 如果与缓存匹配
    return nBitsCache;                             // 直接返回缓存的结果

  // 回退30天
  const CBlockIndex *pindexFirst = pindexLast;        // 第一个区块索引
  for (int i = 0; pindexFirst && i < nIntervals; i++) // 回退nIntervals个区块
    pindexFirst = pindexFirst->pprev;                 // 前一个区块
  if (pindexFirst == NULL) // 如果找不到足够的历史区块
    return MINPROOFOFWORK; // 返回最小工作量证明难度

  // 加载第一个和最后一个区块
  CBlock blockFirst;                                // 第一个区块
  if (!blockFirst.ReadFromDisk(pindexFirst, false)) // 读取失败
    throw runtime_error(
        "GetNextWorkRequired() : blockFirst.ReadFromDisk failed\n");
  CBlock blockLast;                               // 最后一个区块
  if (!blockLast.ReadFromDisk(pindexLast, false)) // 读取失败
    throw runtime_error(
        "GetNextWorkRequired() : blockLast.ReadFromDisk failed\n");

  // 限制每次时间跨度内的难度变化
  unsigned int nBits = blockLast.nBits;    // 当前难度目标
  if (blockFirst.nBits == blockLast.nBits) // 如果难度目标未变
  {
    unsigned int nTimespan = blockLast.nTime - blockFirst.nTime; // 实际时间跨度
    if (nTimespan > nTargetTimespan * 2 &&
        nBits >= MINPROOFOFWORK) // 如果出块太慢，降低难度
      nBits--;                   // 难度降低（nBits减小表示难度降低）
    else if (nTimespan < nTargetTimespan / 2) // 如果出块太快，增加难度
      nBits++; // 难度增加（nBits增大表示难度增加）
  }

  CRITICAL_BLOCK(cs_cache) // 更新缓存
  {
    pindexLastCache = pindexLast; // 更新缓存的区块索引
    nBitsCache = nBits;           // 更新缓存的难度目标
  }
  return nBits; // 返回计算后的难度目标
}

// 获取孤立链的根区块哈希
uint256 GetOrphanRoot(const CBlock *pblock) {
  // 回溯到孤立链中的第一个区块
  while (
      mapOrphanBlocks.count(pblock->hashPrevBlock))  // 如果前一个区块也是孤立的
    pblock = mapOrphanBlocks[pblock->hashPrevBlock]; // 移动到前一个区块
  return pblock->hashPrevBlock; // 返回孤立链第一个区块的前一个区块哈希
}

// 测试断开区块连接（用于回滚）
bool CBlock::TestDisconnectBlock(CTxDB &txdb,
                                 map<uint256, CTransaction> &mapTestPool) {
  foreach (CTransaction &tx, vtx)                    // 遍历区块中的所有交易
    if (!tx.TestDisconnectInputs(txdb, mapTestPool)) // 测试断开交易输入
      return false; // 如果有任何交易断开失败，返回false
  return true;      // 所有交易断开成功
}

// 测试连接区块（用于验证）
bool CBlock::TestConnectBlock(CTxDB &txdb,
                              map<uint256, CTransaction> &mapTestPool) {
  int64 nFees = 0;                // 交易费用
  foreach (CTransaction &tx, vtx) // 遍历区块中的所有交易
    if (!tx.TestConnectInputs(txdb, mapTestPool, false, false,
                              nFees)) // 测试连接交易输入
      return false;                   // 如果有任何交易连接失败，返回false

  // 验证coinbase交易的输出金额是否等于区块奖励
  if (vtx[0].GetValueOut() != GetBlockValue(nFees)) // 检查coinbase交易输出金额
    return false;                                   // 金额不匹配，返回false
  return true;                                      // 区块验证成功
}

// 断开区块连接（实际执行回滚）
bool CBlock::DisconnectBlock() {
  CTxDB txdb;                       // 交易数据库
  foreach (CTransaction &tx, vtx)   // 遍历区块中的所有交易
    if (!tx.DisconnectInputs(txdb)) // 断开交易输入
      return false;                 // 如果有任何交易断开失败，返回false
  return true;                      // 所有交易断开成功
}

// 连接区块（实际执行添加）
bool CBlock::ConnectBlock(unsigned int nFile, unsigned int nBlockPos,
                          int nHeight) {
  //// 这里有个问题：不知道版本号
  // 计算第一个交易的位置
  unsigned int nTxPos = nBlockPos + ::GetSerializeSize(CBlock(), SER_DISK) - 1 +
                        GetSizeOfCompactSize(vtx.size());

  CTxDB txdb;                     // 交易数据库
  foreach (CTransaction &tx, vtx) // 遍历区块中的所有交易
  {
    CDiskTxPos posThisTx(nFile, nBlockPos, nTxPos); // 当前交易的位置
    nTxPos += ::GetSerializeSize(tx, SER_DISK);     // 更新下一个交易的位置

    if (!tx.ConnectInputs(txdb, posThisTx, nHeight)) // 连接交易输入
      return false;                                  // 如果连接失败，返回false
  }
  txdb.Close(); // 关闭数据库

  // 监控支付给我的交易
  foreach (CTransaction &tx, vtx) // 遍历区块中的所有交易
    AddToWalletIfMine(tx, this);  // 如果交易属于我，添加到钱包

  return true; // 区块连接成功
}

// 重组区块链（处理链分叉）
bool Reorganize(CBlockIndex *pindexNew, bool fWriteDisk) {
  // 查找分叉点
  CBlockIndex *pfork = pindexBest;  // 当前最佳链的分叉点
  CBlockIndex *plonger = pindexNew; // 新的更长链
  while (pfork != plonger)          // 直到找到共同的祖先区块
  {
    if (!(pfork = pfork->pprev)) // 如果回溯完当前链仍未找到共同祖先
      return false;              // 返回失败
    while (plonger->nHeight > pfork->nHeight) // 如果新链更高
      if (!(plonger = plonger->pprev))        // 回溯新链
        return false;                         // 返回失败
  }

  // 要断开连接的区块列表
  vector<CBlockIndex *> vDisconnect; // 存储需要断开的区块
  for (CBlockIndex *pindex = pindexBest; pindex != pfork;
       pindex = pindex->pprev)     // 从当前最佳区块回溯到分叉点
    vDisconnect.push_back(pindex); // 添加到断开列表

  // 要连接的区块列表
  vector<CBlockIndex *> vConnect; // 存储需要连接的区块
  for (CBlockIndex *pindex = pindexNew; pindex != pfork;
       pindex = pindex->pprev)               // 从新链回溯到分叉点
    vConnect.push_back(pindex);              // 添加到连接列表
  reverse(vConnect.begin(), vConnect.end()); // 反转顺序，使连接顺序正确

  // 预测试重组
  if (fWriteDisk) // 如果需要写入磁盘
  {
    CTxDB txdb("r");                        // 以只读模式打开交易数据库
    map<uint256, CTransaction> mapTestPool; // 测试池

    foreach (CBlockIndex *pindex, vDisconnect) // 测试断开所有区块
      if (!pindex->TestDisconnectBlock(txdb,
                                       mapTestPool)) // 如果任何区块断开测试失败
        return false;                                // 返回失败

    bool fValid = true;                     // 有效性标志
    foreach (CBlockIndex *pindex, vConnect) // 测试连接所有区块
    {
      fValid =
          fValid && pindex->TestConnectBlock(txdb, mapTestPool); // 连接测试
      if (!fValid)                                               // 如果区块无效
      {
        // 无效区块，删除该分支的其余部分
        CBlock block;                         // 创建区块对象
        block.ReadFromDisk(pindex, false);    // 读取区块
        pindex->EraseBlockFromDisk();         // 从磁盘删除区块
        mapBlockIndex.erase(block.GetHash()); // 从区块索引中删除
        delete pindex;                        // 删除区块索引对象
      }
    }
    if (!fValid)    // 如果有无效区块
      return false; // 返回失败
  }

  // 断开较短的分支
  foreach (CBlockIndex *pindex, vDisconnect) // 遍历需要断开的区块
  {
    if (fWriteDisk && !pindex->DisconnectBlock()) // 如果需要写入磁盘且断开失败
      return false;                               // 返回失败
    if (pindex->pprev)                            // 如果有前一个区块
      pindex->pprev->pnext = NULL;                // 断开链接
  }

  // 连接较长的分支
  foreach (CBlockIndex *pindex, vConnect) // 遍历需要连接的区块
  {
    if (fWriteDisk && !pindex->ConnectBlock()) // 如果需要写入磁盘且连接失败
      return false;                            // 返回失败
    if (pindex->pprev)                         // 如果有前一个区块
      pindex->pprev->pnext = pindex;           // 建立链接
  }

  return true; // 重组成功
}

// 将区块添加到区块索引
bool CBlock::AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos,
                             bool fWriteDisk) {
  uint256 hash = GetHash(); // 获取区块哈希

  // 添加到区块索引
  CBlockIndex *pindexNew = new CBlockIndex(nFile, nBlockPos); // 创建新区块索引
  if (!pindexNew)                  // 如果内存分配失败
    return false;                  // 返回失败
  mapBlockIndex[hash] = pindexNew; // 添加到区块索引映射
  // 查找前一个区块的索引
  map<uint256, CBlockIndex *>::iterator mi = mapBlockIndex.find(hashPrevBlock);
  if (mi != mapBlockIndex.end()) // 如果找到前一个区块
  {
    pindexNew->pprev = (*mi).second;                    // 设置前一个区块指针
    pindexNew->nHeight = pindexNew->pprev->nHeight + 1; // 设置区块高度
  }

  // 新的最佳区块
  if (pindexNew->nHeight > nBestHeight) // 如果新区块高度大于当前最佳区块
  {
    if (pindexGenesisBlock == NULL &&
        hash == hashGenesisBlock) // 如果是创世区块
    {
      pindexGenesisBlock = pindexNew;              // 设置创世区块索引
    } else if (hashPrevBlock == hashTimeChainBest) // 如果添加到当前最佳链
    {
      // 添加到当前最佳分支
      if (fWriteDisk)                      // 如果需要写入磁盘
        if (!pindexNew->ConnectBlock())    // 连接区块失败
          return false;                    // 返回失败
      pindexNew->pprev->pnext = pindexNew; // 建立链接
    } else                                 // 如果是新的最佳分支
    {
      // 新的最佳分支
      if (!Reorganize(pindexNew, fWriteDisk)) // 重组失败
        return false;                         // 返回失败
    }

    // 更新最佳链接信息
    nBestHeight = pindexNew->nHeight; // 更新最佳高度
    hashTimeChainBest = hash;         // 更新最佳区块哈希
    pindexBest = pindexNew;           // 更新最佳区块索引
    nTransactionsUpdated++;           // 增加交易更新计数

    // 中继尚未进入区块的钱包交易
    if (fWriteDisk && nTime > GetAdjustedTime() - 30 * 60) // 如果是近期区块
      RelayWalletTransactions();                           // 中继钱包交易
  }

  MainFrameRepaint(); // 刷新主窗口
  return true;        // 添加成功
}

// 扫描消息起始标记（用于文件解析）
template <typename Stream> bool ScanMessageStart(Stream &s) {
  // 向前扫描下一个pchMessageStart，通常应该紧跟在文件指针位置
  // 扫描完成后，文件指针位于pchMessageStart的末尾
  s.clear(0);                             // 清除错误标志
  short prevmask = s.exceptions(0);       // 保存之前的异常掩码
  const char *p = BEGIN(pchMessageStart); // 指向消息起始标记的开头
  try {
    loop // 无限循环直到找到完整标记或失败
    {
      char c;        // 当前读取的字符
      s.read(&c, 1); // 读取一个字符
      if (s.fail())  // 如果读取失败
      {
        s.clear(0);             // 清除错误标志
        s.exceptions(prevmask); // 恢复异常掩码
        return false;           // 返回失败
      }
      if (*p != c)                  // 如果字符不匹配
        p = BEGIN(pchMessageStart); // 重置指针到起始位置
      if (*p == c)                  // 如果字符匹配
      {
        if (++p == END(pchMessageStart)) // 如果找到了完整标记
        {
          s.clear(0);             // 清除错误标志
          s.exceptions(prevmask); // 恢复异常掩码
          return true;            // 返回成功
        }
      }
    }
  } catch (...) // 捕获任何异常
  {
    s.clear(0);             // 清除错误标志
    s.exceptions(prevmask); // 恢复异常掩码
    return false;           // 返回失败
  }
}

// 打开区块文件
FILE *OpenBlockFile(unsigned int nFile, unsigned int nBlockPos,
                    const char *pszMode) {
  if (nFile == -1) // 如果文件号无效
    return NULL;   // 返回NULL
  // 打开文件，文件名格式为blkNNNN.dat
  FILE *file = fopen(strprintf("blk%04d.dat", nFile).c_str(), pszMode);
  if (!file)     // 如果文件打开失败
    return NULL; // 返回NULL
  // 如果需要定位到特定位置
  if (nBlockPos != 0 && !strchr(pszMode, 'a') && !strchr(pszMode, 'w')) {
    if (fseek(file, nBlockPos, SEEK_SET) != 0) // 定位失败
    {
      fclose(file); // 关闭文件
      return NULL;  // 返回NULL
    }
  }
  return file; // 返回文件指针
}

static unsigned int nCurrentBlockFile = 1; // 当前区块文件号

// 追加区块文件（创建新文件或继续使用现有文件）
FILE *AppendBlockFile(unsigned int &nFileRet) {
  nFileRet = 0; // 初始化返回的文件号
  loop          // 无限循环直到成功
  {
    // 打开当前文件用于追加
    FILE *file = OpenBlockFile(nCurrentBlockFile, 0, "ab");
    if (!file)                         // 如果文件打开失败
      return NULL;                     // 返回NULL
    if (fseek(file, 0, SEEK_END) != 0) // 定位到文件末尾失败
      return NULL;                     // 返回NULL
    // FAT32文件大小最大4GB，fseek和ftell最大2GB，所以我们必须保持在2GB以下
    if (ftell(file) < 0x7F000000 - MAX_SIZE) // 如果文件大小足够小
    {
      nFileRet = nCurrentBlockFile; // 设置返回的文件号
      return file;                  // 返回文件指针
    }
    fclose(file);        // 文件太大，关闭当前文件
    nCurrentBlockFile++; // 尝试下一个文件号
  }
}

// 加载区块索引
bool LoadBlockIndex(bool fAllowNew) {
  //
  // 从磁盘加载
  //
  for (nCurrentBlockFile = 1;; nCurrentBlockFile++) // 遍历所有区块文件
  {
    CAutoFile filein =
        OpenBlockFile(nCurrentBlockFile, 0, "rb"); // 以二进制只读模式打开文件
    if (filein == NULL)                            // 如果文件打开失败
    {
      if (nCurrentBlockFile > 1) // 如果当前文件号大于1
      {
        nCurrentBlockFile--; // 回退到上一个文件号
        break;               // 退出循环
      }
      if (!fAllowNew) // 如果不允许创建新文件
        return false; // 返回失败

      // 创世区块的详细信息（调试信息）
      // 创世区块包含的关键信息：哈希值、前一个区块哈希（0）、默克尔根、时间戳、难度目标、随机数等

      // 创建创世区块
      CTransaction txNew;   // 交易对象
      txNew.vin.resize(1);  // 设置输入数量为1（coinbase交易）
      txNew.vout.resize(1); // 设置输出数量为1
      txNew.vin[0].scriptSig = CScript() << 247422313; // 设置coinbase脚本签名
      txNew.vout[0].nValue = 10000; // 设置输出金额为10000（初始区块奖励）
      txNew.vout[0].scriptPubKey =
          CScript() << OP_CODESEPARATOR
                    << CBigNum("0x31D18A083F381B4BDE37B649AACF8CD0AFD88C53A3587"
                               "ECDB7FAF23D449C800AF1CE516199390BFE42991F10E7F5"
                               "340F2A63449F0B639A7115C667E5D7B051D404")
                    << OP_CHECKSIG; // 设置输出脚本
      CBlock block;                 // 创建区块对象
      block.vtx.push_back(txNew);   // 添加交易到区块
      block.hashPrevBlock = 0;      // 创世区块没有前一个区块，设置为0
      block.hashMerkleRoot =
          block.BuildMerkleTree(); // 构建默克尔树并设置默克尔根
      block.nTime = 1221069728;    // 设置时间戳（2008-08-26 15:15:28 UTC）
      block.nBits = 20;            // 设置难度目标
      block.nNonce = 141755;       // 设置nonce值

      // 调试输出，验证创世区块的关键值
      printf("%s\n", block.GetHash().ToString().c_str());
      printf("%s\n", block.hashMerkleRoot.ToString().c_str());
      printf("%s\n", hashGenesisBlock.ToString().c_str());
      txNew.vout[0].scriptPubKey.print();
      block.print();
      assert(block.hashMerkleRoot ==
             uint256("0x769a5e93fac273fd825da42d39ead975b5d712b2d50953f35a4fdeb"
                     "dec8083e3")); // 验证默克尔根

      assert(block.GetHash() == hashGenesisBlock); // 验证区块哈希

      // 开始新的区块文件
      unsigned int nFile;                                 // 文件号
      unsigned int nBlockPos;                             // 区块位置
      if (!block.WriteToDisk(true, nFile, nBlockPos))     // 写入磁盘失败
        return false;                                     // 返回失败
      if (!block.AddToBlockIndex(nFile, nBlockPos, true)) // 添加到区块索引失败
        return false;                                     // 返回失败
      break;                                              // 退出循环
    }

    int nFilesize = GetFilesize(filein); // 获取文件大小
    if (nFilesize == -1)                 // 如果获取文件大小失败
      return false;                      // 返回失败
    filein.nType |= SER_BLOCKHEADERONLY; // 设置文件类型为仅读取区块头

    while (ScanMessageStart(filein)) // 扫描消息起始标记
    {
      // 读取索引头
      unsigned int nSize; // 区块大小
      filein >> nSize;    // 读取区块大小
      if (nSize > MAX_SIZE ||
          ftell(filein) + nSize > nFilesize) // 如果区块大小超出限制
        continue;                            // 跳过这个区块

      // 读取区块头
      int nBlockPos = ftell(filein); // 记录区块位置
      CBlock block;                  // 创建区块对象
      filein >> block;               // 读取区块

      // 跳过交易数据
      if (fseek(filein, nBlockPos + nSize, SEEK_SET) !=
          0)   // 定位到下一个区块失败
        break; // 退出循环

      // 添加到区块索引，但不更新磁盘
      if (!block.AddToBlockIndex(nCurrentBlockFile, nBlockPos,
                                 false)) // 添加失败
        return false;                    // 返回失败
    }
  }
  return true; // 加载成功
}

// 打印区块链结构（用于调试）
void PrintTimechain() {
  // 预计算树结构
  map<CBlockIndex *, vector<CBlockIndex *>>
      mapNext; // 存储每个区块索引的下一个区块
  for (map<uint256, CBlockIndex *>::iterator mi = mapBlockIndex.begin();
       mi != mapBlockIndex.end(); ++mi) // 遍历所有区块索引
  {
    CBlockIndex *pindex = (*mi).second;       // 获取区块索引
    mapNext[pindex->pprev].push_back(pindex); // 记录前一个区块索引的下一个区块
  }

  vector<pair<int, CBlockIndex *>> vStack;            // 用于遍历树结构的栈
  vStack.push_back(make_pair(0, pindexGenesisBlock)); // 从创世区块开始

  int nPrevCol = 0;       // 前一列的位置
  while (!vStack.empty()) // 当栈不为空时
  {
    int nCol = vStack.back().first;             // 当前列位置
    CBlockIndex *pindex = vStack.back().second; // 当前区块索引
    vStack.pop_back();                          // 弹出栈顶元素

    // 打印分隔符或间隙
    if (nCol > nPrevCol) // 如果当前列在前一列的右边
    {
      for (int i = 0; i < nCol - 1; i++) // 打印左边的连接线
        printf("| ");
      printf("|\\\n");          // 打印向右的分支
    } else if (nCol < nPrevCol) // 如果当前列在前一列的左边
    {
      for (int i = 0; i < nCol; i++) // 打印左边的连接线
        printf("| ");
      printf("|\n"); // 打印垂直线
    }
    nPrevCol = nCol; // 更新前一列位置

    // 打印列
    for (int i = 0; i < nCol; i++) // 打印每列的连接线
      printf("| ");

    // 打印区块信息（高度和文件位置）
    printf("%d (%u,%u)\n", pindex->nHeight, pindex->nFile, pindex->nBlockPos);

    // 将主时间链放在最前面
    vector<CBlockIndex *> &vNext =
        mapNext[pindex];                   // 获取当前区块的下一个区块列表
    for (int i = 0; i < vNext.size(); i++) // 遍历下一个区块列表
    {
      if (vNext[i]->pnext) // 如果是主链上的区块
      {
        swap(vNext[0], vNext[i]); // 交换到第一位
        break;                    // 跳出循环
      }
    }

    // 迭代子区块
    for (int i = 0; i < vNext.size(); i++)             // 遍历下一个区块列表
      vStack.push_back(make_pair(nCol + i, vNext[i])); // 添加到栈中
  }
}

// 检查区块是否有效
bool CBlock::CheckBlock() const {
  // 大小限制检查
  if (vtx.empty() || vtx.size() > MAX_SIZE ||
      ::GetSerializeSize(*this, SER_DISK) > MAX_SIZE)  // 检查交易数量和区块大小
    return error("CheckBlock() : size limits failed"); // 返回错误

  // 检查时间戳
  if (nTime > GetAdjustedTime() + 36 * 60 * 60) // 如果时间戳超过当前时间+36小时
    return error("CheckBlock() : block timestamp out of range"); // 返回错误

  // 检查工作量证明是否匹配声明的难度
  if (nBits < MINPROOFOFWORK)                           // 如果难度低于最小值
    return error("CheckBlock() : nBits below minimum"); // 返回错误
  if (GetHash() > (~uint256(0) >> nBits)) // 如果哈希值不满足难度要求
    return error("CheckBlock() : hash doesn't match nBits"); // 返回错误

  // 第一个交易必须是coinbase，其余交易不能是coinbase
  if (vtx.empty() ||
      !vtx[0].IsCoinBase()) // 如果没有交易或第一个交易不是coinbase
    return error("CheckBlock() : first tx is not coinbase"); // 返回错误
  for (int i = 1; i < vtx.size(); i++)                       // 遍历其余交易
    if (vtx[i].IsCoinBase()) // 如果有其他coinbase交易
      return error("CheckBlock() : more than one coinbase"); // 返回错误

  // 检查交易有效性
  foreach (const CTransaction &tx, vtx) // 遍历所有交易
    if (!tx.CheckTransaction())         // 如果交易检查失败
      return error("CheckBlock() : CheckTransaction failed"); // 返回错误

  // 检查默克尔根
  if (hashMerkleRoot != BuildMerkleTree()) // 如果默克尔根不匹配
    return error("CheckBlock() : hashMerkleRoot mismatch"); // 返回错误

  return true; // 区块有效
}

// 接受区块（写入磁盘并添加到区块索引）
bool CBlock::AcceptBlock() {
  // 检查重复
  uint256 hash = GetHash();      // 获取区块哈希
  if (mapBlockIndex.count(hash)) // 如果区块已在索引中
    return false;                // 返回失败

  // 获取前一个区块的索引
  map<uint256, CBlockIndex *>::iterator mi =
      mapBlockIndex.find(hashPrevBlock);  // 查找前一个区块
  if (mi == mapBlockIndex.end())          // 如果找不到前一个区块
    return false;                         // 返回失败
  CBlockIndex *pindexPrev = (*mi).second; // 获取前一个区块索引

  // 检查时间戳是否大于前一个区块
  CBlock blockPrev;                               // 创建前一个区块对象
  if (!blockPrev.ReadFromDisk(pindexPrev, false)) // 读取前一个区块失败
    return false;                                 // 返回失败
  if (nTime <= blockPrev.nTime)                   // 如果时间戳不大于前一个区块
    return false;                                 // 返回失败

  // 检查工作量证明难度
  if (nBits != GetNextWorkRequired(pindexPrev)) // 如果难度不匹配
    return false;                               // 返回失败

  // 检查交易输入并验证签名
  {
    CTxDB txdb("r");                        // 以只读模式打开交易数据库
    map<uint256, CTransaction> mapTestPool; // 测试池
    bool fIgnoreDiskConflicts =
        (hashPrevBlock != hashTimeChainBest); // 是否忽略磁盘冲突
    int64 nFees = 0;                          // 交易费用
    foreach (CTransaction &tx, vtx)           // 遍历所有交易
      if (!tx.TestConnectInputs(txdb, mapTestPool, false, fIgnoreDiskConflicts,
                                nFees)) // 测试连接输入失败
        return error("AcceptBlock() : TestConnectInputs failed"); // 返回错误
    if (vtx[0].GetValueOut() !=
        GetBlockValue(nFees)) // 如果coinbase交易输出金额不匹配
      return false;           // 返回失败
  }

  // 写入区块到历史文件
  unsigned int nFile;                           // 文件号
  unsigned int nBlockPos;                       // 区块位置
  if (!WriteToDisk(!fClient, nFile, nBlockPos)) // 写入磁盘失败
    return false;                               // 返回失败
  if (!AddToBlockIndex(nFile, nBlockPos, true)) // 添加到区块索引失败
    return false;                               // 返回失败

  if (hashTimeChainBest == hash)           // 如果是新的最佳区块
    RelayInventory(CInv(MSG_BLOCK, hash)); // 中继区块到网络

  // 为新创建的硬币添加原子到用户评论
  vector<unsigned char> vchPubKey; // 公钥
  if (ExtractPubKey(vtx[0].vout[0].scriptPubKey, false,
                    vchPubKey)) // 提取公钥成功
  {
    uint64 nRand = 0;                                       // 随机数
    RAND_bytes((unsigned char *)&nRand, sizeof(nRand));     // 生成随机数
    unsigned short nAtom = nRand % (USHRT_MAX - 100) + 100; // 计算原子值
    vector<unsigned short> vAtoms(1, nAtom);                // 原子向量
    AddAtomsAndPropagate(Hash(vchPubKey.begin(), vchPubKey.end()), vAtoms,
                         true); // 添加原子并传播
  }

  return true; // 接受成功
}

// 处理接收到的区块
bool ProcessBlock(CNode *pfrom, CBlock *pblock) {
  // 检查重复
  uint256 hash = pblock->GetHash(); // 获取区块哈希
  if (mapBlockIndex.count(hash) ||
      mapOrphanBlocks.count(hash)) // 如果区块已在索引中或孤立区块中
    return false;                  // 返回失败

  // 初步检查
  if (!pblock->CheckBlock()) // 如果区块检查失败
  {
    printf("CheckBlock FAILED\n"); // 打印错误信息
    delete pblock;                 // 删除区块对象
    return false;                  // 返回失败
  }

  // 如果还没有前一个区块，将其放入孤立区块区域，直到获取前一个区块
  if (!mapBlockIndex.count(pblock->hashPrevBlock)) // 如果找不到前一个区块
  {
    mapOrphanBlocks.insert(make_pair(hash, pblock)); // 添加到孤立区块映射
    mapOrphanBlocksByPrev.insert(make_pair(
        pblock->hashPrevBlock, pblock)); // 通过前一个区块哈希索引孤立区块

    // 要求节点填充缺失的区块
    if (pfrom) // 如果有发送方
      pfrom->PushMessage("getblocks", CBlockLocator(pindexBest),
                         GetOrphanRoot(pblock)); // 请求区块
    return true; // 返回成功（区块已添加到孤立区块）
  }

  // 存储到磁盘
  if (!pblock->AcceptBlock()) // 如果接受区块失败
  {
    printf("AcceptBlock FAILED\n"); // 打印错误信息
    delete pblock;                  // 删除区块对象
    return false;                   // 返回失败
  }
  delete pblock; // 删除区块对象

  // 处理依赖于此区块的孤立区块
  for (multimap<uint256, CBlock *>::iterator mi =
           mapOrphanBlocksByPrev.lower_bound(
               hash); // 查找所有前一个区块哈希为此区块的孤立区块
       mi != mapOrphanBlocksByPrev.upper_bound(hash); ++mi) {
    CBlock *pblockOrphan = (*mi).second;            // 获取孤立区块
    pblockOrphan->AcceptBlock();                    // 尝试接受孤立区块
    mapOrphanBlocks.erase(pblockOrphan->GetHash()); // 从孤立区块映射中删除
    delete pblockOrphan;                            // 删除孤立区块对象
  }
  mapOrphanBlocksByPrev.erase(hash); // 从索引中删除

  return true; // 处理成功
}

//////////////////////////////////////////////////////////////////////////////
//
// Messages - 网络消息处理
//

// 检查是否已经拥有指定的库存项
bool AlreadyHave(const CInv &inv) {
  switch (inv.type) // 根据库存类型检查
  {
  case MSG_TX:
    return mapTransactions.count(inv.hash); // 交易检查
  case MSG_BLOCK:
    return mapBlockIndex.count(inv.hash) ||
           mapOrphanBlocks.count(inv.hash); // 区块检查
  case MSG_REVIEW:
    return true; // 评论总是返回true
  case MSG_PRODUCT:
    return mapProducts.count(inv.hash); // 产品检查
  case MSG_TABLE:
    return mapTables.count(inv.hash); // 表格检查
  }
  // 未知类型，默认返回true
  return true;
}

// 处理接收到的消息
bool ProcessMessages(CNode *pfrom) {
  CDataStream &vRecv = pfrom->vRecv;                   // 接收缓冲区
  if (vRecv.empty())                                   // 如果缓冲区为空
    return true;                                       // 返回成功
  printf("ProcessMessages(%d bytes)\n", vRecv.size()); // 打印消息大小

  //
  // 消息格式
  //  (4) message start - 消息起始标记
  //  (12) command - 命令
  //  (4) size - 大小
  //  (x) data - 数据
  //

  loop // 无限循环处理消息
  {
    // 扫描消息起始标记
    CDataStream::iterator pstart =
        search(vRecv.begin(), vRecv.end(), BEGIN(pchMessageStart),
               END(pchMessageStart));                  // 查找消息起始标记
    if (vRecv.end() - pstart < sizeof(CMessageHeader)) // 如果没有足够的数据
    {
      if (vRecv.size() > sizeof(CMessageHeader)) // 如果缓冲区大小大于消息头大小
      {
        printf("\n\nPROCESSMESSAGE MESSAGESTART NOT FOUND\n\n"); // 打印错误信息
        vRecv.erase(vRecv.begin(),
                    vRecv.end() -
                        sizeof(CMessageHeader)); // 保留部分数据以便下次处理
      }
      break; // 退出循环
    }
    if (pstart - vRecv.begin() > 0) // 如果有跳过的字节
      printf("\n\nPROCESSMESSAGE SKIPPED %d BYTES\n\n",
             pstart - vRecv.begin());   // 打印跳过的字节数
    vRecv.erase(vRecv.begin(), pstart); // 清除起始标记前的数据

    // 读取消息头
    CMessageHeader hdr; // 消息头对象
    vRecv >> hdr;       // 读取消息头
    if (!hdr.IsValid()) // 如果消息头无效
    {
      printf("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n",
             hdr.GetCommand().c_str()); // 打印错误信息
      continue;                         // 继续处理下一条消息
    }
    string strCommand = hdr.GetCommand(); // 获取命令

    // 消息大小
    unsigned int nMessageSize = hdr.nMessageSize; // 获取消息大小
    if (nMessageSize > vRecv.size())              // 如果没有足够的数据
    {
      // 倒回并等待消息的其余部分
      printf("MESSAGE-BREAK 2\n");                       // 打印断点信息
      vRecv.insert(vRecv.begin(), BEGIN(hdr), END(hdr)); // 将消息头放回缓冲区
      break;                                             // 退出循环
    }

    // 复制消息到自己的缓冲区
    CDataStream vMsg(vRecv.begin(), vRecv.begin() + nMessageSize, vRecv.nType,
                     vRecv.nVersion); // 创建消息数据流
    vRecv.ignore(nMessageSize);       // 忽略已读取的数据

    // 处理消息
    bool fRet = false; // 返回值
    try {
      fRet = ProcessMessage(pfrom, strCommand, vMsg); // 调用具体的消息处理函数
    }
    CATCH_PRINT_EXCEPTION("ProcessMessage()") // 捕获并打印异常
    if (!fRet)                                // 如果处理失败
      printf("ProcessMessage(%s, %d bytes) from %s to %s FAILED\n",
             strCommand.c_str(), nMessageSize, pfrom->addr.ToString().c_str(),
             addrLocalHost.ToString().c_str()); // 打印失败信息
  }

  vRecv.Compact(); // 压缩缓冲区
  return true;     // 处理成功
}

// 处理具体的消息
bool ProcessMessage(CNode *pfrom, string strCommand, CDataStream &vRecv) {
  static map<unsigned int, vector<unsigned char>> mapReuseKey; // 复用密钥映射
  CheckForShutdown(2); // 检查是否需要关闭
  printf("received: %-12s (%d bytes)  ", strCommand.c_str(),
         vRecv.size()); // 打印接收到的命令和大小
  for (int i = 0; i < min(vRecv.size(), (unsigned int)25);
       i++) // 打印前25个字节的十六进制表示
    printf("%02x ", vRecv[i] & 0xff);
  printf("\n"); // 换行

  if (strCommand == "version") // 处理版本消息
  {
    // 只能处理一次
    if (pfrom->nVersion != 0) // 如果已经有版本信息
      return false;           // 返回失败

    unsigned int nTime; // 时间戳
    vRecv >> pfrom->nVersion >> pfrom->nServices >>
        nTime;                // 读取版本、服务和时间
    if (pfrom->nVersion == 0) // 如果版本为0
      return false;           // 返回失败

    pfrom->vSend.SetVersion(min(pfrom->nVersion, VERSION)); // 设置发送版本
    pfrom->vRecv.SetVersion(min(pfrom->nVersion, VERSION)); // 设置接收版本

    pfrom->fClient = !(pfrom->nServices & NODE_NETWORK); // 确定是否为客户端模式
    if (pfrom->fClient)                                  // 如果是客户端模式
    {
      pfrom->vSend.nType |= SER_BLOCKHEADERONLY; // 设置仅发送区块头
      pfrom->vRecv.nType |= SER_BLOCKHEADERONLY; // 设置仅接收区块头
    }

    AddTimeData(pfrom->addr.ip, nTime); // 添加时间数据

    // 向第一个连接的节点请求区块更新
    static bool fAskedForBlocks;             // 是否已经请求过区块
    if (!fAskedForBlocks && !pfrom->fClient) // 如果还没有请求且不是客户端
    {
      fAskedForBlocks = true; // 设置已请求标志
      pfrom->PushMessage("getblocks", CBlockLocator(pindexBest),
                         uint256(0)); // 请求区块
    }
  }

  else if (pfrom->nVersion == 0) // 如果没有版本消息
  {
    // 必须先有版本消息
    return false; // 返回失败
  }

  else if (strCommand == "addr") // 处理地址消息
  {
    vector<CAddress> vAddr; // 地址向量
    vRecv >> vAddr;         // 读取地址列表

    // 存储新地址
    CAddrDB addrdb;                       // 地址数据库
    foreach (const CAddress &addr, vAddr) // 遍历所有地址
    {
      if (AddAddress(addrdb, addr)) // 如果添加地址成功
      {
        // 添加到发送给其他节点的列表
        pfrom->setAddrKnown.insert(addr);       // 标记为已知地址
        CRITICAL_BLOCK(cs_vNodes)               // 在临界区内操作
        foreach (CNode *pnode, vNodes)          // 遍历所有节点
          if (!pnode->setAddrKnown.count(addr)) // 如果节点不知道该地址
            pnode->vAddrToSend.push_back(addr); // 添加到发送列表
      }
    }
  }

  else if (strCommand == "inv") // 处理库存消息
  {
    vector<CInv> vInv; // 库存向量
    vRecv >> vInv;     // 读取库存列表

    foreach (const CInv &inv, vInv) // 遍历所有库存项
    {
      printf("  got inventory: %s  %s\n", inv.ToString().c_str(),
             AlreadyHave(inv) ? "have" : "new"); // 打印库存项信息和是否已拥有

      CRITICAL_BLOCK(pfrom->cs_inventory)   // 临界区保护库存状态
      pfrom->setInventoryKnown.insert(inv); // 标记为已知库存

      if (!AlreadyHave(inv)) // 如果没有此库存项
        pfrom->AskFor(inv);  // 请求获取该库存项
      else if (inv.type == MSG_BLOCK &&
               mapOrphanBlocks.count(inv.hash)) // 如果是区块且在孤立区块中
        pfrom->PushMessage(
            "getblocks", CBlockLocator(pindexBest),
            GetOrphanRoot(mapOrphanBlocks[inv.hash])); // 请求孤立区块的根区块
    }
  }

  else if (strCommand == "getdata") // 处理获取数据消息
  {
    vector<CInv> vInv; // 库存向量
    vRecv >> vInv;     // 读取库存列表

    foreach (const CInv &inv, vInv) // 遍历所有库存项
    {
      printf("received getdata for: %s\n",
             inv.ToString().c_str()); // 打印获取数据请求

      if (inv.type == MSG_BLOCK) // 如果是区块
      {
        // 从磁盘发送区块
        map<uint256, CBlockIndex *>::iterator mi =
            mapBlockIndex.find(inv.hash); // 查找区块索引
        if (mi != mapBlockIndex.end())    // 如果找到
        {
          CBlock block;                                      // 区块对象
          block.ReadFromDisk((*mi).second, !pfrom->fClient); // 读取区块数据
          pfrom->PushMessage("block", block);                // 发送区块
        }
      } else if (inv.IsKnownType()) // 如果是已知类型
      {
        // 从中继内存发送数据流
        CRITICAL_BLOCK(cs_mapRelay) // 临界区保护中继映射
        {
          map<CInv, CDataStream>::iterator mi =
              mapRelay.find(inv);                               // 查找中继数据
          if (mi != mapRelay.end())                             // 如果找到
            pfrom->PushMessage(inv.GetCommand(), (*mi).second); // 发送数据
        }
      }
    }
  }

  else if (strCommand == "getblocks") // 处理获取区块消息
  {
    CBlockLocator locator;        // 区块定位器
    uint256 hashStop;             // 停止区块哈希
    vRecv >> locator >> hashStop; // 读取定位器和停止哈希

    // 找到调用者在主链上拥有的第一个区块
    CBlockIndex *pindex = locator.GetBlockIndex(); // 获取区块索引

    // 发送链的其余部分
    if (pindex)                            // 如果找到了区块
      pindex = pindex->pnext;              // 移动到下一个区块
    for (; pindex; pindex = pindex->pnext) // 遍历后续区块
    {
      CBlock block;                                // 区块对象
      block.ReadFromDisk(pindex, !pfrom->fClient); // 读取区块数据
      if (block.GetHash() == hashStop)             // 如果到达停止区块
        break;                                     // 退出循环
      pfrom->PushMessage("block", block);          // 发送区块
    }
  }

  else if (strCommand == "getmywtxes") // 处理获取钱包交易消息
  {
    CBlockLocator locator;             // 区块定位器
    vector<uint160> vPubKeyHashes;     // 公钥哈希向量
    vRecv >> locator >> vPubKeyHashes; // 读取定位器和公钥哈希列表

    // 查找所有者的新交易
    int nHeight = locator.GetHeight();       // 获取高度
    CTxDB txdb("r");                         // 以只读模式打开交易数据库
    foreach (uint160 hash160, vPubKeyHashes) // 遍历所有公钥哈希
    {
      vector<CTransaction> vtx;                      // 交易向量
      if (txdb.ReadOwnerTxes(hash160, nHeight, vtx)) // 读取所有者交易
      {
        foreach (const CTransaction &tx, vtx) // 遍历所有交易
        {
          // 将交易升级为完全支持的CWalletTx
          CWalletTx wtx(tx);                   // 创建钱包交易
          wtx.AddSupportingTransactions(txdb); // 添加支持交易

          pfrom->PushMessage("wtx", wtx); // 发送钱包交易
        }
      }
    }
  }

  else if (strCommand == "wtx") // 处理钱包交易消息
  {
    CWalletTx wtx; // 钱包交易对象
    vRecv >> wtx;  // 读取钱包交易

    if (!wtx.AcceptWalletTransaction()) // 如果接受钱包交易失败
      return error("message wtx : AcceptWalletTransaction failed!"); // 返回错误
    AddToWallet(wtx); // 添加到钱包
  }

  else if (strCommand == "tx") // 处理交易消息
  {
    CDataStream vMsg(vRecv); // 保存原始消息
    CTransaction tx;         // 交易对象
    vRecv >> tx;             // 读取交易

    CInv inv(MSG_TX, tx.GetHash()); // 创建库存项
    pfrom->AddInventoryKnown(inv);  // 添加到已知库存

    if (tx.AcceptTransaction()) // 如果接受交易成功
    {
      AddToWalletIfMine(tx, NULL);   // 如果是我的交易则添加到钱包
      RelayMessage(inv, vMsg);       // 中继消息
      mapAlreadyAskedFor.erase(inv); // 从已请求列表中删除
    }
  }

  else if (strCommand == "block") // 处理区块消息
  {
    auto_ptr<CBlock> pblock(new CBlock); // 创建区块智能指针
    vRecv >> *pblock;                    // 读取区块

    //// debug print
    printf("received block:\n");
    pblock->print(); // 打印区块信息

    CInv inv(MSG_BLOCK, pblock->GetHash()); // 创建库存项
    pfrom->AddInventoryKnown(inv);          // 添加到已知库存

    if (ProcessBlock(pfrom, pblock.release())) // 处理区块
      mapAlreadyAskedFor.erase(inv);           // 从已请求列表中删除
  }

  else if (strCommand == "getaddr") // 处理获取地址消息
  {
    pfrom->vAddrToSend.clear(); // 清空发送地址列表
    //// 需要扩展时间范围如果不够
    int64 nSince = GetAdjustedTime() - 60 * 60; // 最近一小时
    CRITICAL_BLOCK(cs_mapAddresses)             // 临界区保护地址映射
    {
      foreach (const PAIRTYPE(vector<unsigned char>, CAddress) & item,
               mapAddresses) // 遍历所有地址
      {
        const CAddress &addr = item.second;   // 获取地址
        if (addr.nTime > nSince)              // 如果在指定时间范围内
          pfrom->vAddrToSend.push_back(addr); // 添加到发送列表
      }
    }
  }

  else if (strCommand == "checkorder") // 处理检查订单消息
  {
    uint256 hashReply;           // 回复哈希
    CWalletTx order;             // 订单交易
    vRecv >> hashReply >> order; // 读取回复哈希和订单

    /// 我们有机会在这里检查订单

    // 保持给同一个ip使用相同的密钥，直到他们使用它
    if (!mapReuseKey.count(pfrom->addr.ip))           // 如果没有为该IP分配密钥
      mapReuseKey[pfrom->addr.ip] = GenerateNewKey(); // 生成新密钥

    // 发送订单批准和要使用的公钥
    CScript scriptPubKey; // 公钥脚本
    scriptPubKey << OP_CODESEPARATOR << mapReuseKey[pfrom->addr.ip]
                 << OP_CHECKSIG;                                  // 设置脚本
    pfrom->PushMessage("reply", hashReply, (int)0, scriptPubKey); // 发送回复
  }

  else if (strCommand == "submitorder") // 处理提交订单消息
  {
    uint256 hashReply;            // 回复哈希
    CWalletTx wtxNew;             // 新钱包交易
    vRecv >> hashReply >> wtxNew; // 读取回复哈希和新交易

    // 广播
    if (!wtxNew.AcceptWalletTransaction()) // 如果接受钱包交易失败
    {
      pfrom->PushMessage("reply", hashReply, (int)1); // 发送失败回复
      return error("submitorder AcceptWalletTransaction() failed, returning "
                   "error 1"); // 返回错误
    }
    AddToWallet(wtxNew);               // 添加到钱包
    wtxNew.RelayWalletTransaction();   // 中继钱包交易
    mapReuseKey.erase(pfrom->addr.ip); // 删除重用密钥

    // 发送确认
    pfrom->PushMessage("reply", hashReply, (int)0); // 发送成功回复
  }

  else if (strCommand == "reply") // 处理回复消息
  {
    uint256 hashReply;  // 回复哈希
    vRecv >> hashReply; // 读取回复哈希

    CRequestTracker tracker;              // 请求跟踪器
    CRITICAL_BLOCK(pfrom->cs_mapRequests) // 临界区保护请求映射
    {
      map<uint256, CRequestTracker>::iterator mi =
          pfrom->mapRequests.find(hashReply); // 查找请求
      if (mi != pfrom->mapRequests.end())     // 如果找到
      {
        tracker = (*mi).second;       // 获取跟踪器
        pfrom->mapRequests.erase(mi); // 从映射中删除
      }
    }
    if (!tracker.IsNull())               // 如果跟踪器有效
      tracker.fn(tracker.param1, vRecv); // 调用回调函数
  }

  else // 其他未知命令
  {
    // 忽略未知命令以实现可扩展性
    printf("ProcessMessage(%s) : Ignored unknown message\n",
           strCommand.c_str()); // 打印忽略信息
  }

  if (!vRecv.empty()) // 如果接收缓冲区不为空
    printf("ProcessMessage(%s) : %d extra bytes\n", strCommand.c_str(),
           vRecv.size()); // 打印多余字节

  return true; // 处理成功
}

bool SendMessages(CNode *pto) {
  CheckForShutdown(2); // 检查是否需要关闭

  // 在收到他们的版本消息之前不要发送任何内容
  if (pto->nVersion == 0) // 如果没有版本信息
    return true;          // 返回成功

  //
  // 消息: addr
  //
  vector<CAddress> vAddrToSend;                    // 要发送的地址向量
  vAddrToSend.reserve(pto->vAddrToSend.size());    // 预分配空间
  foreach (const CAddress &addr, pto->vAddrToSend) // 遍历所有要发送的地址
    if (!pto->setAddrKnown.count(addr))            // 如果节点不知道该地址
      vAddrToSend.push_back(addr);                 // 添加到发送列表
  pto->vAddrToSend.clear();                        // 清空待发送列表
  if (!vAddrToSend.empty())                        // 如果有地址要发送
    pto->PushMessage("addr", vAddrToSend);         // 发送地址消息

  //
  // 消息: inventory
  //
  vector<CInv> vInventoryToSend;    // 要发送的库存向量
  CRITICAL_BLOCK(pto->cs_inventory) // 临界区保护库存状态
  {
    vInventoryToSend.reserve(pto->vInventoryToSend.size()); // 预分配空间
    foreach (const CInv &inv, pto->vInventoryToSend) // 遍历所有要发送的库存
      if (!pto->setInventoryKnown.count(inv))        // 如果节点不知道该库存
        vInventoryToSend.push_back(inv);             // 添加到发送列表
    pto->vInventoryToSend.clear();                   // 清空待发送列表
  }
  if (!vInventoryToSend.empty())               // 如果有库存要发送
    pto->PushMessage("inv", vInventoryToSend); // 发送库存消息

  //
  // 消息: getdata
  //
  vector<CInv> vAskFor;   // 要请求的数据向量
  int64 nNow = GetTime(); // 当前时间
  while (!pto->mapAskFor.empty() &&
         (*pto->mapAskFor.begin()).first <= nNow) // 遍历所有请求
  {
    const CInv &inv = (*pto->mapAskFor.begin()).second; // 获取请求的库存
    printf("getdata %s\n", inv.ToString().c_str());     // 打印请求信息
    if (!AlreadyHave(inv))                              // 如果还没有该库存
      vAskFor.push_back(inv);                           // 添加到请求列表
    pto->mapAskFor.erase(pto->mapAskFor.begin());       // 从映射中删除
  }
  if (!vAskFor.empty())                   // 如果有请求要发送
    pto->PushMessage("getdata", vAskFor); // 发送获取数据消息

  return true; // 发送成功
}

//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner - 比特币挖矿功能
//

int FormatHashBlocks(void *pbuffer, unsigned int len) {
  unsigned char *pdata = (unsigned char *)pbuffer; // 数据指针
  unsigned int blocks = 1 + ((len + 8) / 64);      // 计算SHA-256块数
  unsigned char *pend = pdata + 64 * blocks;       // 结束指针
  memset(pdata + len, 0, 64 * blocks - len);       // 填充剩余空间为0
  pdata[len] = 0x80;                               // 添加填充标志
  unsigned int bits = len * 8;                     // 计算位长度
  pend[-1] = (bits >> 0) & 0xff;                   // 设置位长度（小端序）
  pend[-2] = (bits >> 8) & 0xff;
  pend[-3] = (bits >> 16) & 0xff;
  pend[-4] = (bits >> 24) & 0xff;
  return blocks; // 返回块数
}

using CryptoPP::ByteReverse;       // 使用字节反转函数
static int detectlittleendian = 1; // 检测是否为小端序

void BlockSHA256(const void *pin, unsigned int nBlocks, void *pout) {
  unsigned int *pinput = (unsigned int *)pin;  // 输入数据指针
  unsigned int *pstate = (unsigned int *)pout; // 输出状态指针

  CryptoPP::SHA256::InitState(pstate); // 初始化SHA-256状态

  if (*(char *)&detectlittleendian != 0) // 如果是小端序
  {
    for (int n = 0; n < nBlocks; n++) // 遍历每个块
    {
      unsigned int pbuf[16];                       // 缓冲区
      for (int i = 0; i < 16; i++)                 // 遍历每个字
        pbuf[i] = ByteReverse(pinput[n * 16 + i]); // 反转字节顺序
      CryptoPP::SHA256::Transform(pstate, pbuf);   // 执行变换
    }
    for (int i = 0; i < 8; i++) // 反转输出
      pstate[i] = ByteReverse(pstate[i]);
  } else // 大端序
  {
    for (int n = 0; n < nBlocks; n++)                       // 遍历每个块
      CryptoPP::SHA256::Transform(pstate, pinput + n * 16); // 直接执行变换
  }
}

bool BitcoinMiner() {
  printf("BitcoinMiner started\n"); // 打印开始信息

  SetThreadPriority(GetCurrentThread(),
                    THREAD_PRIORITY_LOWEST); // 设置最低线程优先级

  CBlock blockPrev;         // 前一个区块
  while (fGenerateBitcoins) // 当挖矿标志为真时循环
  {
    CheckForShutdown(3); // 检查是否需要关闭

    //
    // 创建coinbase交易
    //
    CTransaction txNew;             // 新交易
    txNew.vin.resize(1);            // 设置输入数量为1
    txNew.vin[0].prevout.SetNull(); // 设置前一个输出为空（coinbase交易）
    CBigNum bnNonce;                // 这个nonce用于多个进程为同一个keyUser工作
    BN_rand_range(&bnNonce, &CBigNum(INT_MAX)); // 生成随机数，避免重复工作
    txNew.vin[0].scriptSig << bnNonce;          // 设置脚本签名
    txNew.vout.resize(1);                       // 设置输出数量为1
    txNew.vout[0].scriptPubKey << OP_CODESEPARATOR << keyUser.GetPubKey()
                               << OP_CHECKSIG; // 设置输出脚本（挖矿奖励）
    txNew.vout[0].posNext.SetNull();           // 设置下一个位置为空

    //
    // 创建新区块
    //
    auto_ptr<CBlock> pblock(new CBlock()); // 创建区块智能指针
    if (!pblock.get())                     // 如果创建失败
      return false;                        // 返回失败

    // 将我们的coinbase交易作为第一个交易添加
    pblock->vtx.push_back(txNew); // 添加coinbase交易

    // 收集最新交易到区块中
    unsigned int nTransactionsUpdatedLast =
        nTransactionsUpdated;          // 记录交易更新次数
    int64 nFees = 0;                   // 交易费用
    CRITICAL_BLOCK(cs_mapTransactions) // 临界区保护交易映射
    {
      CTxDB txdb("r");             // 以只读模式打开交易数据库
      set<uint256> setInThisBlock; // 此区块中的交易集合
      vector<char> vfAlreadyAdded(mapTransactions.size()); // 已添加标志
      bool fFoundSomething = true;                         // 是否找到新交易
      unsigned int nSize = 0;                              // 区块大小
      while (fFoundSomething &&
             nSize <
                 MAX_SIZE / 2) // 当找到新交易且区块大小小于最大大小的一半时循环
      {
        fFoundSomething = false; // 重置标志
        unsigned int n = 0;      // 计数器
        for (map<uint256, CTransaction>::iterator mi = mapTransactions.begin();
             mi != mapTransactions.end(); ++mi, ++n) // 遍历所有交易
        {
          if (vfAlreadyAdded[n])           // 如果已添加
            continue;                      // 跳过
          CTransaction &tx = (*mi).second; // 获取交易
          if (!tx.IsFinal() ||
              tx.IsCoinBase()) // 如果不是最终交易或coinbase交易
            continue;          // 跳过

          // 查找是否所有依赖都在这个或之前的区块中
          bool fHaveAllPrev = true;           // 是否拥有所有前置
          int64 nValueIn = 0;                 // 输入价值
          foreach (const CTxIn &txin, tx.vin) // 遍历所有输入
          {
            COutPoint prevout = txin.prevout;       // 前一个输出
            CTransaction txPrev;                    // 前一个交易
            if (setInThisBlock.count(prevout.hash)) // 如果在前一个交易集合中
            {
              txPrev = mapTransactions[prevout.hash];          // 获取交易
            } else if (!txdb.ReadDiskTx(prevout.hash, txPrev)) // 从磁盘读取失败
            {
              fHaveAllPrev = false; // 设置标志为假
              break;                // 跳出循环
            }
            if (prevout.n >= txPrev.vout.size()) // 如果输出索引超出范围
            {
              fHaveAllPrev = false; // 设置标志为假
              break;                // 跳出循环
            }
            nValueIn += txPrev.vout[prevout.n].nValue; // 累加输入价值
          }
          int64 nTransactionFee = nValueIn - tx.GetValueOut(); // 计算交易费用
          if (nTransactionFee < 0) // 这里可以要求交易费用
            continue;              // 跳过

          // 将交易添加到区块
          if (fHaveAllPrev) // 如果拥有所有前置
          {
            fFoundSomething = true;                       // 设置标志为真
            pblock->vtx.push_back(tx);                    // 添加交易到区块
            nSize += ::GetSerializeSize(tx, SER_NETWORK); // 增加区块大小
            nFees += nTransactionFee;                     // 增加总费用
            vfAlreadyAdded[n] = true;                     // 标记为已添加
            setInThisBlock.insert(tx.GetHash());          // 添加到交易集合
          }
        }
      }
    }

    // 更新最后几项
    pblock->vtx[0].vout[0].nValue = GetBlockValue(nFees); // 设置区块奖励
    pblock->hashMerkleRoot = pblock->BuildMerkleTree();   // 构建默克尔树

    printf("\n\nRunning BitcoinMiner with %d transactions in block\n",
           pblock->vtx.size()); // 打印区块中的交易数量

    //
    // 预构建哈希缓冲区
    //
    struct unnamed1 // 匿名结构体1
    {
      struct unnamed2 // 匿名结构体2
      {
        uint256 hashPrevBlock;       // 前一个区块哈希
        uint256 hashMerkleRoot;      // 默克尔根
        unsigned int nTime;          // 时间戳
        unsigned int nBits;          // 难度目标
        unsigned int nNonce;         // 随机数
      } block;                       // 区块部分
      unsigned char pchPadding0[64]; // 填充0
      uint256 hash1;                 // 第一次哈希结果
      unsigned char pchPadding1[64]; // 填充1
    } tmp;                           // 临时变量

    const CBlockIndex *pindexPrev = pindexBest; // 获取最佳区块索引
    tmp.block.hashPrevBlock = pblock->hashPrevBlock =
        hashTimeChainBest;                             // 设置前一个区块哈希
    tmp.block.hashMerkleRoot = pblock->hashMerkleRoot; // 设置默克尔根

    // 获取前一个区块的时间
    if (pindexPrev) // 如果有前一个区块
    {
      if (blockPrev.GetHash() !=
          pblock->hashPrevBlock)                   // 如果前一个区块哈希不匹配
        blockPrev.ReadFromDisk(pindexPrev, false); // 重新读取前一个区块
      if (blockPrev.GetHash() !=
          pblock->hashPrevBlock) // 如果前一个区块哈希不匹配
      {
        printf(
            "pindexBest and hashTimeChainBest out of sync\n"); // 打印不同步错误
        continue; // 跳过此次循环，重新开始
      }
    }
    tmp.block.nTime = pblock->nTime = max(
        blockPrev.nTime + 1,
        (unsigned int)
            GetAdjustedTime()); // 设置区块时间戳（至少比前一个区块大1或使用当前时间）
    tmp.block.nBits = pblock->nBits =
        GetNextWorkRequired(pindexPrev); // 设置区块难度目标
    tmp.block.nNonce = 1;                // 初始化nonce值

    unsigned int nBlocks0 = FormatHashBlocks(
        &tmp.block, sizeof(tmp.block)); // 格式化区块数据用于哈希
    unsigned int nBlocks1 = FormatHashBlocks(
        &tmp.hash1, sizeof(tmp.hash1)); // 格式化中间哈希结果用于哈希

    //
    // 挖矿搜索过程
    //
    uint256 hashTarget = (~uint256(0) >> pblock->nBits); // 计算目标哈希值
    uint256 hash;                                        // 当前哈希值
    while (nTransactionsUpdated ==
           nTransactionsUpdatedLast) // 当没有新交易时继续挖矿
    {
      BlockSHA256(&tmp.block, nBlocks0, &tmp.hash1); // 第一次SHA256哈希
      BlockSHA256(&tmp.hash1, nBlocks1, &hash); // 第二次SHA256哈希（双SHA256）

      if (hash <= hashTarget) // 如果哈希值满足目标条件（挖矿成功）
      {
        pblock->nNonce = tmp.block.nNonce; // 设置区块的nonce值
        assert(hash == pblock->GetHash()); // 确保计算的哈希与区块哈希一致

        //// 调试打印
        printf("BitcoinMiner:\n");
        printf("supercoin found  \n  hash: %s  \ntarget: %s\n",
               hash.GetHex().c_str(),
               hashTarget.GetHex().c_str()); // 打印找到的哈希和目标值
        pblock->print();                     // 打印区块信息

        // 像从其他节点接收区块一样处理这个区块
        if (!ProcessBlock(NULL, pblock.release())) // 处理区块
          printf(
              "ERROR in BitcoinMiner, ProcessBlock, block not accepted\n"); // 打印错误信息
        break; // 跳出循环
      }

      // 每几秒更新一次时间戳
      if ((++tmp.block.nNonce & 0xfffff) ==
          0) // 每次nonce增加，当达到0xfffff倍数时更新时间
      {
        if (tmp.block.nNonce == 0) // 如果nonce溢出
          break;                   // 跳出循环
        tmp.block.nTime = pblock->nTime = max(
            blockPrev.nTime + 1, (unsigned int)GetAdjustedTime()); // 更新时间戳
      }
    }
  }

  return true; // 返回成功
}

//////////////////////////////////////////////////////////////////////////////
//
// Actions - 操作函数
//

int64 CountMoney() // 计算钱包中的总金额
{
  int64 nTotal = 0;            // 总金额
  CRITICAL_BLOCK(cs_mapWallet) // 临界区保护钱包映射
  {
    for (map<uint256, CWalletTx>::iterator it = mapWallet.begin();
         it != mapWallet.end(); ++it) // 遍历所有钱包交易
    {
      CWalletTx *pcoin = &(*it).second;       // 获取钱包交易指针
      if (!pcoin->IsFinal() || pcoin->fSpent) // 如果交易不是最终状态或已花费
        continue;                             // 跳过
      nTotal += pcoin->GetCredit();           // 累加信用额度（可用金额）
    }
  }
  return nTotal; // 返回总金额
}

bool SelectCoins(
    int64 nTargetValue,
    set<CWalletTx *> &setCoinsRet) // 选择合适的交易币来凑够目标金额
{
  setCoinsRet.clear(); // 清空返回集合

  // 寻找接近目标值的交易
  int64 nLowestLarger = _I64_MAX;          // 大于目标值的最小金额
  CWalletTx *pcoinLowestLarger = NULL;     // 对应的交易指针
  vector<pair<int64, CWalletTx *>> vValue; // 金额-交易对向量
  int64 nTotalLower = 0;                   // 小于目标值的总金额

  CRITICAL_BLOCK(cs_mapWallet) // 临界区保护钱包映射
  {
    for (map<uint256, CWalletTx>::iterator it = mapWallet.begin();
         it != mapWallet.end(); ++it) // 遍历所有钱包交易
    {
      CWalletTx *pcoin = &(*it).second;       // 获取钱包交易指针
      if (!pcoin->IsFinal() || pcoin->fSpent) // 如果交易不是最终状态或已花费
        continue;                             // 跳过
      int64 n = pcoin->GetCredit();           // 获取信用额度
      if (n < nTargetValue)                   // 如果金额小于目标值
      {
        vValue.push_back(make_pair(n, pcoin)); // 添加到向量
        nTotalLower += n;                      // 累加总金额
      } else if (n == nTargetValue)            // 如果金额正好等于目标值
      {
        setCoinsRet.insert(pcoin);  // 直接返回该交易
        return true;                // 成功
      } else if (n < nLowestLarger) // 如果金额大于目标值且是当前找到的最小的
      {
        nLowestLarger = n;         // 更新最小金额
        pcoinLowestLarger = pcoin; // 更新交易指针
      }
    }
  }

  if (nTotalLower < nTargetValue) // 如果所有小额交易总和小于目标值
  {
    if (pcoinLowestLarger == NULL)         // 如果没有找到大额交易
      return false;                        // 失败
    setCoinsRet.insert(pcoinLowestLarger); // 返回找到的最小大额交易
    return true;                           // 成功
  }

  // 使用随机近似算法解决子集和问题
  sort(vValue.rbegin(), vValue.rend());     // 按金额降序排序
  vector<char> vfIncluded;                  // 是否包含在集合中
  vector<char> vfBest(vValue.size(), true); // 最佳选择（默认全部选中）
  int64 nBest = nTotalLower;                // 最佳总金额

  for (int nRep = 0; nRep < 1000 && nBest != nTargetValue;
       nRep++) // 重复1000次尝试或直到找到精确匹配
  {
    vfIncluded.assign(vValue.size(), false); // 重置包含标志
    int64 nTotal = 0;                        // 当前总金额
    for (int i = 0; i < vValue.size(); i++)  // 遍历所有交易
    {
      if (rand() % 2) // 随机选择
      {
        nTotal += vValue[i].first;  // 累加金额
        vfIncluded[i] = true;       // 标记为包含
        if (nTotal >= nTargetValue) // 如果达到或超过目标
        {
          if (nTotal < nBest) // 如果比当前最佳更接近目标
          {
            nBest = nTotal;      // 更新最佳金额
            vfBest = vfIncluded; // 更新最佳选择
          }
          nTotal -= vValue[i].first; // 减去当前交易金额
          vfIncluded[i] = false;     // 取消选择
        }
      }
    }
  }

  // 如果大额交易更接近目标，返回它
  if (pcoinLowestLarger && nLowestLarger - nTargetValue <= nBest - nTargetValue)
    setCoinsRet.insert(pcoinLowestLarger);
  else // 否则返回子集和的结果
    for (int i = 0; i < vValue.size(); i++)
      if (vfBest[i])
        setCoinsRet.insert(vValue[i].second);
  return true; // 成功
}

bool CreateTransaction(CScript scriptPubKey, int64 nValue,
                       CWalletTx &wtxNew) // 创建新交易
{
  wtxNew.vin.clear();          // 清空输入
  wtxNew.vout.clear();         // 清空输出
  if (nValue < TRANSACTIONFEE) // 如果金额小于交易费
    return false;              // 失败

  // 选择要使用的币
  set<CWalletTx *> setCoins;           // 选中的交易集合
  if (!SelectCoins(nValue, setCoins))  // 选择币
    return false;                      // 失败
  int64 nValueIn = 0;                  // 输入总金额
  foreach (CWalletTx *pcoin, setCoins) // 遍历选中的交易
    nValueIn += pcoin->GetCredit();    // 累加输入金额

  // 设置输出[0]给收款人
  int64 nValueOut = nValue - TRANSACTIONFEE; // 输出金额（减去交易费）
  wtxNew.vout.push_back(CTxOut(nValueOut, scriptPubKey)); // 添加输出

  // 设置输出[1]给自己找零
  if (nValueIn - TRANSACTIONFEE > nValueOut) // 如果输入大于输出（需要找零）
  {
    // 使用其中一个币的密钥
    vector<unsigned char> vchPubKey;              // 公钥
    CTransaction &txFirst = *(*setCoins.begin()); // 获取第一个交易
    foreach (const CTxOut &txout, txFirst.vout)   // 遍历其输出
      if (txout.IsMine())                         // 如果是我的输出
        if (ExtractPubKey(txout.scriptPubKey, true, vchPubKey)) // 提取公钥
          break;           // 找到后退出循环
    if (vchPubKey.empty()) // 如果没有找到公钥
      return false;        // 失败

    // 设置输出[1]给我自己（找零）
    CScript scriptPubKey;                                         // 公钥脚本
    scriptPubKey << OP_CODESEPARATOR << vchPubKey << OP_CHECKSIG; // 设置脚本
    wtxNew.vout.push_back(CTxOut(nValueIn - TRANSACTIONFEE - nValueOut,
                                 scriptPubKey)); // 添加找零输出
  }

  // 填充输入
  foreach (CWalletTx *pcoin, setCoins)                    // 遍历选中的交易
    for (int nOut = 0; nOut < pcoin->vout.size(); nOut++) // 遍历其输出
      if (pcoin->vout[nOut].IsMine())                     // 如果是我的输出
        SignSignature(*pcoin, nOut, wtxNew, -1, "all");   // 签名

  // 填充vtxPrev通过复制前一个交易的vtxPrev
  wtxNew.AddSupportingTransactions(); // 添加支持交易

  // 添加交易到钱包，因为如果有找零也是我们的，否则只是为了交易历史
  wtxNew.nTime = GetAdjustedTime(); // 设置交易时间
  AddToWallet(wtxNew);              // 添加到钱包

  // 标记旧币为已花费
  foreach (CWalletTx *pcoin, setCoins) // 遍历选中的交易
  {
    pcoin->fSpent = true; // 标记为已花费
    pcoin->WriteToDisk(); // 写入磁盘
    vWalletUpdated.push_back(
        make_pair(pcoin->GetHash(), false)); // 添加到更新列表
  }

  return true; // 成功
}

bool SendMoney(CScript scriptPubKey, int64 nValue,
               CWalletTx &wtxNew) // 发送比特币
{
  if (!CreateTransaction(scriptPubKey, nValue, wtxNew)) // 创建交易
    return false;                                       // 失败

  // 广播交易
  if (!wtxNew.AcceptTransaction()) // 接受交易
  {
    // 这不应该失败。交易已经签名并记录。
    throw runtime_error(
        "SendMoney() : wtxNew.AcceptTransaction() failed\n"); // 抛出异常
    return false; // 失败（实际上不会执行到这里）
  }
  wtxNew.RelayWalletTransaction(); // 中继钱包交易

  return true; // 成功
}
