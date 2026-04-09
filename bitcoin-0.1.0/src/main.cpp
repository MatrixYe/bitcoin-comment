// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "headers.h"
#include "sha.h"

//
// Global state
//

CCriticalSection cs_main;

map<uint256, CTransaction> mapTransactions;
CCriticalSection cs_mapTransactions;
unsigned int nTransactionsUpdated = 0;
map<COutPoint, CInPoint> mapNextTx;

map<uint256, CBlockIndex *> mapBlockIndex;
const uint256 hashGenesisBlock(
    "0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
CBlockIndex *pindexGenesisBlock = NULL;
int nBestHeight = -1;
uint256 hashBestChain = 0;
CBlockIndex *pindexBest = NULL;

map<uint256, CBlock *> mapOrphanBlocks;
multimap<uint256, CBlock *> mapOrphanBlocksByPrev;

map<uint256, CDataStream *> mapOrphanTransactions;
multimap<uint256, CDataStream *> mapOrphanTransactionsByPrev;

map<uint256, CWalletTx> mapWallet;
vector<pair<uint256, bool>> vWalletUpdated;
CCriticalSection cs_mapWallet;

map<vector<unsigned char>, CPrivKey> mapKeys;
map<uint160, vector<unsigned char>> mapPubKeys;
CCriticalSection cs_mapKeys;
CKey keyUser;

string strSetDataDir;
int nDropMessagesTest = 0;

// Settings
int fGenerateBitcoins;
int64 nTransactionFee = 0;
CAddress addrIncoming;

//////////////////////////////////////////////////////////////////////////////
//
// mapKeys
//

bool AddKey(const CKey &key) {
  CRITICAL_BLOCK(cs_mapKeys) {
    mapKeys[key.GetPubKey()] = key.GetPrivKey();
    mapPubKeys[Hash160(key.GetPubKey())] = key.GetPubKey();
  }
  return CWalletDB().WriteKey(key.GetPubKey(), key.GetPrivKey());
}

vector<unsigned char> GenerateNewKey() {
  CKey key;
  key.MakeNewKey();
  if (!AddKey(key))
    throw runtime_error("GenerateNewKey() : AddKey failed\n");
  return key.GetPubKey();
}

//////////////////////////////////////////////////////////////////////////////
//
// mapWallet
//

bool AddToWallet(const CWalletTx &wtxIn) {
  uint256 hash = wtxIn.GetHash();
  CRITICAL_BLOCK(cs_mapWallet) {
    // Inserts only if not already there, returns tx inserted or tx found
    pair<map<uint256, CWalletTx>::iterator, bool> ret =
        mapWallet.insert(make_pair(hash, wtxIn));
    CWalletTx &wtx = (*ret.first).second;
    bool fInsertedNew = ret.second;
    if (fInsertedNew)
      wtx.nTimeReceived = GetAdjustedTime();

    //// debug print
    printf("AddToWallet %s  %s\n",
           wtxIn.GetHash().ToString().substr(0, 6).c_str(),
           fInsertedNew ? "new" : "update");

    if (!fInsertedNew) {
      // Merge
      bool fUpdated = false;
      if (wtxIn.hashBlock != 0 && wtxIn.hashBlock != wtx.hashBlock) {
        wtx.hashBlock = wtxIn.hashBlock;
        fUpdated = true;
      }
      if (wtxIn.nIndex != -1 && (wtxIn.vMerkleBranch != wtx.vMerkleBranch ||
                                 wtxIn.nIndex != wtx.nIndex)) {
        wtx.vMerkleBranch = wtxIn.vMerkleBranch;
        wtx.nIndex = wtxIn.nIndex;
        fUpdated = true;
      }
      if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe) {
        wtx.fFromMe = wtxIn.fFromMe;
        fUpdated = true;
      }
      if (wtxIn.fSpent && wtxIn.fSpent != wtx.fSpent) {
        wtx.fSpent = wtxIn.fSpent;
        fUpdated = true;
      }
      if (!fUpdated)
        return true;
    }

    // Write to disk
    if (!wtx.WriteToDisk())
      return false;

    // Notify UI
    vWalletUpdated.push_back(make_pair(hash, fInsertedNew));
  }

  // Refresh UI
  MainFrameRepaint();
  return true;
}

bool AddToWalletIfMine(const CTransaction &tx, const CBlock *pblock) {
  if (tx.IsMine() || mapWallet.count(tx.GetHash())) {
    CWalletTx wtx(tx);
    // Get merkle branch if transaction was found in a block
    if (pblock)
      wtx.SetMerkleBranch(pblock);
    return AddToWallet(wtx);
  }
  return true;
}

bool EraseFromWallet(uint256 hash) {
  CRITICAL_BLOCK(cs_mapWallet) {
    if (mapWallet.erase(hash))
      CWalletDB().EraseTx(hash);
  }
  return true;
}

//////////////////////////////////////////////////////////////////////////////
//
// mapOrphanTransactions
//

void AddOrphanTx(const CDataStream &vMsg) {
  CTransaction tx;
  CDataStream(vMsg) >> tx;
  uint256 hash = tx.GetHash();
  if (mapOrphanTransactions.count(hash))
    return;
  CDataStream *pvMsg = mapOrphanTransactions[hash] = new CDataStream(vMsg);
  foreach (const CTxIn &txin, tx.vin)
    mapOrphanTransactionsByPrev.insert(make_pair(txin.prevout.hash, pvMsg));
}

void EraseOrphanTx(uint256 hash) {
  if (!mapOrphanTransactions.count(hash))
    return;
  const CDataStream *pvMsg = mapOrphanTransactions[hash];
  CTransaction tx;
  CDataStream(*pvMsg) >> tx;
  foreach (const CTxIn &txin, tx.vin) {
    for (multimap<uint256, CDataStream *>::iterator mi =
             mapOrphanTransactionsByPrev.lower_bound(txin.prevout.hash);
         mi != mapOrphanTransactionsByPrev.upper_bound(txin.prevout.hash);) {
      if ((*mi).second == pvMsg)
        mapOrphanTransactionsByPrev.erase(mi++);
      else
        mi++;
    }
  }
  delete pvMsg;
  mapOrphanTransactions.erase(hash);
}

//////////////////////////////////////////////////////////////////////////////
//
// CTransaction
//

bool CTxIn::IsMine() const {
  CRITICAL_BLOCK(cs_mapWallet) {
    map<uint256, CWalletTx>::iterator mi = mapWallet.find(prevout.hash);
    if (mi != mapWallet.end()) {
      const CWalletTx &prev = (*mi).second;
      if (prevout.n < prev.vout.size())
        if (prev.vout[prevout.n].IsMine())
          return true;
    }
  }
  return false;
}

int64 CTxIn::GetDebit() const {
  CRITICAL_BLOCK(cs_mapWallet) {
    map<uint256, CWalletTx>::iterator mi = mapWallet.find(prevout.hash);
    if (mi != mapWallet.end()) {
      const CWalletTx &prev = (*mi).second;
      if (prevout.n < prev.vout.size())
        if (prev.vout[prevout.n].IsMine())
          return prev.vout[prevout.n].nValue;
    }
  }
  return 0;
}

int64 CWalletTx::GetTxTime() const {
  if (!fTimeReceivedIsTxTime && hashBlock != 0) {
    // If we did not receive the transaction directly, we rely on the block's
    // time to figure out when it happened.  We use the median over a range
    // of blocks to try to filter out inaccurate block times.
    map<uint256, CBlockIndex *>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi != mapBlockIndex.end()) {
      CBlockIndex *pindex = (*mi).second;
      if (pindex)
        return pindex->GetMedianTime();
    }
  }
  return nTimeReceived;
}

int CMerkleTx::SetMerkleBranch(const CBlock *pblock) {
  if (fClient) {
    if (hashBlock == 0)
      return 0;
  } else {
    CBlock blockTmp;
    if (pblock == NULL) {
      // Load the block this tx is in
      CTxIndex txindex;
      if (!CTxDB("r").ReadTxIndex(GetHash(), txindex))
        return 0;
      if (!blockTmp.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos,
                                 true))
        return 0;
      pblock = &blockTmp;
    }

    // Update the tx's hashBlock
    hashBlock = pblock->GetHash();

    // Locate the transaction
    for (nIndex = 0; nIndex < pblock->vtx.size(); nIndex++)
      if (pblock->vtx[nIndex] == *(CTransaction *)this)
        break;
    if (nIndex == pblock->vtx.size()) {
      vMerkleBranch.clear();
      nIndex = -1;
      printf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
      return 0;
    }

    // Fill in merkle branch
    vMerkleBranch = pblock->GetMerkleBranch(nIndex);
  }

  // Is the tx in a block that's in the main chain
  map<uint256, CBlockIndex *>::iterator mi = mapBlockIndex.find(hashBlock);
  if (mi == mapBlockIndex.end())
    return 0;
  CBlockIndex *pindex = (*mi).second;
  if (!pindex || !pindex->IsInMainChain())
    return 0;

  return pindexBest->nHeight - pindex->nHeight + 1;
}

void CWalletTx::AddSupportingTransactions(CTxDB &txdb) {
  vtxPrev.clear();

  const int COPY_DEPTH = 3;
  if (SetMerkleBranch() < COPY_DEPTH) {
    vector<uint256> vWorkQueue;
    foreach (const CTxIn &txin, vin)
      vWorkQueue.push_back(txin.prevout.hash);

    // This critsect is OK because txdb is already open
    CRITICAL_BLOCK(cs_mapWallet) {
      map<uint256, const CMerkleTx *> mapWalletPrev;
      set<uint256> setAlreadyDone;
      for (int i = 0; i < vWorkQueue.size(); i++) {
        uint256 hash = vWorkQueue[i];
        if (setAlreadyDone.count(hash))
          continue;
        setAlreadyDone.insert(hash);

        CMerkleTx tx;
        if (mapWallet.count(hash)) {
          tx = mapWallet[hash];
          foreach (const CMerkleTx &txWalletPrev, mapWallet[hash].vtxPrev)
            mapWalletPrev[txWalletPrev.GetHash()] = &txWalletPrev;
        } else if (mapWalletPrev.count(hash)) {
          tx = *mapWalletPrev[hash];
        } else if (!fClient && txdb.ReadDiskTx(hash, tx)) {
          ;
        } else {
          printf(
              "ERROR: AddSupportingTransactions() : unsupported transaction\n");
          continue;
        }

        int nDepth = tx.SetMerkleBranch();
        vtxPrev.push_back(tx);

        if (nDepth < COPY_DEPTH)
          foreach (const CTxIn &txin, tx.vin)
            vWorkQueue.push_back(txin.prevout.hash);
      }
    }
  }

  reverse(vtxPrev.begin(), vtxPrev.end());
}

/**
 * 接受交易
 * 验证交易的有效性，并将其添加到内存池
 *
 * @param txdb 交易数据库，用于查询已有交易和验证输入
 * @param fCheckInputs 是否检查输入，如果为false则跳过输入验证
 * @param pfMissingInputs 可选的输出参数，用于标记是否有缺失的输入
 * @return 如果交易被成功接受，返回true；否则返回false
 *
 * 主要验证步骤：
 * 1. 检查是否为币基交易（币基交易不能作为独立交易被接受）
 * 2. 执行基本交易检查（CheckTransaction）
 * 3. 检查交易是否已存在于内存池或数据库中
 * 4. 检查与内存中交易的冲突（支持用新版本替换旧版本）
 * 5. 验证交易输入（ConnectInputs）
 * 6. 将交易添加到内存池
 */
bool CTransaction::AcceptTransaction(CTxDB &txdb, bool fCheckInputs,
                                     bool *pfMissingInputs) {
  // 初始化缺失输入标记为false
  if (pfMissingInputs)
    *pfMissingInputs = false;

  // Coinbase is only valid in a block, not as a loose transaction
  // 币基交易只在区块中有效，不能作为独立交易被接受
  if (IsCoinBase())
    return error("AcceptTransaction() : coinbase as individual tx");

  // 执行基本交易检查
  if (!CheckTransaction())
    return error("AcceptTransaction() : CheckTransaction failed");

  // Do we already have it?
  // 检查交易是否已存在于内存池或数据库中
  uint256 hash = GetHash();
  CRITICAL_BLOCK(cs_mapTransactions)
  if (mapTransactions.count(hash))
    return false;
  if (fCheckInputs)
    if (txdb.ContainsTx(hash))
      return false;

  // Check for conflicts with in-memory transactions
  // 检查与内存中交易的冲突
  CTransaction *ptxOld = NULL;
  for (int i = 0; i < vin.size(); i++) {
    COutPoint outpoint = vin[i].prevout;
    if (mapNextTx.count(outpoint)) {
      // Allow replacing with a newer version of the same transaction
      // 允许用新版本替换同一交易的旧版本，只有第一个输入可以触发替换
      if (i != 0)
        return false;
      ptxOld = mapNextTx[outpoint].ptx;
      // 检查当前交易是否比旧版本更新
      if (!IsNewerThan(*ptxOld))
        return false;
      // 验证所有输入都指向同一旧交易
      for (int i = 0; i < vin.size(); i++) {
        COutPoint outpoint = vin[i].prevout;
        if (!mapNextTx.count(outpoint) || mapNextTx[outpoint].ptx != ptxOld)
          return false;
      }
      break;
    }
  }

  // Check against previous transactions
  // 验证交易输入
  map<uint256, CTxIndex> mapUnused;
  int64 nFees = 0;
  if (fCheckInputs && !ConnectInputs(txdb, mapUnused, CDiskTxPos(1, 1, 1), 0,
                                     nFees, false, false)) {
    if (pfMissingInputs)
      *pfMissingInputs = true;
    return error("AcceptTransaction() : ConnectInputs failed %s",
                 hash.ToString().substr(0, 6).c_str());
  }

  // Store transaction in memory
  // 将交易存储到内存池
  CRITICAL_BLOCK(cs_mapTransactions) {
    if (ptxOld) {
      printf("mapTransaction.erase(%s) replacing with new version\n",
             ptxOld->GetHash().ToString().c_str());
      mapTransactions.erase(ptxOld->GetHash());
    }
    AddToMemoryPool();
  }

  ///// are we sure this is ok when loading transactions or restoring block txes
  // If updated, erase old tx from wallet
  // 如果更新了交易，从钱包中删除旧交易
  if (ptxOld)
    EraseFromWallet(ptxOld->GetHash());

  printf("AcceptTransaction(): accepted %s\n",
         hash.ToString().substr(0, 6).c_str());
  return true;
}

bool CTransaction::AddToMemoryPool() {
  // Add to memory pool without checking anything.  Don't call this directly,
  // call AcceptTransaction to properly check the transaction first.
  CRITICAL_BLOCK(cs_mapTransactions) {
    uint256 hash = GetHash();
    mapTransactions[hash] = *this;
    for (int i = 0; i < vin.size(); i++)
      mapNextTx[vin[i].prevout] = CInPoint(&mapTransactions[hash], i);
    nTransactionsUpdated++;
  }
  return true;
}

bool CTransaction::RemoveFromMemoryPool() {
  // Remove transaction from memory pool
  CRITICAL_BLOCK(cs_mapTransactions) {
    foreach (const CTxIn &txin, vin)
      mapNextTx.erase(txin.prevout);
    mapTransactions.erase(GetHash());
    nTransactionsUpdated++;
  }
  return true;
}

int CMerkleTx::GetDepthInMainChain() const {
  if (hashBlock == 0 || nIndex == -1)
    return 0;

  // Find the block it claims to be in
  map<uint256, CBlockIndex *>::iterator mi = mapBlockIndex.find(hashBlock);
  if (mi == mapBlockIndex.end())
    return 0;
  CBlockIndex *pindex = (*mi).second;
  if (!pindex || !pindex->IsInMainChain())
    return 0;

  // Make sure the merkle branch connects to this block
  if (!fMerkleVerified) {
    if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) !=
        pindex->hashMerkleRoot)
      return 0;
    fMerkleVerified = true;
  }

  return pindexBest->nHeight - pindex->nHeight + 1;
}

int CMerkleTx::GetBlocksToMaturity() const {
  if (!IsCoinBase())
    return 0;
  return max(0, (COINBASE_MATURITY + 20) - GetDepthInMainChain());
}

bool CMerkleTx::AcceptTransaction(CTxDB &txdb, bool fCheckInputs) {
  if (fClient) {
    if (!IsInMainChain() && !ClientConnectInputs())
      return false;
    return CTransaction::AcceptTransaction(txdb, false);
  } else {
    return CTransaction::AcceptTransaction(txdb, fCheckInputs);
  }
}

bool CWalletTx::AcceptWalletTransaction(CTxDB &txdb, bool fCheckInputs) {
  CRITICAL_BLOCK(cs_mapTransactions) {
    foreach (CMerkleTx &tx, vtxPrev) {
      if (!tx.IsCoinBase()) {
        uint256 hash = tx.GetHash();
        if (!mapTransactions.count(hash) && !txdb.ContainsTx(hash))
          tx.AcceptTransaction(txdb, fCheckInputs);
      }
    }
    if (!IsCoinBase())
      return AcceptTransaction(txdb, fCheckInputs);
  }
  return true;
}

void ReacceptWalletTransactions() {
  // Reaccept any txes of ours that aren't already in a block
  CTxDB txdb("r");
  CRITICAL_BLOCK(cs_mapWallet) {
    foreach (PAIRTYPE(const uint256, CWalletTx) & item, mapWallet) {
      CWalletTx &wtx = item.second;
      if (!wtx.IsCoinBase() && !txdb.ContainsTx(wtx.GetHash()))
        wtx.AcceptWalletTransaction(txdb, false);
    }
  }
}

void CWalletTx::RelayWalletTransaction(CTxDB &txdb) {
  foreach (const CMerkleTx &tx, vtxPrev) {
    if (!tx.IsCoinBase()) {
      uint256 hash = tx.GetHash();
      if (!txdb.ContainsTx(hash))
        RelayMessage(CInv(MSG_TX, hash), (CTransaction)tx);
    }
  }
  if (!IsCoinBase()) {
    uint256 hash = GetHash();
    if (!txdb.ContainsTx(hash)) {
      printf("Relaying wtx %s\n", hash.ToString().substr(0, 6).c_str());
      RelayMessage(CInv(MSG_TX, hash), (CTransaction) * this);
    }
  }
}

void RelayWalletTransactions() {
  static int64 nLastTime;
  if (GetTime() - nLastTime < 10 * 60)
    return;
  nLastTime = GetTime();

  // Rebroadcast any of our txes that aren't in a block yet
  printf("RelayWalletTransactions()\n");
  CTxDB txdb("r");
  CRITICAL_BLOCK(cs_mapWallet) {
    // Sort them in chronological order
    multimap<unsigned int, CWalletTx *> mapSorted;
    foreach (PAIRTYPE(const uint256, CWalletTx) & item, mapWallet) {
      CWalletTx &wtx = item.second;
      mapSorted.insert(make_pair(wtx.nTimeReceived, &wtx));
    }
    foreach (PAIRTYPE(const unsigned int, CWalletTx *) & item, mapSorted) {
      CWalletTx &wtx = *item.second;
      wtx.RelayWalletTransaction(txdb);
    }
  }
}

//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

bool CBlock::ReadFromDisk(const CBlockIndex *pblockindex,
                          bool fReadTransactions) {
  return ReadFromDisk(pblockindex->nFile, pblockindex->nBlockPos,
                      fReadTransactions);
}

uint256 GetOrphanRoot(const CBlock *pblock) {
  // Work back to the first block in the orphan chain
  while (mapOrphanBlocks.count(pblock->hashPrevBlock))
    pblock = mapOrphanBlocks[pblock->hashPrevBlock];
  return pblock->GetHash();
}

int64 CBlock::GetBlockValue(int64 nFees) const {
  int64 nSubsidy = 50 * COIN;

  // Subsidy is cut in half every 4 years
  nSubsidy >>= (nBestHeight / 210000);

  return nSubsidy + nFees;
}

unsigned int GetNextWorkRequired(const CBlockIndex *pindexLast) {
  const unsigned int nTargetTimespan = 14 * 24 * 60 * 60; // two weeks
  const unsigned int nTargetSpacing = 10 * 60;
  const unsigned int nInterval = nTargetTimespan / nTargetSpacing;

  // Genesis block
  if (pindexLast == NULL)
    return bnProofOfWorkLimit.GetCompact();

  // Only change once per interval
  if ((pindexLast->nHeight + 1) % nInterval != 0)
    return pindexLast->nBits;

  // Go back by what we want to be 14 days worth of blocks
  const CBlockIndex *pindexFirst = pindexLast;
  for (int i = 0; pindexFirst && i < nInterval - 1; i++)
    pindexFirst = pindexFirst->pprev;
  assert(pindexFirst);

  // Limit adjustment step
  unsigned int nActualTimespan = pindexLast->nTime - pindexFirst->nTime;
  printf("  nActualTimespan = %d  before bounds\n", nActualTimespan);
  if (nActualTimespan < nTargetTimespan / 4)
    nActualTimespan = nTargetTimespan / 4;
  if (nActualTimespan > nTargetTimespan * 4)
    nActualTimespan = nTargetTimespan * 4;

  // Retarget
  CBigNum bnNew;
  bnNew.SetCompact(pindexLast->nBits);
  bnNew *= nActualTimespan;
  bnNew /= nTargetTimespan;

  if (bnNew > bnProofOfWorkLimit)
    bnNew = bnProofOfWorkLimit;

  /// debug print
  printf("\n\n\nGetNextWorkRequired RETARGET *****\n");
  printf("nTargetTimespan = %d    nActualTimespan = %d\n", nTargetTimespan,
         nActualTimespan);
  printf(
      "Before: %08x  %s\n", pindexLast->nBits,
      CBigNum().SetCompact(pindexLast->nBits).getuint256().ToString().c_str());
  printf("After:  %08x  %s\n", bnNew.GetCompact(),
         bnNew.getuint256().ToString().c_str());

  return bnNew.GetCompact();
}

bool CTransaction::DisconnectInputs(CTxDB &txdb) {
  // Relinquish previous transactions' spent pointers
  if (!IsCoinBase()) {
    foreach (const CTxIn &txin, vin) {
      COutPoint prevout = txin.prevout;

      // Get prev txindex from disk
      CTxIndex txindex;
      if (!txdb.ReadTxIndex(prevout.hash, txindex))
        return error("DisconnectInputs() : ReadTxIndex failed");

      if (prevout.n >= txindex.vSpent.size())
        return error("DisconnectInputs() : prevout.n out of range");

      // Mark outpoint as not spent
      txindex.vSpent[prevout.n].SetNull();

      // Write back
      txdb.UpdateTxIndex(prevout.hash, txindex);
    }
  }

  // Remove transaction from index
  if (!txdb.EraseTxIndex(*this))
    return error("DisconnectInputs() : EraseTxPos failed");

  return true;
}

/**
 * 连接交易输入
 * 验证交易输入的有效性，检查签名、防止双重花费，并更新花费状态
 *
 * @param txdb 交易数据库，用于读写交易索引
 * @param mapTestPool 测试池映射，矿工挖矿时用于暂存未确认的交易索引变更
 * @param posThisTx 当前交易在磁盘上的位置（区块模式下）或占位符（矿工模式下）
 * @param nHeight 当前区块高度，用于币基交易成熟度检查
 * @param nFees 交易手续费的累加引用，函数会将当前交易的手续费加到该值上
 * @param fBlock 是否在区块连接模式下运行（区块被添加到链上时为true）
 * @param fMiner 是否在矿工挖矿模式下运行（矿工构建区块时为true）
 * @param nMinFee 最低手续费要求，低于此值的交易将被拒绝
 * @return 如果所有输入验证通过，返回true；否则返回false
 *
 * 主要验证步骤：
 * 1. 获取前序交易的索引和交易数据
 * 2. 检查输出索引是否越界
 * 3. 检查币基交易是否已成熟（100个确认）
 * 4. 验证交易签名（核心安全检查）
 * 5. 检查双重花费（输出是否已被使用）
 * 6. 标记输出为已花费
 * 7. 计算并验证交易手续费
 */
bool CTransaction::ConnectInputs(CTxDB &txdb,
                                 map<uint256, CTxIndex> &mapTestPool,
                                 CDiskTxPos posThisTx, int nHeight,
                                 int64 &nFees, bool fBlock, bool fMiner,
                                 int64 nMinFee) {
  // Take over previous transactions' spent pointers
  // 接管前序交易的花费指针，币基交易没有前序输入，跳过此步骤
  if (!IsCoinBase()) {
    int64 nValueIn = 0;
    for (int i = 0; i < vin.size(); i++) {
      COutPoint prevout = vin[i].prevout;

      // Read txindex
      // 读取前序交易的索引信息
      CTxIndex txindex;
      bool fFound = true;
      if (fMiner && mapTestPool.count(prevout.hash)) {
        // Get txindex from current proposed changes
        // 矿工模式下，优先从测试池中获取（测试池包含当前正在构建的区块中的交易索引）
        txindex = mapTestPool[prevout.hash];
      } else {
        // Read txindex from txdb
        // 非矿工模式或测试池中没有，从交易数据库中读取
        fFound = txdb.ReadTxIndex(prevout.hash, txindex);
      }
      // 如果未找到索引且在区块或矿工模式下，返回错误
      // 矿工模式下静默返回false，区块模式下输出错误日志
      if (!fFound && (fBlock || fMiner))
        return fMiner ? false
                      : error("ConnectInputs() : %s prev tx %s index entry not "
                              "found",
                              GetHash().ToString().substr(0, 6).c_str(),
                              prevout.hash.ToString().substr(0, 6).c_str());

      // Read txPrev
      // 读取前序交易的完整数据
      CTransaction txPrev;
      if (!fFound || txindex.pos == CDiskTxPos(1, 1, 1)) {
        // Get prev tx from single transactions in memory
        // 未找到索引或索引位置为占位符(1,1,1)时，从内存池中获取前序交易
        // 占位符(1,1,1)表示交易尚未写入磁盘，仍在内存池中
        CRITICAL_BLOCK(cs_mapTransactions) {
          if (!mapTransactions.count(prevout.hash))
            return error(
                "ConnectInputs() : %s mapTransactions prev not found %s",
                GetHash().ToString().substr(0, 6).c_str(),
                prevout.hash.ToString().substr(0, 6).c_str());
          txPrev = mapTransactions[prevout.hash];
        }
        // 如果索引未找到，初始化vSpent数组大小
        if (!fFound)
          txindex.vSpent.resize(txPrev.vout.size());
      } else {
        // Get prev tx from disk
        // 索引存在且位置有效时，从磁盘读取前序交易
        if (!txPrev.ReadFromDisk(txindex.pos))
          return error("ConnectInputs() : %s ReadFromDisk prev tx %s failed",
                       GetHash().ToString().substr(0, 6).c_str(),
                       prevout.hash.ToString().substr(0, 6).c_str());
      }

      // 检查输出索引是否越界
      // prevout.n 不能超过前序交易的输出数量和花费记录数量
      if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
        return error("ConnectInputs() : %s prevout.n out of range %d %d %d",
                     GetHash().ToString().substr(0, 6).c_str(), prevout.n,
                     txPrev.vout.size(), txindex.vSpent.size());

      // If prev is coinbase, check that it's matured
      // 如果前序交易是币基交易，检查其是否已成熟
      // 币基交易需要COINBASE_MATURITY（100）个确认才能被花费
      // 遍历最近的区块，检查币基交易所在区块是否在成熟度范围内
      if (txPrev.IsCoinBase())
        for (CBlockIndex *pindex = pindexBest;
             pindex && nBestHeight - pindex->nHeight < COINBASE_MATURITY - 1;
             pindex = pindex->pprev)
          if (pindex->nBlockPos == txindex.pos.nBlockPos &&
              pindex->nFile == txindex.pos.nFile)
            return error(
                "ConnectInputs() : tried to spend coinbase at depth %d",
                nBestHeight - pindex->nHeight);

      // Verify signature
      // 验证签名：核心安全检查
      // 使用前序交易的输出脚本(scriptPubKey)验证当前交易的输入脚本(scriptSig)
      // 确保交易确实由UTXO的拥有者签名授权
      if (!VerifySignature(txPrev, *this, i))
        return error("ConnectInputs() : %s VerifySignature failed",
                     GetHash().ToString().substr(0, 6).c_str());

      // Check for conflicts
      // 检查双重花费：如果该输出已被其他交易花费，则拒绝
      // vSpent[prevout.n]非空表示该输出已被引用
      if (!txindex.vSpent[prevout.n].IsNull())
        return fMiner ? false
                      : error("ConnectInputs() : %s prev tx already used at %s",
                              GetHash().ToString().substr(0, 6).c_str(),
                              txindex.vSpent[prevout.n].ToString().c_str());

      // Mark outpoints as spent
      // 标记输出为已花费，记录花费该输出的交易位置
      txindex.vSpent[prevout.n] = posThisTx;

      // Write back
      // 将更新后的交易索引写回
      if (fBlock)
        // 区块模式：直接更新数据库中的交易索引
        txdb.UpdateTxIndex(prevout.hash, txindex);
      else if (fMiner)
        // 矿工模式：更新测试池中的交易索引（尚未写入磁盘）
        mapTestPool[prevout.hash] = txindex;

      // 累加输入金额
      nValueIn += txPrev.vout[prevout.n].nValue;
    }

    // Tally transaction fees
    // 计算交易手续费 = 输入总额 - 输出总额
    int64 nTxFee = nValueIn - GetValueOut();
    // 手续费不能为负（输出不能超过输入）
    if (nTxFee < 0)
      return error("ConnectInputs() : %s nTxFee < 0",
                   GetHash().ToString().substr(0, 6).c_str());
    // 手续费不能低于最低要求
    if (nTxFee < nMinFee)
      return false;
    // 将手续费累加到总手续费中
    nFees += nTxFee;
  }

  // 根据运行模式将当前交易添加到索引
  if (fBlock) {
    // Add transaction to disk index
    // 区块模式：将交易添加到磁盘索引，记录其位置和高度
    if (!txdb.AddTxIndex(*this, posThisTx, nHeight))
      return error("ConnectInputs() : AddTxPos failed");
  } else if (fMiner) {
    // Add transaction to test pool
    // 矿工模式：将交易添加到测试池，使用占位符(1,1,1)表示尚未写入磁盘
    mapTestPool[GetHash()] = CTxIndex(CDiskTxPos(1, 1, 1), vout.size());
  }

  return true;
}

bool CTransaction::ClientConnectInputs() {
  if (IsCoinBase())
    return false;

  // Take over previous transactions' spent pointers
  CRITICAL_BLOCK(cs_mapTransactions) {
    int64 nValueIn = 0;
    for (int i = 0; i < vin.size(); i++) {
      // Get prev tx from single transactions in memory
      COutPoint prevout = vin[i].prevout;
      if (!mapTransactions.count(prevout.hash))
        return false;
      CTransaction &txPrev = mapTransactions[prevout.hash];

      if (prevout.n >= txPrev.vout.size())
        return false;

      // Verify signature
      if (!VerifySignature(txPrev, *this, i))
        return error("ConnectInputs() : VerifySignature failed");

      ///// this is redundant with the mapNextTx stuff, not sure which I want to
      /// get rid of
      ///// this has to go away now that posNext is gone
      // // Check for conflicts
      // if (!txPrev.vout[prevout.n].posNext.IsNull())
      //     return error("ConnectInputs() : prev tx already used");
      //
      // // Flag outpoints as used
      // txPrev.vout[prevout.n].posNext = posThisTx;

      nValueIn += txPrev.vout[prevout.n].nValue;
    }
    if (GetValueOut() > nValueIn)
      return false;
  }

  return true;
}

bool CBlock::DisconnectBlock(CTxDB &txdb, CBlockIndex *pindex) {
  // Disconnect in reverse order
  for (int i = vtx.size() - 1; i >= 0; i--)
    if (!vtx[i].DisconnectInputs(txdb))
      return false;

  // Update block index on disk without changing it in memory.
  // The memory index structure will be changed after the db commits.
  if (pindex->pprev) {
    CDiskBlockIndex blockindexPrev(pindex->pprev);
    blockindexPrev.hashNext = 0;
    txdb.WriteBlockIndex(blockindexPrev);
  }

  return true;
}

bool CBlock::ConnectBlock(CTxDB &txdb, CBlockIndex *pindex) {
  //// issue here: it doesn't know the version
  unsigned int nTxPos = pindex->nBlockPos +
                        ::GetSerializeSize(CBlock(), SER_DISK) - 1 +
                        GetSizeOfCompactSize(vtx.size());

  map<uint256, CTxIndex> mapUnused;
  int64 nFees = 0;
  foreach (CTransaction &tx, vtx) {
    CDiskTxPos posThisTx(pindex->nFile, pindex->nBlockPos, nTxPos);
    nTxPos += ::GetSerializeSize(tx, SER_DISK);

    if (!tx.ConnectInputs(txdb, mapUnused, posThisTx, pindex->nHeight, nFees,
                          true, false))
      return false;
  }

  if (vtx[0].GetValueOut() > GetBlockValue(nFees))
    return false;

  // Update block index on disk without changing it in memory.
  // The memory index structure will be changed after the db commits.
  if (pindex->pprev) {
    CDiskBlockIndex blockindexPrev(pindex->pprev);
    blockindexPrev.hashNext = pindex->GetBlockHash();
    txdb.WriteBlockIndex(blockindexPrev);
  }

  // Watch for transactions paying to me
  foreach (CTransaction &tx, vtx)
    AddToWalletIfMine(tx, this);

  return true;
}

bool Reorganize(CTxDB &txdb, CBlockIndex *pindexNew) {
  printf("*** REORGANIZE ***\n");

  // Find the fork
  CBlockIndex *pfork = pindexBest;
  CBlockIndex *plonger = pindexNew;
  while (pfork != plonger) {
    if (!(pfork = pfork->pprev))
      return error("Reorganize() : pfork->pprev is null");
    while (plonger->nHeight > pfork->nHeight)
      if (!(plonger = plonger->pprev))
        return error("Reorganize() : plonger->pprev is null");
  }

  // List of what to disconnect
  vector<CBlockIndex *> vDisconnect;
  for (CBlockIndex *pindex = pindexBest; pindex != pfork;
       pindex = pindex->pprev)
    vDisconnect.push_back(pindex);

  // List of what to connect
  vector<CBlockIndex *> vConnect;
  for (CBlockIndex *pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
    vConnect.push_back(pindex);
  reverse(vConnect.begin(), vConnect.end());

  // Disconnect shorter branch
  vector<CTransaction> vResurrect;
  foreach (CBlockIndex *pindex, vDisconnect) {
    CBlock block;
    if (!block.ReadFromDisk(pindex->nFile, pindex->nBlockPos, true))
      return error("Reorganize() : ReadFromDisk for disconnect failed");
    if (!block.DisconnectBlock(txdb, pindex))
      return error("Reorganize() : DisconnectBlock failed");

    // Queue memory transactions to resurrect
    foreach (const CTransaction &tx, block.vtx)
      if (!tx.IsCoinBase())
        vResurrect.push_back(tx);
  }

  // Connect longer branch
  vector<CTransaction> vDelete;
  for (int i = 0; i < vConnect.size(); i++) {
    CBlockIndex *pindex = vConnect[i];
    CBlock block;
    if (!block.ReadFromDisk(pindex->nFile, pindex->nBlockPos, true))
      return error("Reorganize() : ReadFromDisk for connect failed");
    if (!block.ConnectBlock(txdb, pindex)) {
      // Invalid block, delete the rest of this branch
      txdb.TxnAbort();
      for (int j = i; j < vConnect.size(); j++) {
        CBlockIndex *pindex = vConnect[j];
        pindex->EraseBlockFromDisk();
        txdb.EraseBlockIndex(pindex->GetBlockHash());
        mapBlockIndex.erase(pindex->GetBlockHash());
        delete pindex;
      }
      return error("Reorganize() : ConnectBlock failed");
    }

    // Queue memory transactions to delete
    foreach (const CTransaction &tx, block.vtx)
      vDelete.push_back(tx);
  }
  if (!txdb.WriteHashBestChain(pindexNew->GetBlockHash()))
    return error("Reorganize() : WriteHashBestChain failed");

  // Commit now because resurrecting could take some time
  txdb.TxnCommit();

  // Disconnect shorter branch
  foreach (CBlockIndex *pindex, vDisconnect)
    if (pindex->pprev)
      pindex->pprev->pnext = NULL;

  // Connect longer branch
  foreach (CBlockIndex *pindex, vConnect)
    if (pindex->pprev)
      pindex->pprev->pnext = pindex;

  // Resurrect memory transactions that were in the disconnected branch
  foreach (CTransaction &tx, vResurrect)
    tx.AcceptTransaction(txdb, false);

  // Delete redundant memory transactions that are in the connected branch
  foreach (CTransaction &tx, vDelete)
    tx.RemoveFromMemoryPool();

  return true;
}

bool CBlock::AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos) {
  // Check for duplicate
  uint256 hash = GetHash();
  if (mapBlockIndex.count(hash))
    return error("AddToBlockIndex() : %s already exists",
                 hash.ToString().substr(0, 14).c_str());

  // Construct new block index object
  CBlockIndex *pindexNew = new CBlockIndex(nFile, nBlockPos, *this);
  if (!pindexNew)
    return error("AddToBlockIndex() : new CBlockIndex failed");
  map<uint256, CBlockIndex *>::iterator mi =
      mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
  pindexNew->phashBlock = &((*mi).first);
  map<uint256, CBlockIndex *>::iterator miPrev =
      mapBlockIndex.find(hashPrevBlock);
  if (miPrev != mapBlockIndex.end()) {
    pindexNew->pprev = (*miPrev).second;
    pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
  }

  CTxDB txdb;
  txdb.TxnBegin();
  txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew));

  // New best
  if (pindexNew->nHeight > nBestHeight) {
    if (pindexGenesisBlock == NULL && hash == hashGenesisBlock) {
      pindexGenesisBlock = pindexNew;
      txdb.WriteHashBestChain(hash);
    } else if (hashPrevBlock == hashBestChain) {
      // Adding to current best branch
      if (!ConnectBlock(txdb, pindexNew) || !txdb.WriteHashBestChain(hash)) {
        txdb.TxnAbort();
        pindexNew->EraseBlockFromDisk();
        mapBlockIndex.erase(pindexNew->GetBlockHash());
        delete pindexNew;
        return error("AddToBlockIndex() : ConnectBlock failed");
      }
      txdb.TxnCommit();
      pindexNew->pprev->pnext = pindexNew;

      // Delete redundant memory transactions
      foreach (CTransaction &tx, vtx)
        tx.RemoveFromMemoryPool();
    } else {
      // New best branch
      if (!Reorganize(txdb, pindexNew)) {
        txdb.TxnAbort();
        return error("AddToBlockIndex() : Reorganize failed");
      }
    }

    // New best link
    hashBestChain = hash;
    pindexBest = pindexNew;
    nBestHeight = pindexBest->nHeight;
    nTransactionsUpdated++;
    printf("AddToBlockIndex: new best=%s  height=%d\n",
           hashBestChain.ToString().substr(0, 14).c_str(), nBestHeight);
  }

  txdb.TxnCommit();
  txdb.Close();

  // Relay wallet transactions that haven't gotten in yet
  if (pindexNew == pindexBest)
    RelayWalletTransactions();

  MainFrameRepaint();
  return true;
}

bool CBlock::CheckBlock() const {
  // These are checks that are independent of context
  // that can be verified before saving an orphan block.

  // Size limits
  if (vtx.empty() || vtx.size() > MAX_SIZE ||
      ::GetSerializeSize(*this, SER_DISK) > MAX_SIZE)
    return error("CheckBlock() : size limits failed");

  // Check timestamp
  if (nTime > GetAdjustedTime() + 2 * 60 * 60)
    return error("CheckBlock() : block timestamp too far in the future");

  // First transaction must be coinbase, the rest must not be
  if (vtx.empty() || !vtx[0].IsCoinBase())
    return error("CheckBlock() : first tx is not coinbase");
  for (int i = 1; i < vtx.size(); i++)
    if (vtx[i].IsCoinBase())
      return error("CheckBlock() : more than one coinbase");

  // Check transactions
  foreach (const CTransaction &tx, vtx)
    if (!tx.CheckTransaction())
      return error("CheckBlock() : CheckTransaction failed");

  // Check proof of work matches claimed amount
  if (CBigNum().SetCompact(nBits) > bnProofOfWorkLimit)
    return error("CheckBlock() : nBits below minimum work");
  if (GetHash() > CBigNum().SetCompact(nBits).getuint256())
    return error("CheckBlock() : hash doesn't match nBits");

  // Check merkleroot
  if (hashMerkleRoot != BuildMerkleTree())
    return error("CheckBlock() : hashMerkleRoot mismatch");

  return true;
}

bool CBlock::AcceptBlock() {
  // Check for duplicate
  uint256 hash = GetHash();
  if (mapBlockIndex.count(hash))
    return error("AcceptBlock() : block already in mapBlockIndex");

  // Get prev block index
  map<uint256, CBlockIndex *>::iterator mi = mapBlockIndex.find(hashPrevBlock);
  if (mi == mapBlockIndex.end())
    return error("AcceptBlock() : prev block not found");
  CBlockIndex *pindexPrev = (*mi).second;

  // Check timestamp against prev
  if (nTime <= pindexPrev->GetMedianTimePast())
    return error("AcceptBlock() : block's timestamp is too early");

  // Check proof of work
  if (nBits != GetNextWorkRequired(pindexPrev))
    return error("AcceptBlock() : incorrect proof of work");

  // Write block to history file
  unsigned int nFile;
  unsigned int nBlockPos;
  if (!WriteToDisk(!fClient, nFile, nBlockPos))
    return error("AcceptBlock() : WriteToDisk failed");
  if (!AddToBlockIndex(nFile, nBlockPos))
    return error("AcceptBlock() : AddToBlockIndex failed");

  if (hashBestChain == hash)
    RelayInventory(CInv(MSG_BLOCK, hash));

  // // Add atoms to user reviews for coins created
  // vector<unsigned char> vchPubKey;
  // if (ExtractPubKey(vtx[0].vout[0].scriptPubKey, false, vchPubKey))
  // {
  //     unsigned short nAtom = GetRand(USHRT_MAX - 100) + 100;
  //     vector<unsigned short> vAtoms(1, nAtom);
  //     AddAtomsAndPropagate(Hash(vchPubKey.begin(), vchPubKey.end()), vAtoms,
  //     true);
  // }

  return true;
}

bool ProcessBlock(CNode *pfrom, CBlock *pblock) {
  // Check for duplicate
  uint256 hash = pblock->GetHash();
  if (mapBlockIndex.count(hash))
    return error("ProcessBlock() : already have block %d %s",
                 mapBlockIndex[hash]->nHeight,
                 hash.ToString().substr(0, 14).c_str());
  if (mapOrphanBlocks.count(hash))
    return error("ProcessBlock() : already have block (orphan) %s",
                 hash.ToString().substr(0, 14).c_str());

  // Preliminary checks
  if (!pblock->CheckBlock()) {
    delete pblock;
    return error("ProcessBlock() : CheckBlock FAILED");
  }

  // If don't already have its previous block, shunt it off to holding area
  // until we get it
  if (!mapBlockIndex.count(pblock->hashPrevBlock)) {
    printf("ProcessBlock: ORPHAN BLOCK, prev=%s\n",
           pblock->hashPrevBlock.ToString().substr(0, 14).c_str());
    mapOrphanBlocks.insert(make_pair(hash, pblock));
    mapOrphanBlocksByPrev.insert(make_pair(pblock->hashPrevBlock, pblock));

    // Ask this guy to fill in what we're missing
    if (pfrom)
      pfrom->PushMessage("getblocks", CBlockLocator(pindexBest),
                         GetOrphanRoot(pblock));
    return true;
  }

  // Store to disk
  if (!pblock->AcceptBlock()) {
    delete pblock;
    return error("ProcessBlock() : AcceptBlock FAILED");
  }
  delete pblock;

  // Recursively process any orphan blocks that depended on this one
  vector<uint256> vWorkQueue;
  vWorkQueue.push_back(hash);
  for (int i = 0; i < vWorkQueue.size(); i++) {
    uint256 hashPrev = vWorkQueue[i];
    for (multimap<uint256, CBlock *>::iterator mi =
             mapOrphanBlocksByPrev.lower_bound(hashPrev);
         mi != mapOrphanBlocksByPrev.upper_bound(hashPrev); ++mi) {
      CBlock *pblockOrphan = (*mi).second;
      if (pblockOrphan->AcceptBlock())
        vWorkQueue.push_back(pblockOrphan->GetHash());
      mapOrphanBlocks.erase(pblockOrphan->GetHash());
      delete pblockOrphan;
    }
    mapOrphanBlocksByPrev.erase(hashPrev);
  }

  printf("ProcessBlock: ACCEPTED\n");
  return true;
}

template <typename Stream> bool ScanMessageStart(Stream &s) {
  // Scan ahead to the next pchMessageStart, which should normally be
  // immediately at the file pointer.  Leaves file pointer at end of
  // pchMessageStart.
  s.clear(0);
  short prevmask = s.exceptions(0);
  const char *p = BEGIN(pchMessageStart);
  try {
    loop {
      char c;
      s.read(&c, 1);
      if (s.fail()) {
        s.clear(0);
        s.exceptions(prevmask);
        return false;
      }
      if (*p != c)
        p = BEGIN(pchMessageStart);
      if (*p == c) {
        if (++p == END(pchMessageStart)) {
          s.clear(0);
          s.exceptions(prevmask);
          return true;
        }
      }
    }
  } catch (...) {
    s.clear(0);
    s.exceptions(prevmask);
    return false;
  }
}

string GetAppDir() {
  string strDir;
  if (!strSetDataDir.empty()) {
    strDir = strSetDataDir;
  } else if (getenv("APPDATA")) {
    strDir = strprintf("%s\\Bitcoin", getenv("APPDATA"));
  } else if (getenv("USERPROFILE")) {
    string strAppData =
        strprintf("%s\\Application Data", getenv("USERPROFILE"));
    static bool fMkdirDone;
    if (!fMkdirDone) {
      fMkdirDone = true;
      _mkdir(strAppData.c_str());
    }
    strDir = strprintf("%s\\Bitcoin", strAppData.c_str());
  } else {
    return ".";
  }
  static bool fMkdirDone;
  if (!fMkdirDone) {
    fMkdirDone = true;
    _mkdir(strDir.c_str());
  }
  return strDir;
}

FILE *OpenBlockFile(unsigned int nFile, unsigned int nBlockPos,
                    const char *pszMode) {
  if (nFile == -1)
    return NULL;
  FILE *file =
      fopen(strprintf("%s\\blk%04d.dat", GetAppDir().c_str(), nFile).c_str(),
            pszMode);
  if (!file)
    return NULL;
  if (nBlockPos != 0 && !strchr(pszMode, 'a') && !strchr(pszMode, 'w')) {
    if (fseek(file, nBlockPos, SEEK_SET) != 0) {
      fclose(file);
      return NULL;
    }
  }
  return file;
}

static unsigned int nCurrentBlockFile = 1;

FILE *AppendBlockFile(unsigned int &nFileRet) {
  nFileRet = 0;
  loop {
    FILE *file = OpenBlockFile(nCurrentBlockFile, 0, "ab");
    if (!file)
      return NULL;
    if (fseek(file, 0, SEEK_END) != 0)
      return NULL;
    // FAT32 filesize max 4GB, fseek and ftell max 2GB, so we must stay under
    // 2GB
    if (ftell(file) < 0x7F000000 - MAX_SIZE) {
      nFileRet = nCurrentBlockFile;
      return file;
    }
    fclose(file);
    nCurrentBlockFile++;
  }
}

bool LoadBlockIndex(bool fAllowNew) {
  //
  // Load block index
  //
  CTxDB txdb("cr");
  if (!txdb.LoadBlockIndex())
    return false;
  txdb.Close();

  //
  // Init with genesis block
  //
  if (mapBlockIndex.empty()) {
    if (!fAllowNew)
      return false;

    // Genesis Block:
    // GetHash()      =
    // 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
    // hashMerkleRoot =
    // 0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
    // txNew.vin[0].scriptSig     = 486604799 4
    // 0x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854
    // txNew.vout[0].nValue       = 5000000000
    // txNew.vout[0].scriptPubKey =
    // 0x5F1DF16B2B704C8A578D0BBAF74D385CDE12C11EE50455F3C438EF4C3FBCF649B6DE611FEAE06279A60939E028A8D65C10B73071A6F16719274855FEB0FD8A6704
    // OP_CHECKSIG block.nVersion = 1 block.nTime    = 1231006505 block.nBits =
    // 0x1d00ffff block.nNonce   = 2083236893 CBlock(hash=000000000019d6, ver=1,
    // hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505,
    // nBits=1d00ffff, nNonce=2083236893, vtx=1)
    //   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
    //     CTxIn(COutPoint(000000, -1), coinbase
    //     04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
    //     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
    //   vMerkleTree: 4a5e1e

    // Genesis block
    char *pszTimestamp =
        "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig =
        CScript() << 486604799 << CBigNum(4)
                  << vector<unsigned char>((unsigned char *)pszTimestamp,
                                           (unsigned char *)pszTimestamp +
                                               strlen(pszTimestamp));
    txNew.vout[0].nValue = 50 * COIN;
    txNew.vout[0].scriptPubKey =
        CScript() << CBigNum("0x5F1DF16B2B704C8A578D0BBAF74D385CDE12C11EE50455F"
                             "3C438EF4C3FBCF649B6DE611FEAE06279A60939E028A8D65C"
                             "10B73071A6F16719274855FEB0FD8A6704")
                  << OP_CHECKSIG;
    CBlock block;
    block.vtx.push_back(txNew);
    block.hashPrevBlock = 0;
    block.hashMerkleRoot = block.BuildMerkleTree();
    block.nVersion = 1;
    block.nTime = 1231006505;
    block.nBits = 0x1d00ffff;
    block.nNonce = 2083236893;

    //// debug print, delete this later
    printf("%s\n", block.GetHash().ToString().c_str());
    printf("%s\n", block.hashMerkleRoot.ToString().c_str());
    printf("%s\n", hashGenesisBlock.ToString().c_str());
    txNew.vout[0].scriptPubKey.print();
    block.print();
    assert(block.hashMerkleRoot == uint256("0x4a5e1e4baab89f3a32518a88c31bc87f6"
                                           "18f76673e2cc77ab2127b7afdeda33b"));

    assert(block.GetHash() == hashGenesisBlock);

    // Start new block file
    unsigned int nFile;
    unsigned int nBlockPos;
    if (!block.WriteToDisk(!fClient, nFile, nBlockPos))
      return error("LoadBlockIndex() : writing genesis block to disk failed");
    if (!block.AddToBlockIndex(nFile, nBlockPos))
      return error("LoadBlockIndex() : genesis block not accepted");
  }

  return true;
}

void PrintBlockTree() {
  // precompute tree structure
  map<CBlockIndex *, vector<CBlockIndex *>> mapNext;
  for (map<uint256, CBlockIndex *>::iterator mi = mapBlockIndex.begin();
       mi != mapBlockIndex.end(); ++mi) {
    CBlockIndex *pindex = (*mi).second;
    mapNext[pindex->pprev].push_back(pindex);
    // test
    // while (rand() % 3 == 0)
    //    mapNext[pindex->pprev].push_back(pindex);
  }

  vector<pair<int, CBlockIndex *>> vStack;
  vStack.push_back(make_pair(0, pindexGenesisBlock));

  int nPrevCol = 0;
  while (!vStack.empty()) {
    int nCol = vStack.back().first;
    CBlockIndex *pindex = vStack.back().second;
    vStack.pop_back();

    // print split or gap
    if (nCol > nPrevCol) {
      for (int i = 0; i < nCol - 1; i++)
        printf("| ");
      printf("|\\\n");
    } else if (nCol < nPrevCol) {
      for (int i = 0; i < nCol; i++)
        printf("| ");
      printf("|\n");
    }
    nPrevCol = nCol;

    // print columns
    for (int i = 0; i < nCol; i++)
      printf("| ");

    // print item
    CBlock block;
    block.ReadFromDisk(pindex, true);
    printf("%d (%u,%u) %s  %s  tx %d", pindex->nHeight, pindex->nFile,
           pindex->nBlockPos, block.GetHash().ToString().substr(0, 14).c_str(),
           DateTimeStr(block.nTime).c_str(), block.vtx.size());

    CRITICAL_BLOCK(cs_mapWallet) {
      if (mapWallet.count(block.vtx[0].GetHash())) {
        CWalletTx &wtx = mapWallet[block.vtx[0].GetHash()];
        printf("    mine:  %d  %d  %d", wtx.GetDepthInMainChain(),
               wtx.GetBlocksToMaturity(), wtx.GetCredit());
      }
    }
    printf("\n");

    // put the main timechain first
    vector<CBlockIndex *> &vNext = mapNext[pindex];
    for (int i = 0; i < vNext.size(); i++) {
      if (vNext[i]->pnext) {
        swap(vNext[0], vNext[i]);
        break;
      }
    }

    // iterate children
    for (int i = 0; i < vNext.size(); i++)
      vStack.push_back(make_pair(nCol + i, vNext[i]));
  }
}

//////////////////////////////////////////////////////////////////////////////
//
// Messages
//

bool AlreadyHave(CTxDB &txdb, const CInv &inv) {
  switch (inv.type) {
  case MSG_TX:
    return mapTransactions.count(inv.hash) || txdb.ContainsTx(inv.hash);
  case MSG_BLOCK:
    return mapBlockIndex.count(inv.hash) || mapOrphanBlocks.count(inv.hash);
  case MSG_REVIEW:
    return true;
  case MSG_PRODUCT:
    return mapProducts.count(inv.hash);
  }
  // Don't know what it is, just say we already got one
  return true;
}

bool ProcessMessages(CNode *pfrom) {
  CDataStream &vRecv = pfrom->vRecv;
  if (vRecv.empty())
    return true;
  printf("ProcessMessages(%d bytes)\n", vRecv.size());

  //
  // Message format
  //  (4) message start
  //  (12) command
  //  (4) size
  //  (x) data
  //

  loop {
    // Scan for message start
    CDataStream::iterator pstart =
        search(vRecv.begin(), vRecv.end(), BEGIN(pchMessageStart),
               END(pchMessageStart));
    if (vRecv.end() - pstart < sizeof(CMessageHeader)) {
      if (vRecv.size() > sizeof(CMessageHeader)) {
        printf("\n\nPROCESSMESSAGE MESSAGESTART NOT FOUND\n\n");
        vRecv.erase(vRecv.begin(), vRecv.end() - sizeof(CMessageHeader));
      }
      break;
    }
    if (pstart - vRecv.begin() > 0)
      printf("\n\nPROCESSMESSAGE SKIPPED %d BYTES\n\n", pstart - vRecv.begin());
    vRecv.erase(vRecv.begin(), pstart);

    // Read header
    CMessageHeader hdr;
    vRecv >> hdr;
    if (!hdr.IsValid()) {
      printf("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n",
             hdr.GetCommand().c_str());
      continue;
    }
    string strCommand = hdr.GetCommand();

    // Message size
    unsigned int nMessageSize = hdr.nMessageSize;
    if (nMessageSize > vRecv.size()) {
      // Rewind and wait for rest of message
      ///// need a mechanism to give up waiting for overlong message size error
      printf("MESSAGE-BREAK 2\n");
      vRecv.insert(vRecv.begin(), BEGIN(hdr), END(hdr));
      Sleep(100);
      break;
    }

    // Copy message to its own buffer
    CDataStream vMsg(vRecv.begin(), vRecv.begin() + nMessageSize, vRecv.nType,
                     vRecv.nVersion);
    vRecv.ignore(nMessageSize);

    // Process message
    bool fRet = false;
    try {
      CheckForShutdown(2);
      CRITICAL_BLOCK(cs_main)
      fRet = ProcessMessage(pfrom, strCommand, vMsg);
      CheckForShutdown(2);
    }
    CATCH_PRINT_EXCEPTION("ProcessMessage()")
    if (!fRet)
      printf("ProcessMessage(%s, %d bytes) from %s to %s FAILED\n",
             strCommand.c_str(), nMessageSize, pfrom->addr.ToString().c_str(),
             addrLocalHost.ToString().c_str());
  }

  vRecv.Compact();
  return true;
}

// ============================================================================
// 消息处理核心函数 - 处理从P2P网络接收到的各种消息
// 参数说明：
//   pfrom: 发送消息的节点指针
//   strCommand: 消息类型命令字符串（如"version"、"addr"、"inv"等）
//   vRecv: 接收到的消息数据流
// 返回值：
//   true: 消息处理成功
//   false: 消息处理失败（如协议错误）
// ============================================================================
bool ProcessMessage(CNode *pfrom, string strCommand, CDataStream &vRecv) {
  // ============================================================================
  // 静态变量：用于订单处理中的密钥重用机制
  // 作用：为同一IP地址重复使用相同的公钥，直到该IP使用该密钥完成交易
  // 这样可以简化订单处理流程，避免为每个订单生成新密钥
  // ============================================================================
  static map<unsigned int, vector<unsigned char>> mapReuseKey;

  // ============================================================================
  // 调试输出：打印接收到的消息信息
  // 输出内容包括：消息类型、消息大小、前25字节的十六进制表示
  // 这对于调试网络协议和消息格式非常有用
  // ============================================================================
  printf("received: %-12s (%d bytes)  ", strCommand.c_str(), vRecv.size());
  for (int i = 0; i < min(vRecv.size(), (unsigned int)25); i++)
    printf("%02x ", vRecv[i] & 0xff);
  printf("\n");

  // ============================================================================
  // 测试模式：随机丢弃消息以测试网络容错能力
  // nDropMessagesTest > 0时，以1/nDropMessagesTest的概率随机丢弃消息
  // 这是用于测试网络在消息丢失情况下的行为
  // ============================================================================
  if (nDropMessagesTest > 0 && GetRand(nDropMessagesTest) == 0) {
    printf("dropmessages DROPPING RECV MESSAGE\n");
    return true; // 返回true表示消息已处理（被丢弃）
  }

  // ============================================================================
  // 消息类型处理：version - 版本握手消息
  // 这是P2P连接建立后的第一条消息，用于协商协议版本和服务类型
  // ============================================================================
  if (strCommand == "version") {
    // 版本消息只能接收一次，防止重复处理
    // 如果pfrom->nVersion != 0，说明已经处理过版本消息
    if (pfrom->nVersion != 0)
      return false; // 返回false表示协议错误

    // 从消息流中读取版本信息
    int64 nTime;     // 对方节点的时间戳
    CAddress addrMe; // 对方节点认为的我的地址

    // 解析版本消息：版本号、服务标志、时间戳、地址
    vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;

    // 验证版本号有效性（不能为0）
    if (pfrom->nVersion == 0)
      return false;

    // 设置发送和接收流的版本号
    // 使用双方版本号的较小值，确保兼容性
    pfrom->vSend.SetVersion(min(pfrom->nVersion, VERSION));
    pfrom->vRecv.SetVersion(min(pfrom->nVersion, VERSION));

    // 判断对方是否为客户端节点
    // NODE_NETWORK标志表示该节点是全节点，提供完整服务
    // 如果没有NODE_NETWORK标志，则是轻量级客户端，只请求自己需要的数据
    pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);

    // 如果对方是轻量级客户端，优化数据传输
    // 只发送区块头，不发送完整的区块内容
    if (pfrom->fClient) {
      pfrom->vSend.nType |= SER_BLOCKHEADERONLY; // 发送流只包含区块头
      pfrom->vRecv.nType |= SER_BLOCKHEADERONLY; // 接收流只包含区块头
    }

    // 记录时间数据用于网络时间同步
    // 通过收集多个节点的时间戳，可以计算出更准确的网络时间
    AddTimeData(pfrom->addr.ip, nTime);

    // 向第一个连接的非客户端节点请求区块更新
    // 静态变量fAskedForBlocks确保只向一个节点请求，避免重复请求
    static bool fAskedForBlocks;
    if (!fAskedForBlocks && !pfrom->fClient) {
      fAskedForBlocks = true; // 标记已请求过区块

      // 发送getblocks消息，请求从当前最佳区块开始的区块
      // CBlockLocator(pindexBest)表示从当前最佳区块开始
      // uint256(0)表示请求直到链的末端
      pfrom->PushMessage("getblocks", CBlockLocator(pindexBest), uint256(0));
    }

    // 调试输出：打印对方认为的我的地址
    printf("version addrMe = %s\n", addrMe.ToString().c_str());
  }

  // ============================================================================
  // 版本检查：确保在接收其他消息之前已经完成了版本握手
  // 如果pfrom->nVersion == 0，说明还没有收到version消息
  // 这种情况下拒绝处理任何其他消息，防止协议混乱
  // ============================================================================
  else if (pfrom->nVersion == 0) {
    // 必须先收到version消息才能处理其他消息
    return false;
  }

  // ============================================================================
  // 消息类型处理：addr - 地址消息
  // 用于交换网络中的节点地址，帮助节点发现新的对等节点
  // ============================================================================
  else if (strCommand == "addr") {
    // 从消息流中读取地址列表
    vector<CAddress> vAddr;
    vRecv >> vAddr;

    // 打开地址数据库，用于持久化存储节点地址
    CAddrDB addrdb;

    // 遍历收到的每个地址
    foreach (const CAddress &addr, vAddr) {
      // 检查是否正在关闭程序
      if (fShutdown)
        return true; // 正常退出，返回true

      // 尝试将新地址添加到地址管理器
      // AddAddress会检查地址是否已存在，并更新地址的时间戳
      if (AddAddress(addrdb, addr)) {
        // 如果地址是新的，将其添加到发送队列中
        // 这样可以将新地址传播给其他节点

        // 将地址标记为已知，避免重复发送给同一节点
        pfrom->setAddrKnown.insert(addr);

        // 遍历所有连接的节点，将新地址加入它们的发送队列
        CRITICAL_BLOCK(cs_vNodes) // 临界区保护，确保线程安全
        foreach (CNode *pnode, vNodes)
          // 只向不知道该地址的节点发送
          if (!pnode->setAddrKnown.count(addr))
            pnode->vAddrToSend.push_back(addr); // 加入发送队列
      }
    }
  }

  // ============================================================================
  // 消息类型处理：inv - 库存消息
  // 用于通知对方节点有哪些数据对象可用（交易、区块、评论等）
  // 这是比特币P2P网络中数据发现的核心机制
  // ============================================================================
  else if (strCommand == "inv") {
    // 从消息流中读取库存列表
    vector<CInv> vInv;
    vRecv >> vInv;

    // 打开交易数据库（只读模式），用于检查是否已有相关数据
    CTxDB txdb("r");

    // 遍历每个库存项
    foreach (const CInv &inv, vInv) {
      // 检查是否正在关闭程序
      if (fShutdown)
        return true;

      // 将库存项标记为已知，避免重复请求
      // 这是防止重复请求的重要机制
      pfrom->AddInventoryKnown(inv);

      // 检查本地是否已有该数据
      bool fAlreadyHave = AlreadyHave(txdb, inv);
      printf("  got inventory: %s  %s\n", inv.ToString().c_str(),
             fAlreadyHave ? "have" : "new");

      // 如果本地没有该数据，向对方请求
      if (!fAlreadyHave)
        pfrom->AskFor(inv); // 将请求加入优先队列，稍后发送getdata消息
      // 特殊处理：如果是区块且在孤儿区块映射中存在
      // 说明该区块的前驱区块还未收到，需要请求前驱区块
      else if (inv.type == MSG_BLOCK && mapOrphanBlocks.count(inv.hash))
        pfrom->PushMessage("getblocks", CBlockLocator(pindexBest),
                           GetOrphanRoot(mapOrphanBlocks[inv.hash]));
    }
  }

  // ============================================================================
  // 消息类型处理：getdata - 数据请求消息
  // 用于请求具体的交易、区块、评论等数据对象
  // ============================================================================
  else if (strCommand == "getdata") {
    // 从消息流中读取请求的数据列表
    vector<CInv> vInv;
    vRecv >> vInv;

    // 遍历每个请求的数据项
    foreach (const CInv &inv, vInv) {
      // 检查是否正在关闭程序
      if (fShutdown)
        return true;

      // 调试输出：打印请求的数据
      printf("received getdata for: %s\n", inv.ToString().c_str());

      // 处理区块请求
      if (inv.type == MSG_BLOCK) {
        // 从磁盘读取区块数据
        // mapBlockIndex是全局的区块索引映射
        map<uint256, CBlockIndex *>::iterator mi = mapBlockIndex.find(inv.hash);
        if (mi != mapBlockIndex.end()) {
          // 优化建议：可以直接从blockindex发送区块头给客户端
          // 而不需要读取完整的区块数据
          CBlock block;
          // 从磁盘读取区块
          // !pfrom->fClient表示如果对方是客户端，可以优化传输
          block.ReadFromDisk((*mi).second, !pfrom->fClient);
          // 发送区块数据给请求节点
          pfrom->PushMessage("block", block);
        }
      }
      // 处理其他已知类型的数据请求（交易、评论等）
      else if (inv.IsKnownType()) {
        // 从中继内存中发送数据流
        // mapRelay是全局的中继消息缓存，保存最近收到的消息
        CRITICAL_BLOCK(cs_mapRelay) { // 临界区保护，确保线程安全
          map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
          if (mi != mapRelay.end())
            // 直接发送原始消息流，保持原始格式
            // 这可以处理版本兼容性问题
            pfrom->PushMessage(inv.GetCommand(), (*mi).second);
        }
      }
    }
  }

  // ============================================================================
  // 消息类型处理：getblocks - 区块请求消息
  // 用于请求从某个位置开始的区块列表
  // 这是区块链同步的核心机制
  // ============================================================================
  else if (strCommand == "getblocks") {
    // 从消息流中读取区块定位符和停止哈希
    CBlockLocator locator; // 区块定位符，表示请求者已知的最新区块
    uint256 hashStop;      // 停止哈希，表示请求到此区块为止
    vRecv >> locator >> hashStop;

    // 根据定位符找到请求者在主链上的第一个区块
    // locator.GetBlockIndex()会返回请求者已知的最新区块索引
    CBlockIndex *pindex = locator.GetBlockIndex();

    // 从该区块的下一个区块开始发送
    // 因为请求者已经有该区块，所以从下一个开始
    if (pindex)
      pindex = pindex->pnext;

    // 调试输出：打印请求的区块范围
    printf("getblocks %d to %s\n", (pindex ? pindex->nHeight : -1),
           hashStop.ToString().substr(0, 14).c_str());

    // 遍历区块链，发送区块库存
    for (; pindex; pindex = pindex->pnext) {
      // 检查是否到达停止哈希
      if (pindex->GetBlockHash() == hashStop) {
        printf("  getblocks stopping at %d %s\n", pindex->nHeight,
               pindex->GetBlockHash().ToString().substr(0, 14).c_str());
        break; // 到达停止点，停止发送
      }

      // 绕过setInventoryKnown，防止库存消息丢失导致区块无法同步
      // 使用setInventoryKnown2作为临时集合，确保消息能够到达
      CRITICAL_BLOCK(pfrom->cs_inventory) { // 临界区保护，确保线程安全
        CInv inv(MSG_BLOCK, pindex->GetBlockHash());
        // 如果不在setInventoryKnown2中，说明是新的库存项
        if (pfrom->setInventoryKnown2.insert(inv).second) {
          // 从setInventoryKnown中移除，允许重新发送
          pfrom->setInventoryKnown.erase(inv);
          // 加入发送队列
          pfrom->vInventoryToSend.push_back(inv);
        }
      }
    }
  }

  // ============================================================================
  // 消息类型处理：tx - 交易消息
  // 用于接收和广播新的交易
  // 这是比特币交易传播的核心机制
  // ============================================================================
  else if (strCommand == "tx") {
    // 工作队列：用于处理依赖此交易的孤儿交易
    vector<uint256> vWorkQueue;

    // 保存原始消息流，用于转发
    CDataStream vMsg(vRecv);

    // 从消息流中读取交易数据
    CTransaction tx;
    vRecv >> tx;

    // 创建交易库存项
    CInv inv(MSG_TX, tx.GetHash());
    pfrom->AddInventoryKnown(inv); // 标记为已知，避免重复处理

    // 标记是否缺少输入
    bool fMissingInputs = false;

    // 尝试接受交易
    // AcceptTransaction会验证交易的有效性，包括签名、输入输出等
    if (tx.AcceptTransaction(true, &fMissingInputs)) {
      // 如果交易属于本节点（输入使用本节点的私钥），添加到钱包
      AddToWalletIfMine(tx, NULL);

      // 广播交易到网络
      // 使用原始消息流，保持原始格式
      RelayMessage(inv, vMsg);

      // 从已请求列表中移除，避免重复请求
      mapAlreadyAskedFor.erase(inv);

      // 将交易哈希加入工作队列
      vWorkQueue.push_back(inv.hash);

      // 递归处理依赖此交易的孤儿交易
      // 孤儿交易是指缺少输入的交易，当其输入交易到达后，可以重新处理
      for (int i = 0; i < vWorkQueue.size(); i++) {
        // 获取工作队列中的交易哈希
        uint256 hashPrev = vWorkQueue[i];

        // 查找以该哈希为前驱的所有孤儿交易
        // mapOrphanTransactionsByPrev是按前驱哈希索引的孤儿交易映射
        for (multimap<uint256, CDataStream *>::iterator mi =
                 mapOrphanTransactionsByPrev.lower_bound(hashPrev);
             mi != mapOrphanTransactionsByPrev.upper_bound(hashPrev); ++mi) {
          // 获取孤儿交易的消息流
          const CDataStream &vMsg = *((*mi).second);
          CTransaction tx;
          CDataStream(vMsg) >> tx; // 反序列化交易

          // 创建孤儿交易的库存项
          CInv inv(MSG_TX, tx.GetHash());

          // 尝试接受孤儿交易
          if (tx.AcceptTransaction(true)) {
            // 调试输出：打印接受的孤儿交易
            printf("   accepted orphan tx %s\n",
                   inv.hash.ToString().substr(0, 6).c_str());

            // 如果交易属于本节点，添加到钱包
            AddToWalletIfMine(tx, NULL);

            // 广播孤儿交易
            RelayMessage(inv, vMsg);

            // 从已请求列表中移除
            mapAlreadyAskedFor.erase(inv);

            // 将孤儿交易哈希加入工作队列，继续处理依赖它的交易
            vWorkQueue.push_back(inv.hash);
          }
        }
      }

      // 清理已处理的孤儿交易
      foreach (uint256 hash, vWorkQueue)
        EraseOrphanTx(hash);
    }
    // 如果交易缺少输入，将其作为孤儿交易存储
    else if (fMissingInputs) {
      printf("storing orphan tx %s\n",
             inv.hash.ToString().substr(0, 6).c_str());
      AddOrphanTx(vMsg); // 存储孤儿交易，等待其输入交易到达
    }
  }

  // ============================================================================
  // 消息类型处理：review - 评论消息
  // 用于接收和广播用户评论
  // 这是去中心化市场功能的一部分
  // ============================================================================
  else if (strCommand == "review") {
    // 保存原始消息流，用于转发
    CDataStream vMsg(vRecv);

    // 从消息流中读取评论数据
    CReview review;
    vRecv >> review;

    // 创建评论库存项
    CInv inv(MSG_REVIEW, review.GetHash());
    pfrom->AddInventoryKnown(inv); // 标记为已知，避免重复处理

    // 尝试接受评论
    // AcceptReview会验证评论的有效性，包括签名、内容等
    if (review.AcceptReview()) {
      // 转发原始消息，保持原始格式
      // 这样可以处理版本兼容性问题，如果消息版本比我们支持的更高
      // 也能正确转发给其他节点
      RelayMessage(inv, vMsg);

      // 从已请求列表中移除，避免重复请求
      mapAlreadyAskedFor.erase(inv);
    }
  }

  // ============================================================================
  // 消息类型处理：block - 区块消息
  // 用于接收和广播新的区块
  // 这是区块链同步的核心机制
  // ============================================================================
  else if (strCommand == "block") {
    // 使用智能指针创建区块对象，自动管理内存
    auto_ptr<CBlock> pblock(new CBlock);

    // 从消息流中读取区块数据
    vRecv >> *pblock;

    // 调试输出：打印区块信息
    printf("received block:\n");
    pblock->print();

    // 创建区块库存项
    CInv inv(MSG_BLOCK, pblock->GetHash());
    pfrom->AddInventoryKnown(inv); // 标记为已知，避免重复处理

    // 处理区块
    // ProcessBlock会验证区块的有效性，并将其加入区块链
    // pblock.release()释放智能指针的所有权，由ProcessBlock负责删除
    if (ProcessBlock(pfrom, pblock.release()))
      // 如果区块处理成功，从已请求列表中移除
      mapAlreadyAskedFor.erase(inv);
  }

  // ============================================================================
  // 消息类型处理：getaddr - 地址请求消息
  // 用于请求网络中的节点地址
  // ============================================================================
  else if (strCommand == "getaddr") {
    // 清空发送队列，准备发送新地址
    pfrom->vAddrToSend.clear();

    // 计算时间范围：只发送最近一小时内活跃的地址
    // 优化建议：如果找到的地址不够，可以扩展时间范围
    int64 nSince = GetAdjustedTime() - 60 * 60; // 距现在1小时

    // 遍历地址数据库，收集符合条件的地址
    CRITICAL_BLOCK(cs_mapAddresses) { // 临界区保护，确保线程安全
      foreach (const PAIRTYPE(vector<unsigned char>, CAddress) & item,
               mapAddresses) {
        // 检查是否正在关闭程序
        if (fShutdown)
          return true;

        // 获取地址对象
        const CAddress &addr = item.second;

        // 只发送最近活跃的地址（时间戳大于nSince）
        if (addr.nTime > nSince)
          pfrom->vAddrToSend.push_back(addr); // 加入发送队列
      }
    }
  }

  // ============================================================================
  // 消息类型处理：checkorder - 订单检查消息
  // 用于检查订单的有效性
  // 这是去中心化市场功能的一部分，用于验证订单
  // ============================================================================
  else if (strCommand == "checkorder") {
    // 从消息流中读取订单信息
    uint256 hashReply; // 回复哈希，用于匹配请求和响应
    CWalletTx order;   // 订单交易
    vRecv >> hashReply >> order;

    // 优化建议：在这里可以检查订单的有效性
    // 例如检查金额、接收地址等

    // 密钥重用机制：为同一IP地址重复使用相同的公钥
    // 这样可以简化订单处理流程，避免为每个订单生成新密钥
    if (!mapReuseKey.count(pfrom->addr.ip))
      // 如果该IP还没有分配密钥，生成一个新的密钥对
      mapReuseKey[pfrom->addr.ip] = GenerateNewKey();

    // 构造输出脚本，用于接收订单支付
    CScript scriptPubKey;
    // 将公钥和OP_CHECKSIG操作码加入脚本
    // 这样只有拥有对应私钥的人才能花费这笔资金
    scriptPubKey << mapReuseKey[pfrom->addr.ip] << OP_CHECKSIG;

    // 发送回复消息，包含批准和公钥
    // (int)0表示批准，(int)1表示拒绝
    pfrom->PushMessage("reply", hashReply, (int)0, scriptPubKey);
  }

  // ============================================================================
  // 消息类型处理：submitorder - 订单提交消息
  // 用于提交已签名的订单交易
  // 这是去中心化市场功能的一部分，用于完成订单
  // ============================================================================
  else if (strCommand == "submitorder") {
    // 从消息流中读取订单信息
    uint256 hashReply; // 回复哈希，用于匹配请求和响应
    CWalletTx wtxNew;  // 新的订单交易
    vRecv >> hashReply >> wtxNew;

    // 广播订单交易
    // AcceptWalletTransaction会验证交易的有效性，并将其加入钱包
    if (!wtxNew.AcceptWalletTransaction()) {
      // 如果交易无效，发送拒绝回复
      pfrom->PushMessage("reply", hashReply, (int)1);
      return error(
          "submitorder AcceptWalletTransaction() failed, returning error 1");
    }

    // 标记交易时间为接收时间
    wtxNew.fTimeReceivedIsTxTime = true;

    // 将交易添加到钱包
    AddToWallet(wtxNew);

    // 广播交易到网络
    wtxNew.RelayWalletTransaction();

    // 清除密钥重用映射，该IP已完成订单
    mapReuseKey.erase(pfrom->addr.ip);

    // 发送确认回复
    // (int)0表示订单已成功处理
    pfrom->PushMessage("reply", hashReply, (int)0);
  }

  // ============================================================================
  // 消息类型处理：reply - 回复消息
  // 用于处理异步请求的响应
  // 这是请求-响应机制的核心，用于处理checkorder等请求的响应
  // ============================================================================
  else if (strCommand == "reply") {
    // 从消息流中读取回复哈希
    uint256 hashReply;
    vRecv >> hashReply;

    // 查找对应的请求跟踪器
    CRequestTracker tracker;
    CRITICAL_BLOCK(pfrom->cs_mapRequests) { // 临界区保护，确保线程安全
      // 在请求映射中查找对应的哈希
      map<uint256, CRequestTracker>::iterator mi =
          pfrom->mapRequests.find(hashReply);
      if (mi != pfrom->mapRequests.end()) {
        // 找到请求，提取跟踪器
        tracker = (*mi).second;
        // 从映射中移除已处理的请求
        pfrom->mapRequests.erase(mi);
      }
    }

    // 如果找到有效的跟踪器，调用其回调函数
    // 回调函数会处理响应数据
    if (!tracker.IsNull())
      tracker.fn(tracker.param1, vRecv);
  }

  // ============================================================================
  // 未知消息处理：忽略未知命令以支持协议扩展
  // 这样设计允许未来添加新的消息类型，而不会破坏旧版本节点的兼容性
  // ============================================================================
  else {
    // 忽略未知命令，打印调试信息
    printf("ProcessMessage(%s) : Ignored unknown message\n",
           strCommand.c_str());
  }

  // ============================================================================
  // 检查消息流是否还有未处理的数据
  // 如果有，说明消息格式可能有问题，打印警告信息
  // ============================================================================
  if (!vRecv.empty())
    printf("ProcessMessage(%s) : %d extra bytes\n", strCommand.c_str(),
           vRecv.size());

  // 返回true表示消息处理成功
  return true;
}

bool SendMessages(CNode *pto) {
  CheckForShutdown(2);
  CRITICAL_BLOCK(cs_main) {
    // Don't send anything until we get their version message
    if (pto->nVersion == 0)
      return true;

    //
    // Message: addr
    //
    vector<CAddress> vAddrToSend;
    vAddrToSend.reserve(pto->vAddrToSend.size());
    foreach (const CAddress &addr, pto->vAddrToSend)
      if (!pto->setAddrKnown.count(addr))
        vAddrToSend.push_back(addr);
    pto->vAddrToSend.clear();
    if (!vAddrToSend.empty())
      pto->PushMessage("addr", vAddrToSend);

    //
    // Message: inventory
    //
    vector<CInv> vInventoryToSend;
    CRITICAL_BLOCK(pto->cs_inventory) {
      vInventoryToSend.reserve(pto->vInventoryToSend.size());
      foreach (const CInv &inv, pto->vInventoryToSend) {
        // returns true if wasn't already contained in the set
        if (pto->setInventoryKnown.insert(inv).second)
          vInventoryToSend.push_back(inv);
      }
      pto->vInventoryToSend.clear();
      pto->setInventoryKnown2.clear();
    }
    if (!vInventoryToSend.empty())
      pto->PushMessage("inv", vInventoryToSend);

    //
    // Message: getdata
    //
    vector<CInv> vAskFor;
    int64 nNow = GetTime() * 1000000;
    CTxDB txdb("r");
    while (!pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow) {
      const CInv &inv = (*pto->mapAskFor.begin()).second;
      printf("sending getdata: %s\n", inv.ToString().c_str());
      if (!AlreadyHave(txdb, inv))
        vAskFor.push_back(inv);
      pto->mapAskFor.erase(pto->mapAskFor.begin());
    }
    if (!vAskFor.empty())
      pto->PushMessage("getdata", vAskFor);
  }
  return true;
}

//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

int FormatHashBlocks(void *pbuffer, unsigned int len) {
  unsigned char *pdata = (unsigned char *)pbuffer;
  unsigned int blocks = 1 + ((len + 8) / 64);
  unsigned char *pend = pdata + 64 * blocks;
  memset(pdata + len, 0, 64 * blocks - len);
  pdata[len] = 0x80;
  unsigned int bits = len * 8;
  pend[-1] = (bits >> 0) & 0xff;
  pend[-2] = (bits >> 8) & 0xff;
  pend[-3] = (bits >> 16) & 0xff;
  pend[-4] = (bits >> 24) & 0xff;
  return blocks;
}

using CryptoPP::ByteReverse;
static int detectlittleendian = 1;

void BlockSHA256(const void *pin, unsigned int nBlocks, void *pout) {
  unsigned int *pinput = (unsigned int *)pin;
  unsigned int *pstate = (unsigned int *)pout;

  CryptoPP::SHA256::InitState(pstate);

  if (*(char *)&detectlittleendian != 0) {
    for (int n = 0; n < nBlocks; n++) {
      unsigned int pbuf[16];
      for (int i = 0; i < 16; i++)
        pbuf[i] = ByteReverse(pinput[n * 16 + i]);
      CryptoPP::SHA256::Transform(pstate, pbuf);
    }
    for (int i = 0; i < 8; i++)
      pstate[i] = ByteReverse(pstate[i]);
  } else {
    for (int n = 0; n < nBlocks; n++)
      CryptoPP::SHA256::Transform(pstate, pinput + n * 16);
  }
}

bool BitcoinMiner() {
  printf("BitcoinMiner started\n");
  SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);

  CKey key;
  key.MakeNewKey();
  CBigNum bnExtraNonce = 0;
  while (fGenerateBitcoins) {
    Sleep(50);
    CheckForShutdown(3);
    while (vNodes.empty()) {
      Sleep(1000);
      CheckForShutdown(3);
    }

    unsigned int nTransactionsUpdatedLast = nTransactionsUpdated;
    CBlockIndex *pindexPrev = pindexBest;
    unsigned int nBits = GetNextWorkRequired(pindexPrev);

    //
    // Create coinbase tx
    //
    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vin[0].scriptSig << nBits << ++bnExtraNonce;
    txNew.vout.resize(1);
    txNew.vout[0].scriptPubKey << key.GetPubKey() << OP_CHECKSIG;

    //
    // Create new block
    //
    auto_ptr<CBlock> pblock(new CBlock());
    if (!pblock.get())
      return false;

    // Add our coinbase tx as first transaction
    pblock->vtx.push_back(txNew);

    // Collect the latest transactions into the block
    int64 nFees = 0;
    CRITICAL_BLOCK(cs_main)
    CRITICAL_BLOCK(cs_mapTransactions) {
      CTxDB txdb("r");
      map<uint256, CTxIndex> mapTestPool;
      vector<char> vfAlreadyAdded(mapTransactions.size());
      bool fFoundSomething = true;
      unsigned int nBlockSize = 0;
      while (fFoundSomething && nBlockSize < MAX_SIZE / 2) {
        fFoundSomething = false;
        unsigned int n = 0;
        for (map<uint256, CTransaction>::iterator mi = mapTransactions.begin();
             mi != mapTransactions.end(); ++mi, ++n) {
          if (vfAlreadyAdded[n])
            continue;
          CTransaction &tx = (*mi).second;
          if (tx.IsCoinBase() || !tx.IsFinal())
            continue;

          // Transaction fee requirements, mainly only needed for flood control
          // Under 10K (about 80 inputs) is free for first 100 transactions
          // Base rate is 0.01 per KB
          int64 nMinFee = tx.GetMinFee(pblock->vtx.size() < 100);

          map<uint256, CTxIndex> mapTestPoolTmp(mapTestPool);
          if (!tx.ConnectInputs(txdb, mapTestPoolTmp, CDiskTxPos(1, 1, 1), 0,
                                nFees, false, true, nMinFee))
            continue;
          swap(mapTestPool, mapTestPoolTmp);

          pblock->vtx.push_back(tx);
          nBlockSize += ::GetSerializeSize(tx, SER_NETWORK);
          vfAlreadyAdded[n] = true;
          fFoundSomething = true;
        }
      }
    }
    pblock->nBits = nBits;
    pblock->vtx[0].vout[0].nValue = pblock->GetBlockValue(nFees);
    printf("\n\nRunning BitcoinMiner with %d transactions in block\n",
           pblock->vtx.size());

    //
    // Prebuild hash buffer
    //
    struct unnamed1 {
      struct unnamed2 {
        int nVersion;
        uint256 hashPrevBlock;
        uint256 hashMerkleRoot;
        unsigned int nTime;
        unsigned int nBits;
        unsigned int nNonce;
      } block;
      unsigned char pchPadding0[64];
      uint256 hash1;
      unsigned char pchPadding1[64];
    } tmp;

    tmp.block.nVersion = pblock->nVersion;
    tmp.block.hashPrevBlock = pblock->hashPrevBlock =
        (pindexPrev ? pindexPrev->GetBlockHash() : 0);
    tmp.block.hashMerkleRoot = pblock->hashMerkleRoot =
        pblock->BuildMerkleTree();
    tmp.block.nTime = pblock->nTime =
        max((pindexPrev ? pindexPrev->GetMedianTimePast() + 1 : 0),
            GetAdjustedTime());
    tmp.block.nBits = pblock->nBits = nBits;
    tmp.block.nNonce = pblock->nNonce = 1;

    unsigned int nBlocks0 = FormatHashBlocks(&tmp.block, sizeof(tmp.block));
    unsigned int nBlocks1 = FormatHashBlocks(&tmp.hash1, sizeof(tmp.hash1));

    //
    // Search
    //
    unsigned int nStart = GetTime();
    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
    uint256 hash;
    loop {
      BlockSHA256(&tmp.block, nBlocks0, &tmp.hash1);
      BlockSHA256(&tmp.hash1, nBlocks1, &hash);

      if (hash <= hashTarget) {
        pblock->nNonce = tmp.block.nNonce;
        assert(hash == pblock->GetHash());

        //// debug print
        printf("BitcoinMiner:\n");
        printf("proof-of-work found  \n  hash: %s  \ntarget: %s\n",
               hash.GetHex().c_str(), hashTarget.GetHex().c_str());
        pblock->print();

        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
        CRITICAL_BLOCK(cs_main) {
          // Save key
          if (!AddKey(key))
            return false;
          key.MakeNewKey();

          // Process this block the same as if we had received it from another
          // node
          if (!ProcessBlock(NULL, pblock.release()))
            printf("ERROR in BitcoinMiner, ProcessBlock, block not accepted\n");
        }
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);

        Sleep(500);
        break;
      }

      // Update nTime every few seconds
      if ((++tmp.block.nNonce & 0x3ffff) == 0) {
        CheckForShutdown(3);
        if (tmp.block.nNonce == 0)
          break;
        if (pindexPrev != pindexBest)
          break;
        if (nTransactionsUpdated != nTransactionsUpdatedLast &&
            GetTime() - nStart > 60)
          break;
        if (!fGenerateBitcoins)
          break;
        tmp.block.nTime = pblock->nTime =
            max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());
      }
    }
  }

  return true;
}

//////////////////////////////////////////////////////////////////////////////
//
// Actions
//

int64 GetBalance() {
  int64 nStart, nEnd;
  QueryPerformanceCounter((LARGE_INTEGER *)&nStart);

  int64 nTotal = 0;
  CRITICAL_BLOCK(cs_mapWallet) {
    for (map<uint256, CWalletTx>::iterator it = mapWallet.begin();
         it != mapWallet.end(); ++it) {
      CWalletTx *pcoin = &(*it).second;
      if (!pcoin->IsFinal() || pcoin->fSpent)
        continue;
      nTotal += pcoin->GetCredit();
    }
  }

  QueryPerformanceCounter((LARGE_INTEGER *)&nEnd);
  /// printf(" GetBalance() time = %16I64d\n", nEnd - nStart);
  return nTotal;
}

bool SelectCoins(int64 nTargetValue, set<CWalletTx *> &setCoinsRet) {
  setCoinsRet.clear();

  // List of values less than target
  int64 nLowestLarger = _I64_MAX;
  CWalletTx *pcoinLowestLarger = NULL;
  vector<pair<int64, CWalletTx *>> vValue;
  int64 nTotalLower = 0;

  CRITICAL_BLOCK(cs_mapWallet) {
    for (map<uint256, CWalletTx>::iterator it = mapWallet.begin();
         it != mapWallet.end(); ++it) {
      CWalletTx *pcoin = &(*it).second;
      if (!pcoin->IsFinal() || pcoin->fSpent)
        continue;
      int64 n = pcoin->GetCredit();
      if (n <= 0)
        continue;
      if (n < nTargetValue) {
        vValue.push_back(make_pair(n, pcoin));
        nTotalLower += n;
      } else if (n == nTargetValue) {
        setCoinsRet.insert(pcoin);
        return true;
      } else if (n < nLowestLarger) {
        nLowestLarger = n;
        pcoinLowestLarger = pcoin;
      }
    }
  }

  if (nTotalLower < nTargetValue) {
    if (pcoinLowestLarger == NULL)
      return false;
    setCoinsRet.insert(pcoinLowestLarger);
    return true;
  }

  // Solve subset sum by stochastic approximation
  sort(vValue.rbegin(), vValue.rend());
  vector<char> vfIncluded;
  vector<char> vfBest(vValue.size(), true);
  int64 nBest = nTotalLower;

  for (int nRep = 0; nRep < 1000 && nBest != nTargetValue; nRep++) {
    vfIncluded.assign(vValue.size(), false);
    int64 nTotal = 0;
    bool fReachedTarget = false;
    for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++) {
      for (int i = 0; i < vValue.size(); i++) {
        if (nPass == 0 ? rand() % 2 : !vfIncluded[i]) {
          nTotal += vValue[i].first;
          vfIncluded[i] = true;
          if (nTotal >= nTargetValue) {
            fReachedTarget = true;
            if (nTotal < nBest) {
              nBest = nTotal;
              vfBest = vfIncluded;
            }
            nTotal -= vValue[i].first;
            vfIncluded[i] = false;
          }
        }
      }
    }
  }

  // If the next larger is still closer, return it
  if (pcoinLowestLarger && nLowestLarger - nTargetValue <= nBest - nTargetValue)
    setCoinsRet.insert(pcoinLowestLarger);
  else {
    for (int i = 0; i < vValue.size(); i++)
      if (vfBest[i])
        setCoinsRet.insert(vValue[i].second);

    //// debug print
    printf("SelectCoins() best subset: ");
    for (int i = 0; i < vValue.size(); i++)
      if (vfBest[i])
        printf("%s ", FormatMoney(vValue[i].first).c_str());
    printf("total %s\n", FormatMoney(nBest).c_str());
  }

  return true;
}

bool CreateTransaction(CScript scriptPubKey, int64 nValue, CWalletTx &wtxNew,
                       int64 &nFeeRequiredRet) {
  nFeeRequiredRet = 0;
  CRITICAL_BLOCK(cs_main) {
    // txdb must be opened before the mapWallet lock
    CTxDB txdb("r");
    CRITICAL_BLOCK(cs_mapWallet) {
      int64 nFee = nTransactionFee;
      loop {
        wtxNew.vin.clear();
        wtxNew.vout.clear();
        if (nValue < 0)
          return false;
        int64 nValueOut = nValue;
        nValue += nFee;

        // Choose coins to use
        set<CWalletTx *> setCoins;
        if (!SelectCoins(nValue, setCoins))
          return false;
        int64 nValueIn = 0;
        foreach (CWalletTx *pcoin, setCoins)
          nValueIn += pcoin->GetCredit();

        // Fill vout[0] to the payee
        wtxNew.vout.push_back(CTxOut(nValueOut, scriptPubKey));

        // Fill vout[1] back to self with any change
        if (nValueIn > nValue) {
          // Use the same key as one of the coins
          vector<unsigned char> vchPubKey;
          CTransaction &txFirst = *(*setCoins.begin());
          foreach (const CTxOut &txout, txFirst.vout)
            if (txout.IsMine())
              if (ExtractPubKey(txout.scriptPubKey, true, vchPubKey))
                break;
          if (vchPubKey.empty())
            return false;

          // Fill vout[1] to ourself
          CScript scriptPubKey;
          scriptPubKey << vchPubKey << OP_CHECKSIG;
          wtxNew.vout.push_back(CTxOut(nValueIn - nValue, scriptPubKey));
        }

        // Fill vin
        foreach (CWalletTx *pcoin, setCoins)
          for (int nOut = 0; nOut < pcoin->vout.size(); nOut++)
            if (pcoin->vout[nOut].IsMine())
              wtxNew.vin.push_back(CTxIn(pcoin->GetHash(), nOut));

        // Sign
        int nIn = 0;
        foreach (CWalletTx *pcoin, setCoins)
          for (int nOut = 0; nOut < pcoin->vout.size(); nOut++)
            if (pcoin->vout[nOut].IsMine())
              SignSignature(*pcoin, wtxNew, nIn++);

        // Check that enough fee is included
        if (nFee < wtxNew.GetMinFee(true)) {
          nFee = nFeeRequiredRet = wtxNew.GetMinFee(true);
          continue;
        }

        // Fill vtxPrev by copying from previous transactions vtxPrev
        wtxNew.AddSupportingTransactions(txdb);
        wtxNew.fTimeReceivedIsTxTime = true;

        break;
      }
    }
  }
  return true;
}

// Call after CreateTransaction unless you want to abort
bool CommitTransactionSpent(const CWalletTx &wtxNew) {
  CRITICAL_BLOCK(cs_main)
  CRITICAL_BLOCK(cs_mapWallet) {
    //// todo: make this transactional, never want to add a transaction
    ////  without marking spent transactions

    // Add tx to wallet, because if it has change it's also ours,
    // otherwise just for transaction history.
    AddToWallet(wtxNew);

    // Mark old coins as spent
    set<CWalletTx *> setCoins;
    foreach (const CTxIn &txin, wtxNew.vin)
      setCoins.insert(&mapWallet[txin.prevout.hash]);
    foreach (CWalletTx *pcoin, setCoins) {
      pcoin->fSpent = true;
      pcoin->WriteToDisk();
      vWalletUpdated.push_back(make_pair(pcoin->GetHash(), false));
    }
  }
  MainFrameRepaint();
  return true;
}

bool SendMoney(CScript scriptPubKey, int64 nValue, CWalletTx &wtxNew) {
  CRITICAL_BLOCK(cs_main) {
    int64 nFeeRequired;
    if (!CreateTransaction(scriptPubKey, nValue, wtxNew, nFeeRequired)) {
      string strError;
      if (nValue + nFeeRequired > GetBalance())
        strError = strprintf("Error: This is an oversized transaction that "
                             "requires a transaction fee of %s ",
                             FormatMoney(nFeeRequired).c_str());
      else
        strError = "Error: Transaction creation failed ";
      wxMessageBox(strError, "Sending...");
      return error("SendMoney() : %s\n", strError.c_str());
    }
    if (!CommitTransactionSpent(wtxNew)) {
      wxMessageBox("Error finalizing transaction", "Sending...");
      return error("SendMoney() : Error finalizing transaction");
    }

    printf("SendMoney: %s\n", wtxNew.GetHash().ToString().substr(0, 6).c_str());

    // Broadcast
    if (!wtxNew.AcceptTransaction()) {
      // This must not fail. The transaction has already been signed and
      // recorded.
      throw runtime_error("SendMoney() : wtxNew.AcceptTransaction() failed\n");
      wxMessageBox("Error: Transaction not valid", "Sending...");
      return error("SendMoney() : Error: Transaction not valid");
    }
    wtxNew.RelayWalletTransaction();
  }
  MainFrameRepaint();
  return true;
}
