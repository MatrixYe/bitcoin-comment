// Copyright (c) 2009-2010 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "cryptopp/sha.h"
#include "headers.h"

//
// Global state
//

CCriticalSection cs_main;

map<uint256, CTransaction> mapTransactions;
CCriticalSection cs_mapTransactions;
unsigned int nTransactionsUpdated = 0;
map<COutPoint, CInPoint> mapNextTx;

map<uint256, CBlockIndex *> mapBlockIndex;
uint256 hashGenesisBlock(
    "0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
CBigNum bnProofOfWorkLimit(~uint256(0) >> 32);
CBlockIndex *pindexGenesisBlock = NULL;
int nBestHeight = -1;
CBigNum bnBestChainWork = 0;
CBigNum bnBestInvalidWork = 0;
uint256 hashBestChain = 0;
CBlockIndex *pindexBest = NULL;
int64 nTimeBestReceived = 0;

map<uint256, CBlock *> mapOrphanBlocks;
multimap<uint256, CBlock *> mapOrphanBlocksByPrev;

map<uint256, CDataStream *> mapOrphanTransactions;
multimap<uint256, CDataStream *> mapOrphanTransactionsByPrev;

map<uint256, CWalletTx> mapWallet;
vector<uint256> vWalletUpdated;
CCriticalSection cs_mapWallet;

map<vector<unsigned char>, CPrivKey> mapKeys;
map<uint160, vector<unsigned char>> mapPubKeys;
CCriticalSection cs_mapKeys;
CKey keyUser;

map<uint256, int> mapRequestCount;
CCriticalSection cs_mapRequestCount;

map<string, string> mapAddressBook;
CCriticalSection cs_mapAddressBook;

vector<unsigned char> vchDefaultKey;

double dHashesPerSec;
int64 nHPSTimerStart;

// Settings
int fGenerateBitcoins = false;
int64 nTransactionFee = 0;
CAddress addrIncoming;
int fLimitProcessors = false;
int nLimitProcessors = 1;
int fMinimizeToTray = true;
int fMinimizeOnClose = true;

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
  RandAddSeedPerfmon();
  CKey key;
  key.MakeNewKey();
  if (!AddKey(key))
    throw runtime_error("GenerateNewKey() : AddKey failed");
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

    bool fUpdated = false;
    if (!fInsertedNew) {
      // Merge
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
    }

    //// debug print
    printf("AddToWallet %s  %s%s\n",
           wtxIn.GetHash().ToString().substr(0, 10).c_str(),
           (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""));

    // Write to disk
    if (fInsertedNew || fUpdated)
      if (!wtx.WriteToDisk())
        return false;

    // If default receiving address gets used, replace it with a new one
    CScript scriptDefaultKey;
    scriptDefaultKey.SetBitcoinAddress(vchDefaultKey);
    foreach (const CTxOut &txout, wtx.vout) {
      if (txout.scriptPubKey == scriptDefaultKey) {
        CWalletDB walletdb;
        vchDefaultKey = GetKeyFromKeyPool();
        walletdb.WriteDefaultKey(vchDefaultKey);
        walletdb.WriteName(PubKeyToAddress(vchDefaultKey), "");
      }
    }

    // Notify UI
    vWalletUpdated.push_back(hash);
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

void WalletUpdateSpent(const COutPoint &prevout) {
  // Anytime a signature is successfully verified, it's proof the outpoint is
  // spent. Update the wallet spent flag if it doesn't know due to wallet.dat
  // being restored from backup or the user making copies of wallet.dat.
  CRITICAL_BLOCK(cs_mapWallet) {
    map<uint256, CWalletTx>::iterator mi = mapWallet.find(prevout.hash);
    if (mi != mapWallet.end()) {
      CWalletTx &wtx = (*mi).second;
      if (!wtx.fSpent && wtx.vout[prevout.n].IsMine()) {
        printf("WalletUpdateSpent found spent coin %sbc %s\n",
               FormatMoney(wtx.GetCredit()).c_str(),
               wtx.GetHash().ToString().c_str());
        wtx.fSpent = true;
        wtx.WriteToDisk();
        vWalletUpdated.push_back(prevout.hash);
      }
    }
  }
}

//////////////////////////////////////////////////////////////////////////////
//
// 孤儿交易处理机制
// 孤儿交易是指其依赖的前序交易尚未收到的交易
// 这种机制确保在网络延迟情况下，交易依赖关系能够得到正确处理
//

// 添加孤儿交易到内存池
// 当接收到一个交易但其依赖的前序交易尚未收到时，将此交易标记为孤儿交易
// 设计目的：解决交易依赖关系中的网络延迟问题，保证交易传播的完整性
void AddOrphanTx(const CDataStream &vMsg) {
  CTransaction tx;
  CDataStream(vMsg) >> tx;
  uint256 hash = tx.GetHash();
  if (mapOrphanTransactions.count(hash))
    return; // 如果已经存在相同的孤儿交易，则忽略

  // 创建交易数据的副本并存储到孤儿交易映射中
  CDataStream *pvMsg = mapOrphanTransactions[hash] = new CDataStream(vMsg);

  // 建立反向依赖关系映射
  // 记录此孤儿交易依赖的每一个前序交易哈希
  foreach (const CTxIn &txin, tx.vin)
    mapOrphanTransactionsByPrev.insert(make_pair(txin.prevout.hash, pvMsg));
}

// 从孤儿交易池中删除指定的孤儿交易
// 当孤儿交易被成功处理或确认不再需要时调用此函数
// 设计目的：清理孤儿交易池，防止内存泄漏和无效数据积累
void EraseOrphanTx(uint256 hash) {
  if (!mapOrphanTransactions.count(hash))
    return;

  const CDataStream *pvMsg = mapOrphanTransactions[hash];
  CTransaction tx;
  CDataStream(*pvMsg) >> tx;

  // 从反向依赖关系映射中删除此孤儿交易的所有引用
  foreach (const CTxIn &txin, tx.vin) {
    for (multimap<uint256, CDataStream *>::iterator mi =
             mapOrphanTransactionsByPrev.lower_bound(txin.prevout.hash);
         mi != mapOrphanTransactionsByPrev.upper_bound(txin.prevout.hash);) {
      if ((*mi).second == pvMsg)
        mapOrphanTransactionsByPrev.erase(mi++); // 安全删除迭代器指向的元素
      else
        mi++;
    }
  }

  // 释放内存并从主映射中删除
  delete pvMsg;
  mapOrphanTransactions.erase(hash);
}

//////////////////////////////////////////////////////////////////////////////
//
// CTransaction
//

bool CTransaction::ReadFromDisk(CTxDB &txdb, COutPoint prevout,
                                CTxIndex &txindexRet) {
  SetNull();
  if (!txdb.ReadTxIndex(prevout.hash, txindexRet))
    return false;
  if (!ReadFromDisk(txindexRet.pos))
    return false;
  if (prevout.n >= vout.size()) {
    SetNull();
    return false;
  }
  return true;
}

bool CTransaction::ReadFromDisk(CTxDB &txdb, COutPoint prevout) {
  CTxIndex txindex;
  return ReadFromDisk(txdb, prevout, txindex);
}

bool CTransaction::ReadFromDisk(COutPoint prevout) {
  CTxDB txdb("r");
  CTxIndex txindex;
  return ReadFromDisk(txdb, prevout, txindex);
}

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

int CWalletTx::GetRequestCount() const {
  // Returns -1 if it wasn't being tracked
  int nRequests = -1;
  CRITICAL_BLOCK(cs_mapRequestCount) {
    if (IsCoinBase()) {
      // Generated block
      if (hashBlock != 0) {
        map<uint256, int>::iterator mi = mapRequestCount.find(hashBlock);
        if (mi != mapRequestCount.end())
          nRequests = (*mi).second;
      }
    } else {
      // Did anyone request this transaction?
      map<uint256, int>::iterator mi = mapRequestCount.find(GetHash());
      if (mi != mapRequestCount.end()) {
        nRequests = (*mi).second;

        // How about the block it's in?
        if (nRequests == 0 && hashBlock != 0) {
          map<uint256, int>::iterator mi = mapRequestCount.find(hashBlock);
          if (mi != mapRequestCount.end())
            nRequests = (*mi).second;
          else
            nRequests =
                1; // If it's in someone else's block it must have got out
        }
      }
    }
  }
  return nRequests;
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
      if (!blockTmp.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos))
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

bool CTransaction::CheckTransaction() const {
  // Basic checks that don't depend on any context
  if (vin.empty() || vout.empty())
    return error("CTransaction::CheckTransaction() : vin or vout empty");

  // Size limits
  if (::GetSerializeSize(*this, SER_NETWORK) > MAX_BLOCK_SIZE)
    return error("CTransaction::CheckTransaction() : size limits failed");

  // Check for negative or overflow output values
  int64 nValueOut = 0;
  foreach (const CTxOut &txout, vout) {
    if (txout.nValue < 0)
      return error("CTransaction::CheckTransaction() : txout.nValue negative");
    if (txout.nValue > MAX_MONEY)
      return error("CTransaction::CheckTransaction() : txout.nValue too high");
    nValueOut += txout.nValue;
    if (!MoneyRange(nValueOut))
      return error(
          "CTransaction::CheckTransaction() : txout total out of range");
  }

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

bool CTransaction::AcceptToMemoryPool(CTxDB &txdb, bool fCheckInputs,
                                      bool *pfMissingInputs) {
  if (pfMissingInputs)
    *pfMissingInputs = false;

  if (!CheckTransaction())
    return error("AcceptToMemoryPool() : CheckTransaction failed");

  // Coinbase is only valid in a block, not as a loose transaction
  if (IsCoinBase())
    return error("AcceptToMemoryPool() : coinbase as individual tx");

  // To help v0.1.5 clients who would see it as a negative number
  if ((int64)nLockTime > INT_MAX)
    return error(
        "AcceptToMemoryPool() : not accepting nLockTime beyond 2038 yet");

  // Safety limits
  unsigned int nSize = ::GetSerializeSize(*this, SER_NETWORK);
  if (GetSigOpCount() > 2 || nSize < 100)
    return error("AcceptToMemoryPool() : nonstandard transaction");

  // Rather not work on nonstandard transactions
  if (!IsStandard())
    return error("AcceptToMemoryPool() : nonstandard transaction type");

  // Do we already have it?
  uint256 hash = GetHash();
  CRITICAL_BLOCK(cs_mapTransactions)
  if (mapTransactions.count(hash))
    return false;
  if (fCheckInputs)
    if (txdb.ContainsTx(hash))
      return false;

  // Check for conflicts with in-memory transactions
  CTransaction *ptxOld = NULL;
  for (int i = 0; i < vin.size(); i++) {
    COutPoint outpoint = vin[i].prevout;
    if (mapNextTx.count(outpoint)) {
      // Disable replacement feature for now
      return false;

      // Allow replacing with a newer version of the same transaction
      if (i != 0)
        return false;
      ptxOld = mapNextTx[outpoint].ptx;
      if (ptxOld->IsFinal())
        return false;
      if (!IsNewerThan(*ptxOld))
        return false;
      for (int i = 0; i < vin.size(); i++) {
        COutPoint outpoint = vin[i].prevout;
        if (!mapNextTx.count(outpoint) || mapNextTx[outpoint].ptx != ptxOld)
          return false;
      }
      break;
    }
  }

  if (fCheckInputs) {
    // Check against previous transactions
    map<uint256, CTxIndex> mapUnused;
    int64 nFees = 0;
    if (!ConnectInputs(txdb, mapUnused, CDiskTxPos(1, 1, 1), pindexBest, nFees,
                       false, false)) {
      if (pfMissingInputs)
        *pfMissingInputs = true;
      return error("AcceptToMemoryPool() : ConnectInputs failed %s",
                   hash.ToString().substr(0, 10).c_str());
    }

    // Don't accept it if it can't get into a block
    if (nFees < GetMinFee(1000))
      return error("AcceptToMemoryPool() : not enough fees");

    // Limit free transactions per 10 minutes
    if (nFees < CENT && GetBoolArg("-limitfreerelay")) {
      static int64 nNextReset;
      static int64 nFreeCount;
      if (GetTime() > nNextReset) {
        nNextReset = GetTime() + 10 * 60;
        nFreeCount = 0;
      }
      if (nFreeCount > 150000 && !IsFromMe())
        return error(
            "AcceptToMemoryPool() : free transaction rejected by rate limiter");
      nFreeCount += nSize;
    }
  }

  // Store transaction in memory
  CRITICAL_BLOCK(cs_mapTransactions) {
    if (ptxOld) {
      printf("AcceptToMemoryPool() : replacing tx %s with new version\n",
             ptxOld->GetHash().ToString().c_str());
      ptxOld->RemoveFromMemoryPool();
    }
    AddToMemoryPoolUnchecked();
  }

  ///// are we sure this is ok when loading transactions or restoring block txes
  // If updated, erase old tx from wallet
  if (ptxOld)
    EraseFromWallet(ptxOld->GetHash());

  printf("AcceptToMemoryPool(): accepted %s\n",
         hash.ToString().substr(0, 10).c_str());
  return true;
}

bool CTransaction::AddToMemoryPoolUnchecked() {
  // Add to memory pool without checking anything.  Don't call this directly,
  // call AcceptToMemoryPool to properly check the transaction first.
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

int CMerkleTx::GetDepthInMainChain(int &nHeightRet) const {
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

  nHeightRet = pindex->nHeight;
  return pindexBest->nHeight - pindex->nHeight + 1;
}

int CMerkleTx::GetBlocksToMaturity() const {
  if (!IsCoinBase())
    return 0;
  return max(0, (COINBASE_MATURITY + 20) - GetDepthInMainChain());
}

bool CMerkleTx::AcceptToMemoryPool(CTxDB &txdb, bool fCheckInputs) {
  if (fClient) {
    if (!IsInMainChain() && !ClientConnectInputs())
      return false;
    return CTransaction::AcceptToMemoryPool(txdb, false);
  } else {
    return CTransaction::AcceptToMemoryPool(txdb, fCheckInputs);
  }
}

bool CWalletTx::AcceptWalletTransaction(CTxDB &txdb, bool fCheckInputs) {
  CRITICAL_BLOCK(cs_mapTransactions) {
    // Add previous supporting transactions first
    foreach (CMerkleTx &tx, vtxPrev) {
      if (!tx.IsCoinBase()) {
        uint256 hash = tx.GetHash();
        if (!mapTransactions.count(hash) && !txdb.ContainsTx(hash))
          tx.AcceptToMemoryPool(txdb, fCheckInputs);
      }
    }
    return AcceptToMemoryPool(txdb, fCheckInputs);
  }
  return false;
}

void ReacceptWalletTransactions() {
  CTxDB txdb("r");
  CRITICAL_BLOCK(cs_mapWallet) {
    foreach (PAIRTYPE(const uint256, CWalletTx) & item, mapWallet) {
      CWalletTx &wtx = item.second;
      if (wtx.fSpent && wtx.IsCoinBase())
        continue;

      CTxIndex txindex;
      if (txdb.ReadTxIndex(wtx.GetHash(), txindex)) {
        // Update fSpent if a tx got spent somewhere else by a copy of
        // wallet.dat
        if (!wtx.fSpent) {
          if (txindex.vSpent.size() != wtx.vout.size()) {
            printf("ERROR: ReacceptWalletTransactions() : "
                   "txindex.vSpent.size() %d != wtx.vout.size() %d\n",
                   txindex.vSpent.size(), wtx.vout.size());
            continue;
          }
          for (int i = 0; i < txindex.vSpent.size(); i++) {
            if (!txindex.vSpent[i].IsNull() && wtx.vout[i].IsMine()) {
              printf("ReacceptWalletTransactions found spent coin %sbc %s\n",
                     FormatMoney(wtx.GetCredit()).c_str(),
                     wtx.GetHash().ToString().c_str());
              wtx.fSpent = true;
              wtx.WriteToDisk();
              break;
            }
          }
        }
      } else {
        // Reaccept any txes of ours that aren't already in a block
        if (!wtx.IsCoinBase())
          wtx.AcceptWalletTransaction(txdb, false);
      }
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
      printf("Relaying wtx %s\n", hash.ToString().substr(0, 10).c_str());
      RelayMessage(CInv(MSG_TX, hash), (CTransaction) * this);
    }
  }
}

void ResendWalletTransactions() {
  // Do this infrequently and randomly to avoid giving away
  // that these are our transactions.
  static int64 nNextTime;
  if (GetTime() < nNextTime)
    return;
  bool fFirst = (nNextTime == 0);
  nNextTime = GetTime() + GetRand(30 * 60);
  if (fFirst)
    return;

  // Only do it if there's been a new block since last time
  static int64 nLastTime;
  if (nTimeBestReceived < nLastTime)
    return;
  nLastTime = GetTime();

  // Rebroadcast any of our txes that aren't in a block yet
  printf("ResendWalletTransactions()\n");
  CTxDB txdb("r");
  CRITICAL_BLOCK(cs_mapWallet) {
    // Sort them in chronological order
    multimap<unsigned int, CWalletTx *> mapSorted;
    foreach (PAIRTYPE(const uint256, CWalletTx) & item, mapWallet) {
      CWalletTx &wtx = item.second;
      // Don't rebroadcast until it's had plenty of time that
      // it should have gotten in already by now.
      if (nTimeBestReceived - (int64)wtx.nTimeReceived > 5 * 60)
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

bool CBlock::ReadFromDisk(const CBlockIndex *pindex, bool fReadTransactions) {
  if (!fReadTransactions) {
    *this = pindex->GetBlockHeader();
    return true;
  }
  if (!ReadFromDisk(pindex->nFile, pindex->nBlockPos, fReadTransactions))
    return false;
  if (GetHash() != pindex->GetBlockHash())
    return error("CBlock::ReadFromDisk() : GetHash() doesn't match index");
  return true;
}

// 获取孤儿链的根区块哈希
// 该函数沿着孤儿区块的前序链接一直回溯，直到找到没有前序区块的根区块
// 这是孤儿链中最早创建的区块，代表了整个孤儿链的起点
// 设计目的：在处理孤儿区块时，能够找到整个链的起始点，便于向网络请求完整的链
uint256 GetOrphanRoot(const CBlock *pblock) {
  // 沿着前序区块回溯到孤儿链的起点
  // mapOrphanBlocks中存储着所有孤儿区块，通过hashPrevBlock链接起来
  while (mapOrphanBlocks.count(pblock->hashPrevBlock))
    pblock = mapOrphanBlocks[pblock->hashPrevBlock];
  return pblock->GetHash();
}
// 计算区块奖励值
// 该函数根据区块高度和交易手续费计算当前区块的奖励值
// 设计目的：根据比特币的奖励机制，动态调整新区块的奖励值
int64 GetBlockValue(int nHeight, int64 nFees) {
  int64 nSubsidy = 50 * COIN;

  // Subsidy is cut in half every 4 years
  nSubsidy >>= (nHeight / 210000);

  return nSubsidy + nFees;
}

// 计算下一个区块的难度目标（nBits）
// 该函数根据当前区块链的状态，动态调整下一个区块的难度目标
// 设计目的：确保比特币网络的安全性和稳定性，防止恶意攻击
// 获取下一个工作难度要求（难度调整算法）
// 该函数实现比特币的核心难度调整机制，确保平均出块时间维持在10分钟左右
// 算法每2016个区块（约14天）执行一次，根据网络算力变化动态调整挖矿难度
unsigned int GetNextWorkRequired(const CBlockIndex *pindexLast) {
  // 难度调整相关常量定义
  
  // 目标时间跨度：14天（以秒为单位）
  // 这是比特币网络设计的目标周期，用于衡量网络算力变化
  const int64 nTargetTimespan = 14 * 24 * 60 * 60; // two weeks
  
  // 目标出块间隔：10分钟（以秒为单位）
  // 这是比特币网络设计的目标出块时间
  const int64 nTargetSpacing = 10 * 60;
  
  // 难度调整周期：2016个区块
  // 比特币每2016个区块（约14天）调整一次难度
  const int64 nInterval = nTargetTimespan / nTargetSpacing;

  // 特殊情况处理：创世区块
  // 如果没有前一个区块（创世区块），返回系统的最大难度限制
  // 创世区块是区块链的起始点，没有可参考的前序区块
  if (pindexLast == NULL)
    return bnProofOfWorkLimit.GetCompact();

  // 检查是否需要调整难度
  // 只有当新区块编号是调整周期的整数倍时才调整难度
  // 例如：第2016、4032、6048...个区块会触发难度调整
  if ((pindexLast->nHeight + 1) % nInterval != 0)
    return pindexLast->nBits; // 不需要调整，返回当前难度

  // 步骤1：计算过去一个难度周期内实际生成区块的时间
  // 通过遍历区块链，找到2016个区块前的区块作为起始点
  
  // 初始化指针：从当前区块开始向前遍历
  const CBlockIndex *pindexFirst = pindexLast;
  
  // 向后遍历nInterval-1个区块（约14天的区块）
  // 循环结束后，pindexFirst指向2016个区块前的区块
  for (int i = 0; pindexFirst && i < nInterval - 1; i++)
    pindexFirst = pindexFirst->pprev;
  
  // 确保pindexFirst不为空（断言用于调试阶段）
  assert(pindexFirst);

  // 步骤2：计算实际时间跨度
  // 计算最近2016个区块实际生成所需的时间
  
  // 实际时间跨度 = 最后一个区块时间 - 第一个区块时间
  // 这里使用GetBlockTime()获取区块的时间戳
  int64 nActualTimespan =
      pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();
      
  printf("  nActualTimespan = %" PRI64d "  before bounds\n", nActualTimespan);
  
  // 步骤3：限制实际时间跨度的范围
  // 防止难度调整过度激进，保持网络稳定性
  
  // 下限：实际时间不能小于目标时间的1/4
  // 如果实际时间过短，说明算力增长过快，需要限制难度增加的幅度
  if (nActualTimespan < nTargetTimespan / 4)
    nActualTimespan = nTargetTimespan / 4;
    
  // 上限：实际时间不能大于目标时间的4倍
  // 如果实际时间过长，说明算力下降过快，需要限制难度降低的幅度
  if (nActualTimespan > nTargetTimespan * 4)
    nActualTimespan = nTargetTimespan * 4;

  // 步骤4：计算新的难度目标值（难度调整的核心算法）
  // 使用比例调整法：根据实际时间与目标时间的比率调整难度
  
  // 创建大数对象，用于高精度计算
  CBigNum bnNew;
  
  // 将当前难度值转换为大数
  bnNew.SetCompact(pindexLast->nBits);
  
  // 调整公式：新难度 = 当前难度 * (实际时间 / 目标时间)
  // 如果实际时间大于目标时间（出块慢），则增大难度目标值（降低难度）
  // 如果实际时间小于目标时间（出块快），则减小难度目标值（提高难度）
  bnNew *= nActualTimespan; // 乘以实际时间跨度
  bnNew /= nTargetTimespan; // 除以目标时间跨度

  // 步骤5：确保新难度不超过系统最大难度限制
  // 防止难度调整过度，保持网络安全性
  if (bnNew > bnProofOfWorkLimit)
    bnNew = bnProofOfWorkLimit;

  /// 调试信息输出
  // 打印难度调整的详细信息，便于监控和调试
  printf("GetNextWorkRequired RETARGET\n");
  printf("nTargetTimespan = %" PRI64d "    nActualTimespan = %" PRI64d "\n",
         nTargetTimespan, nActualTimespan);
  printf(
      "Before: %08x  %s\n", pindexLast->nBits,
      CBigNum().SetCompact(pindexLast->nBits).getuint256().ToString().c_str());
  printf("After:  %08x  %s\n", bnNew.GetCompact(),
         bnNew.getuint256().ToString().c_str());

  // 返回新难度的紧凑编码格式
  return bnNew.GetCompact();
}
// 验证区块的工作量证明（Proof of Work）
// 该函数检查区块的哈希值是否小于等于目标值（nBits）
// 设计目的：确保区块被挖掘出，符合比特币的工作量证明机制
bool CheckProofOfWork(uint256 hash, unsigned int nBits) {
  CBigNum bnTarget;
  bnTarget.SetCompact(nBits);

  // Check range
  if (bnTarget <= 0 || bnTarget > bnProofOfWorkLimit)
    return error("CheckProofOfWork() : nBits below minimum work");

  // Check proof of work matches claimed amount
  if (hash > bnTarget.getuint256())
    return error("CheckProofOfWork() : hash doesn't match nBits");

  return true;
}
// 检查是否正在进行初始区块链下载（Initial Block Download, IBD）
// 该函数根据当前区块链状态和高度，判断是否正在进行IBD
// 设计目的：在IBD过程中，需要禁用一些功能，如交易验证、挖矿等
bool IsInitialBlockDownload() {
  if (pindexBest == NULL || (!fTestNet && nBestHeight < 74000))
    return true;
  static int64 nLastUpdate;
  static CBlockIndex *pindexLastBest;
  if (pindexBest != pindexLastBest) {
    pindexLastBest = pindexBest;
    nLastUpdate = GetTime();
  }
  return (GetTime() - nLastUpdate < 10 &&
          pindexBest->GetBlockTime() < GetTime() - 24 * 60 * 60);
}
// 处理无效区块链发现事件
// 该函数在发现新的无效区块链时调用
// 设计目的：及时发现并处理无效的区块链，保持网络的健康运行
void InvalidChainFound(CBlockIndex *pindexNew) {
  if (pindexNew->bnChainWork > bnBestInvalidWork) {
    bnBestInvalidWork = pindexNew->bnChainWork;
    CTxDB().WriteBestInvalidWork(bnBestInvalidWork);
    MainFrameRepaint();
  }
  printf("InvalidChainFound: invalid block=%s  height=%d  work=%s\n",
         pindexNew->GetBlockHash().ToString().substr(0, 20).c_str(),
         pindexNew->nHeight, pindexNew->bnChainWork.ToString().c_str());
  printf("InvalidChainFound:  current best=%s  height=%d  work=%s\n",
         hashBestChain.ToString().substr(0, 20).c_str(), nBestHeight,
         bnBestChainWork.ToString().c_str());
  if (pindexBest &&
      bnBestInvalidWork > bnBestChainWork + pindexBest->GetBlockWork() * 6)
    printf("InvalidChainFound: WARNING: Displayed transactions may not be "
           "correct!  You may need to upgrade, or other nodes may need to "
           "upgrade.\n");
}

// 交易输入断开连接函数
// 该函数执行与ConnectInputs相反的操作，用于撤销交易的输入连接
// 在区块链重组（reorg）或区块断开连接时调用
// 设计目的：清理交易对UTXO集的修改，恢复到交易前的状态
bool CTransaction::DisconnectInputs(CTxDB &txdb) {
  // 释放前一个交易已花费输出的控制权
  // 与ConnectInputs相反，这里需要将已花费的输出恢复为未花费状态
  if (!IsCoinBase()) {
    foreach (const CTxIn &txin, vin) {
      COutPoint prevout = txin.prevout; // 当前输入引用的前一个输出

      // 从磁盘中获取前一个输出的交易索引信息
      // 这里需要从数据库读取，因为之前ConnectInputs可能已经将状态写入磁盘
      CTxIndex txindex;
      if (!txdb.ReadTxIndex(prevout.hash, txindex))
        return error("DisconnectInputs() : ReadTxIndex failed");

      // 验证输出索引的有效性
      if (prevout.n >= txindex.vSpent.size())
        return error("DisconnectInputs() : prevout.n out of range");

      // 将输出标记为未花费状态
      // SetNull()函数将vSpent数组中对应位置的标记清除，表示该输出现在可以再次被花费
      txindex.vSpent[prevout.n].SetNull();

      // 写回更新后的交易索引
      // 将恢复后的状态保存到数据库中
      if (!txdb.UpdateTxIndex(prevout.hash, txindex))
        return error("DisconnectInputs() : UpdateTxIndex failed");
    }
  }

  // 从索引中移除交易
  // 删除当前交易在磁盘索引中的记录
  if (!txdb.EraseTxIndex(*this))
    return error("DisconnectInputs() : EraseTxPos failed");

  return true;
}

// 交易输入连接验证函数
// 该函数是比特币交易验证的核心，负责验证当前交易的输入是否有效
// 并建立交易之间的连接关系，是UTXO模型实现的关键函数
// 设计目的：确保每个交易都引用有效的未花费输出，防止双重支付
bool CTransaction::ConnectInputs(CTxDB &txdb,
                                 map<uint256, CTxIndex> &mapTestPool,
                                 CDiskTxPos posThisTx, CBlockIndex *pindexBlock,
                                 int64 &nFees, bool fBlock, bool fMiner,
                                 int64 nMinFee) {
  // 获取前一个交易已花费输出的控制权
  // 这是交易验证的第一步，需要检查每个输入引用的前一个输出是否存在且未被花费
  if (!IsCoinBase()) {
    int64 nValueIn = 0; // 总输入金额累计器，用于验证输入输出平衡
    for (int i = 0; i < vin.size(); i++) {
      COutPoint prevout = vin[i].prevout; // 当前输入引用的前一个输出

      // 读取前一个输出的交易索引信息
      // CTxIndex包含交易在磁盘上的位置和花费状态信息
      CTxIndex txindex;
      bool fFound = true;
      if (fMiner && mapTestPool.count(prevout.hash)) {
        // 在挖矿模式下，从当前提议的变更池中获取交易索引
        // 这允许在创建新区块时临时验证交易链
        txindex = mapTestPool[prevout.hash];
      } else {
        // 从数据库中读取交易索引
        fFound = txdb.ReadTxIndex(prevout.hash, txindex);
      }
      if (!fFound && (fBlock || fMiner))
        return fMiner ? false
                      : error("ConnectInputs() : %s prev tx %s index entry not "
                              "found",
                              GetHash().ToString().substr(0, 10).c_str(),
                              prevout.hash.ToString().substr(0, 10).c_str());

      // 读取前一个交易数据
      CTransaction txPrev;
      if (!fFound || txindex.pos == CDiskTxPos(1, 1, 1)) {
        // 从内存中的未确认交易中获取前一个交易
        // CDiskTxPos(1,1,1)表示该交易仅存在于内存池中，未写入磁盘
        CRITICAL_BLOCK(cs_mapTransactions) {
          if (!mapTransactions.count(prevout.hash))
            return error(
                "ConnectInputs() : %s mapTransactions prev not found %s",
                GetHash().ToString().substr(0, 10).c_str(),
                prevout.hash.ToString().substr(0, 10).c_str());
          txPrev = mapTransactions[prevout.hash];
        }
        if (!fFound)
          txindex.vSpent.resize(txPrev.vout.size());
      } else {
        // 从磁盘中读取前一个交易
        if (!txPrev.ReadFromDisk(txindex.pos))
          return error("ConnectInputs() : %s ReadFromDisk prev tx %s failed",
                       GetHash().ToString().substr(0, 10).c_str(),
                       prevout.hash.ToString().substr(0, 10).c_str());
      }

      // 验证输出索引的有效性
      // 确保引用的输出索引在交易输出数组和花费状态数组中都是有效的
      if (prevout.n >= txPrev.vout.size() || prevout.n >= txindex.vSpent.size())
        return error("ConnectInputs() : %s prevout.n out of range %d %d %d "
                     "prev tx %s\n%s",
                     GetHash().ToString().substr(0, 10).c_str(), prevout.n,
                     txPrev.vout.size(), txindex.vSpent.size(),
                     prevout.hash.ToString().substr(0, 10).c_str(),
                     txPrev.ToString().c_str());

      // 如果前一个交易是币基交易，检查其成熟度
      // 币基交易需要在区块链中确认COINBASE_MATURITY(100)次才能被花费
      if (txPrev.IsCoinBase())
        for (CBlockIndex *pindex = pindexBlock;
             pindex &&
             pindexBlock->nHeight - pindex->nHeight < COINBASE_MATURITY;
             pindex = pindex->pprev)
          if (pindex->nBlockPos == txindex.pos.nBlockPos &&
              pindex->nFile == txindex.pos.nFile)
            return error(
                "ConnectInputs() : tried to spend coinbase at depth %d",
                pindexBlock->nHeight - pindex->nHeight);

      // 验证数字签名
      // 确保当前交易的输入确实有权限花费引用的输出
      if (!VerifySignature(txPrev, *this, i))
        return error("ConnectInputs() : %s VerifySignature failed",
                     GetHash().ToString().substr(0, 10).c_str());

      // 检查双重支付
      // 确保被引用的输出尚未被其他交易花费
      if (!txindex.vSpent[prevout.n].IsNull())
        return fMiner ? false
                      : error("ConnectInputs() : %s prev tx already used at %s",
                              GetHash().ToString().substr(0, 10).c_str(),
                              txindex.vSpent[prevout.n].ToString().c_str());

      // 检查输入金额的有效性，防止负值或溢出
      // 确保单个输出金额和累计输入金额都在有效范围内
      nValueIn += txPrev.vout[prevout.n].nValue;
      if (!MoneyRange(txPrev.vout[prevout.n].nValue) || !MoneyRange(nValueIn))
        return error("ConnectInputs() : txin values out of range");

      // 标记输出为已花费状态
      // 将当前交易的磁盘位置记录到vSpent数组中，建立花费关系
      txindex.vSpent[prevout.n] = posThisTx;

      // 写回修改后的交易索引
      // 根据不同的调用模式，将更新后的索引写入数据库或测试池
      if (fBlock) {
        if (!txdb.UpdateTxIndex(prevout.hash, txindex))
          return error("ConnectInputs() : UpdateTxIndex failed");
      } else if (fMiner) {
        mapTestPool[prevout.hash] = txindex;
      }
    }

    // 验证输入输出平衡
    // 确保总输入金额不小于总输出金额，防止创建新资金
    if (nValueIn < GetValueOut())
      return error("ConnectInputs() : %s value in < value out",
                   GetHash().ToString().substr(0, 10).c_str());

    // 计算交易费用
    // 交易费用 = 总输入金额 - 总输出金额，矿工可以收取此费用
    int64 nTxFee = nValueIn - GetValueOut();
    if (nTxFee < 0)
      return error("ConnectInputs() : %s nTxFee < 0",
                   GetHash().ToString().substr(0, 10).c_str());
    if (nTxFee < nMinFee)
      return false;
    nFees += nTxFee;
    if (!MoneyRange(nFees))
      return error("ConnectInputs() : nFees out of range");
  }

  // 添加当前交易到索引中
  // 根据不同的调用模式，将当前交易添加到磁盘索引或测试池中
  if (fBlock) {
    // 将交易添加到磁盘索引中
    if (!txdb.AddTxIndex(*this, posThisTx, pindexBlock->nHeight))
      return error("ConnectInputs() : AddTxPos failed");
  } else if (fMiner) {
    // 将交易添加到测试池中（用于挖矿时的临时验证）
    mapTestPool[GetHash()] = CTxIndex(CDiskTxPos(1, 1, 1), vout.size());
  }

  return true;
}

// 客户端模式交易连接验证函数
// 这是ConnectInputs函数的简化版本，专门用于轻量级客户端
// 只验证内存中的交易，不涉及磁盘操作，适用于SPV（简化支付验证）模式
// 设计目的：为资源受限的客户端提供基本的交易验证功能
bool CTransaction::ClientConnectInputs() {
  // 币基交易不需要连接输入，币基交易是由矿工创建的新币交易
  if (IsCoinBase())
    return false;

  // 获取前一个交易已花费输出的控制权
  // 客户端模式下只处理内存池中的交易，不访问磁盘数据库
  CRITICAL_BLOCK(cs_mapTransactions) {
    int64 nValueIn = 0; // 累计输入金额
    for (int i = 0; i < vin.size(); i++) {
      // 从内存中的单笔交易中获取前一个交易
      // 注意：这里只验证内存池中的交易，不涉及区块链上的历史交易
      COutPoint prevout = vin[i].prevout;
      if (!mapTransactions.count(prevout.hash))
        return false;
      CTransaction &txPrev = mapTransactions[prevout.hash];

      // 验证输出索引的有效性
      if (prevout.n >= txPrev.vout.size())
        return false;

      // 验证数字签名
      // 确保当前交易有权限花费引用的输出
      if (!VerifySignature(txPrev, *this, i))
        return error("ConnectInputs() : VerifySignature failed");

      // 检查双重支付（已注释的旧代码）
      // 以下代码使用了过时的posNext机制，现在已被vSpent数组替代
      // 这些检查现在是多余的，因为ConnectInputs函数已经处理了这些验证
      ///// this is redundant with the mapNextTx stuff, not sure which I want to
      /// get rid of
      ///// this has to go away now that posNext is gone
      // // Check for conflicts
      // if (!txPrev.vout[prevout.n].posNext.IsNull())
      //     return error("ConnectInputs() : prev tx already used");
      //
      // // Flag outpoints as used
      // txPrev.vout[prevout.n].posNext = posThisTx;

      // 累计输入金额并验证范围
      nValueIn += txPrev.vout[prevout.n].nValue;

      if (!MoneyRange(txPrev.vout[prevout.n].nValue) || !MoneyRange(nValueIn))
        return error("ClientConnectInputs() : txin values out of range");
    }
    // 验证输入输出平衡
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
    if (!txdb.WriteBlockIndex(blockindexPrev))
      return error("DisconnectBlock() : WriteBlockIndex failed");
  }

  return true;
}

bool CBlock::ConnectBlock(CTxDB &txdb, CBlockIndex *pindex) {
  // Check it again in case a previous version let a bad block in
  if (!CheckBlock())
    return false;

  //// issue here: it doesn't know the version
  unsigned int nTxPos = pindex->nBlockPos +
                        ::GetSerializeSize(CBlock(), SER_DISK) - 1 +
                        GetSizeOfCompactSize(vtx.size());

  map<uint256, CTxIndex> mapUnused;
  int64 nFees = 0;
  foreach (CTransaction &tx, vtx) {
    CDiskTxPos posThisTx(pindex->nFile, pindex->nBlockPos, nTxPos);
    nTxPos += ::GetSerializeSize(tx, SER_DISK);

    if (!tx.ConnectInputs(txdb, mapUnused, posThisTx, pindex, nFees, true,
                          false))
      return false;
  }

  if (vtx[0].GetValueOut() > GetBlockValue(pindex->nHeight, nFees))
    return false;

  // Update block index on disk without changing it in memory.
  // The memory index structure will be changed after the db commits.
  if (pindex->pprev) {
    CDiskBlockIndex blockindexPrev(pindex->pprev);
    blockindexPrev.hashNext = pindex->GetBlockHash();
    if (!txdb.WriteBlockIndex(blockindexPrev))
      return error("ConnectBlock() : WriteBlockIndex failed");
  }

  // Watch for transactions paying to me
  foreach (CTransaction &tx, vtx)
    AddToWalletIfMine(tx, this);

  return true;
}

bool Reorganize(CTxDB &txdb, CBlockIndex *pindexNew) {
  printf("REORGANIZE\n");

  // Find the fork
  CBlockIndex *pfork = pindexBest;
  CBlockIndex *plonger = pindexNew;
  while (pfork != plonger) {
    while (plonger->nHeight > pfork->nHeight)
      if (!(plonger = plonger->pprev))
        return error("Reorganize() : plonger->pprev is null");
    if (pfork == plonger)
      break;
    if (!(pfork = pfork->pprev))
      return error("Reorganize() : pfork->pprev is null");
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
    if (!block.ReadFromDisk(pindex))
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
    if (!block.ReadFromDisk(pindex))
      return error("Reorganize() : ReadFromDisk for connect failed");
    if (!block.ConnectBlock(txdb, pindex)) {
      // Invalid block
      txdb.TxnAbort();
      return error("Reorganize() : ConnectBlock failed");
    }

    // Queue memory transactions to delete
    foreach (const CTransaction &tx, block.vtx)
      vDelete.push_back(tx);
  }
  if (!txdb.WriteHashBestChain(pindexNew->GetBlockHash()))
    return error("Reorganize() : WriteHashBestChain failed");

  // Make sure it's successfully written to disk before changing memory
  // structure
  if (!txdb.TxnCommit())
    return error("Reorganize() : TxnCommit failed");

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
    tx.AcceptToMemoryPool(txdb, false);

  // Delete redundant memory transactions that are in the connected branch
  foreach (CTransaction &tx, vDelete)
    tx.RemoveFromMemoryPool();

  return true;
}

bool CBlock::SetBestChain(CTxDB &txdb, CBlockIndex *pindexNew) {
  uint256 hash = GetHash();

  txdb.TxnBegin();
  if (pindexGenesisBlock == NULL && hash == hashGenesisBlock) {
    txdb.WriteHashBestChain(hash);
    if (!txdb.TxnCommit())
      return error("SetBestChain() : TxnCommit failed");
    pindexGenesisBlock = pindexNew;
  } else if (hashPrevBlock == hashBestChain) {
    // Adding to current best branch
    if (!ConnectBlock(txdb, pindexNew) || !txdb.WriteHashBestChain(hash)) {
      txdb.TxnAbort();
      InvalidChainFound(pindexNew);
      return error("SetBestChain() : ConnectBlock failed");
    }
    if (!txdb.TxnCommit())
      return error("SetBestChain() : TxnCommit failed");

    // Add to current best branch
    pindexNew->pprev->pnext = pindexNew;

    // Delete redundant memory transactions
    foreach (CTransaction &tx, vtx)
      tx.RemoveFromMemoryPool();
  } else {
    // New best branch
    if (!Reorganize(txdb, pindexNew)) {
      txdb.TxnAbort();
      InvalidChainFound(pindexNew);
      return error("SetBestChain() : Reorganize failed");
    }
  }

  // New best block
  hashBestChain = hash;
  pindexBest = pindexNew;
  nBestHeight = pindexBest->nHeight;
  bnBestChainWork = pindexNew->bnChainWork;
  nTimeBestReceived = GetTime();
  nTransactionsUpdated++;
  printf("SetBestChain: new best=%s  height=%d  work=%s\n",
         hashBestChain.ToString().substr(0, 20).c_str(), nBestHeight,
         bnBestChainWork.ToString().c_str());

  return true;
}

bool CBlock::AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos) {
  // Check for duplicate
  uint256 hash = GetHash();
  if (mapBlockIndex.count(hash))
    return error("AddToBlockIndex() : %s already exists",
                 hash.ToString().substr(0, 20).c_str());

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
  pindexNew->bnChainWork =
      (pindexNew->pprev ? pindexNew->pprev->bnChainWork : 0) +
      pindexNew->GetBlockWork();

  CTxDB txdb;
  txdb.TxnBegin();
  txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew));
  if (!txdb.TxnCommit())
    return false;

  // New best
  if (pindexNew->bnChainWork > bnBestChainWork)
    if (!SetBestChain(txdb, pindexNew))
      return false;

  txdb.Close();

  if (pindexNew == pindexBest) {
    // Notify UI to display prev block's coinbase if it was ours
    static uint256 hashPrevBestCoinBase;
    CRITICAL_BLOCK(cs_mapWallet)
    vWalletUpdated.push_back(hashPrevBestCoinBase);
    hashPrevBestCoinBase = vtx[0].GetHash();
  }

  MainFrameRepaint();
  return true;
}

// 区块完整性验证方法
// 该方法执行区块的基础验证，检查区块结构和内容的合法性
// 验证过程独立于区块链上下文，可在将区块保存为孤儿区块之前进行验证
// 这是区块接受的第一道防线，确保只处理结构正确的基本区块
bool CBlock::CheckBlock() const {
  // 这些检查项独立于区块链上下文，在保存孤儿区块之前就可以验证

  // 检查项1：区块大小限制验证
  // 确保区块不会过大，避免网络传输和存储问题
  // 检查内容包括：
  // - 交易数量不能为空且不能超过最大交易数限制
  // - 序列化后的区块大小不能超过1MB限制
  if (vtx.empty() || vtx.size() > MAX_BLOCK_SIZE ||
      ::GetSerializeSize(*this, SER_NETWORK) > MAX_BLOCK_SIZE)
    return error("CheckBlock() : size limits failed");

  // 检查项2：工作量证明验证
  // 验证区块的哈希值是否满足难度要求，确保挖矿工作的真实性
  // 这是比特币共识机制的核心，防止虚假区块攻击
  // 参数：GetHash()获取区块哈希值，nBits为难度目标压缩表示
  if (!CheckProofOfWork(GetHash(), nBits))
    return error("CheckBlock() : proof of work failed");

  // 检查项3：时间戳合理性验证
  // 确保区块时间戳不会太超前，避免时间操纵攻击
  // 当前时间 + 2小时作为上限，给网络时钟偏差预留余量
  if (GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60)
    return error("CheckBlock() : block timestamp too far in the future");

  // 检查项4：创币交易验证
  // 确保区块包含且只包含一个创币交易，这是比特币区块的标准结构
  // 创币交易（Coinbase Transaction）是区块中生成新比特币的特殊交易
  // 它包含了新生成的比特币奖励和矿工签名
  // 验证第一笔交易必须是创币交易
  if (vtx.empty() || !vtx[0].IsCoinBase())
    return error("CheckBlock() : first tx is not coinbase");

  // 验证除第一笔交易外，其他交易都不能是创币交易
  // 防止创建多个创币交易来生成额外比特币
  for (int i = 1; i < vtx.size(); i++)
    if (vtx[i].IsCoinBase())
      return error("CheckBlock() : more than one coinbase");

  // 检查项5：交易内容验证
  // 验证区块中每笔交易的基本结构合法性
  // 包括签名验证、输入输出检查、金额验证等交易级别的安全检查
  foreach (const CTransaction &tx, vtx)
    if (!tx.CheckTransaction())
      return error("CheckBlock() : CheckTransaction failed");

  // 检查项6：签名操作数量限制
  // 验证区块中的签名操作总数不超过限制，防止区块被恶意构造得过于复杂
  // 限制签名操作数量可以防止DoS攻击和区块处理性能问题
  // 这里是检查区块中是否包含过多的非标准交易或复杂的签名操作
  if (GetSigOpCount() > MAX_BLOCK_SIGOPS)
    return error("CheckBlock() : too many nonstandard transactions");

  // 检查项7：梅克尔根验证
  // 验证区块头中存储的梅克尔根哈希与实际计算的梅克尔树根哈希是否一致
  // 这是确保区块中所有交易完整性和正确性的关键验证
  // 如果不一致，说明区块中的交易数据被篡改或构造错误
  if (hashMerkleRoot != BuildMerkleTree())
    return error("CheckBlock() : hashMerkleRoot mismatch");

  // 所有验证通过，区块结构合法
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
  int nHeight = pindexPrev->nHeight + 1;

  // Check proof of work
  if (nBits != GetNextWorkRequired(pindexPrev))
    return error("AcceptBlock() : incorrect proof of work");

  // Check timestamp against prev
  if (GetBlockTime() <= pindexPrev->GetMedianTimePast())
    return error("AcceptBlock() : block's timestamp is too early");

  // Check that all transactions are finalized
  foreach (const CTransaction &tx, vtx)
    if (!tx.IsFinal(nHeight, GetBlockTime()))
      return error("AcceptBlock() : contains a non-final transaction");

  // Check that the block chain matches the known block chain up to a checkpoint
  if (!fTestNet)
    if ((nHeight == 11111 &&
         hash != uint256("0x0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f"
                         "542fdb26e7c1d")) ||
        (nHeight == 33333 &&
         hash != uint256("0x000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f"
                         "00d7ddfb5d0a6")) ||
        (nHeight == 68555 &&
         hash != uint256("0x00000000001e1b4903550a0b96e9a9405c8a95f387162e4944e"
                         "8d9fbe501cd6a")) ||
        (nHeight == 70567 &&
         hash != uint256("0x00000000006a49b14bcf27462068f1264c961f11fa2e0eddd2b"
                         "e0791e1d4124a")) ||
        (nHeight == 74000 &&
         hash != uint256("0x0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e"
                         "7f953b8661a20")))
      return error("AcceptBlock() : rejected by checkpoint lockin at %d",
                   nHeight);

  // Write block to history file
  if (!CheckDiskSpace(::GetSerializeSize(*this, SER_DISK)))
    return error("AcceptBlock() : out of disk space");
  unsigned int nFile = -1;
  unsigned int nBlockPos = 0;
  if (!WriteToDisk(nFile, nBlockPos))
    return error("AcceptBlock() : WriteToDisk failed");
  if (!AddToBlockIndex(nFile, nBlockPos))
    return error("AcceptBlock() : AddToBlockIndex failed");

  // Relay inventory, but don't relay old inventory during initial block
  // download
  if (hashBestChain == hash)
    CRITICAL_BLOCK(cs_vNodes)
  foreach (CNode *pnode, vNodes)
    if (nBestHeight >
        (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : 55000))
      pnode->PushInventory(CInv(MSG_BLOCK, hash));

  return true;
}

// 处理从网络接收到的区块
// 流程：去重验证 → 前序检查 → 存储到磁盘 → 递归处理孤儿区块
// 设计目的：处理网络接收到的区块，验证其有效性，并维护区块链的一致性
bool ProcessBlock(CNode *pfrom, CBlock *pblock) {
  // 检查是否已有该区块（去重处理）
  // 首先检查是否已经在主链索引中，如果存在则忽略
  uint256 hash = pblock->GetHash();
  if (mapBlockIndex.count(hash))
    return error("ProcessBlock() : already have block %d %s",
                 mapBlockIndex[hash]->nHeight,
                 hash.ToString().substr(0, 20).c_str());
  // 检查是否已经在孤儿区块池中，如果存在则忽略
  if (mapOrphanBlocks.count(hash))
    return error("ProcessBlock() : already have block (orphan) %s",
                 hash.ToString().substr(0, 20).c_str());

  // 基本结构验证
  // 验证区块的基本结构、哈希值、工作量证明等
  if (!pblock->CheckBlock())
    return error("ProcessBlock() : CheckBlock FAILED");

  // 检查前序区块是否存在（孤儿区块处理的关键逻辑）
  // 如果前序区块不在主链索引中，则此区块为孤儿区块
  if (!mapBlockIndex.count(pblock->hashPrevBlock)) {
    printf("ProcessBlock: ORPHAN BLOCK, prev=%s\n",
           pblock->hashPrevBlock.ToString().substr(0, 20).c_str());

    // 创建孤儿区块副本并存储到孤儿区块池中
    // 使用动态分配，因为孤儿区块可能需要在内存中保留一段时间
    CBlock *pblock2 = new CBlock(*pblock);
    mapOrphanBlocks.insert(make_pair(hash, pblock2));
    // 建立反向映射，便于后续找到依赖此区块的孤儿区块
    mapOrphanBlocksByPrev.insert(make_pair(pblock2->hashPrevBlock, pblock2));

    // 向网络请求缺失的前序区块
    // 使用GetOrphanRoot找到孤儿链的起始点，请求完整的链
    if (pfrom)
      pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(pblock2));
    return true;
  }

  // 前序区块存在，可以正常处理区块
  // 存储到磁盘并添加到主链索引中
  if (!pblock->AcceptBlock())
    return error("ProcessBlock() : AcceptBlock FAILED");

  // 递归处理依赖此区块的孤儿区块
  // 当新区块被接受后，可能会有依赖此区块的孤儿区块变得可以处理
  vector<uint256> vWorkQueue;
  vWorkQueue.push_back(hash); // 从当前区块开始处理

  // 广度优先遍历，依次处理每个新加入的区块
  for (int i = 0; i < vWorkQueue.size(); i++) {
    uint256 hashPrev = vWorkQueue[i];

    // 查找所有依赖当前区块的孤儿区块
    for (multimap<uint256, CBlock *>::iterator mi =
             mapOrphanBlocksByPrev.lower_bound(hashPrev);
         mi != mapOrphanBlocksByPrev.upper_bound(hashPrev); ++mi) {
      CBlock *pblockOrphan = (*mi).second;

      // 尝试接受这个孤儿区块
      if (pblockOrphan->AcceptBlock())
        vWorkQueue.push_back(pblockOrphan->GetHash()); // 如果成功，加入处理队列

      // 从孤儿区块池中删除此区块
      mapOrphanBlocks.erase(pblockOrphan->GetHash());
      delete pblockOrphan; // 释放内存
    }
    // 清理当前区块的反向映射
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

bool CheckDiskSpace(uint64 nAdditionalBytes) {
  uint64 nFreeBytesAvailable = filesystem::space(GetDataDir()).available;

  // Check for 15MB because database could create another 10MB log file at any
  // time
  if (nFreeBytesAvailable < (uint64)15000000 + nAdditionalBytes) {
    fShutdown = true;
    string strMessage = _("Warning: Disk space is low  ");
    strMiscWarning = strMessage;
    printf("*** %s\n", strMessage.c_str());
    ThreadSafeMessageBox(strMessage, "Bitcoin", wxOK | wxICON_EXCLAMATION);
    CreateThread(Shutdown, NULL);
    return false;
  }
  return true;
}

FILE *OpenBlockFile(unsigned int nFile, unsigned int nBlockPos,
                    const char *pszMode) {
  if (nFile == -1)
    return NULL;
  FILE *file =
      fopen(strprintf("%s/blk%04d.dat", GetDataDir().c_str(), nFile).c_str(),
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
  if (fTestNet) {
    hashGenesisBlock = uint256(
        "0x0000000224b1593e3ff16a0e3b61285bbc393a39f78c8aa48c456142671f7110");
    bnProofOfWorkLimit = CBigNum(~uint256(0) >> 28);
    pchMessageStart[0] = 0xfa;
    pchMessageStart[1] = 0xbf;
    pchMessageStart[2] = 0xb5;
    pchMessageStart[3] = 0xda;
  }

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
    // CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000,
    // hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff,
    // nNonce=2083236893, vtx=1)
    //   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
    //     CTxIn(COutPoint(000000, -1), coinbase
    //     04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
    //     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
    //   vMerkleTree: 4a5e1e

    // Genesis block
    const char *pszTimestamp =
        "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig =
        CScript() << 486604799 << CBigNum(4)
                  << vector<unsigned char>((const unsigned char *)pszTimestamp,
                                           (const unsigned char *)pszTimestamp +
                                               strlen(pszTimestamp));
    txNew.vout[0].nValue = 50 * COIN;
    txNew.vout[0].scriptPubKey =
        CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
                              "de5c384df7ba0b8d578a4c702b6bf11d5f")
                  << OP_CHECKSIG;
    CBlock block;
    block.vtx.push_back(txNew);
    block.hashPrevBlock = 0;
    block.hashMerkleRoot = block.BuildMerkleTree();
    block.nVersion = 1;
    block.nTime = 1231006505;
    block.nBits = 0x1d00ffff;
    block.nNonce = 2083236893;

    if (fTestNet) {
      block.nTime = 1279232055;
      block.nBits = 0x1d07fff8;
      block.nNonce = 81622180;
    }

    //// debug print
    printf("%s\n", block.GetHash().ToString().c_str());
    printf("%s\n", hashGenesisBlock.ToString().c_str());
    printf("%s\n", block.hashMerkleRoot.ToString().c_str());
    assert(block.hashMerkleRoot == uint256("0x4a5e1e4baab89f3a32518a88c31bc87f6"
                                           "18f76673e2cc77ab2127b7afdeda33b"));
    block.print();
    assert(block.GetHash() == hashGenesisBlock);

    // Start new block file
    unsigned int nFile;
    unsigned int nBlockPos;
    if (!block.WriteToDisk(nFile, nBlockPos))
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
    block.ReadFromDisk(pindex);
    printf("%d (%u,%u) %s  %s  tx %d", pindex->nHeight, pindex->nFile,
           pindex->nBlockPos, block.GetHash().ToString().substr(0, 20).c_str(),
           DateTimeStrFormat("%x %H:%M:%S", block.GetBlockTime()).c_str(),
           block.vtx.size());

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
// CAlert
//

map<uint256, CAlert> mapAlerts;
CCriticalSection cs_mapAlerts;

string GetWarnings(string strFor) {
  int nPriority = 0;
  string strStatusBar;
  string strRPC;
  if (GetBoolArg("-testsafemode"))
    strRPC = "test";

  // Misc warnings like out of disk space and clock is wrong
  if (strMiscWarning != "") {
    nPriority = 1000;
    strStatusBar = strMiscWarning;
  }

  // Longer invalid proof-of-work chain
  if (pindexBest &&
      bnBestInvalidWork > bnBestChainWork + pindexBest->GetBlockWork() * 6) {
    nPriority = 2000;
    strStatusBar = strRPC =
        "WARNING: Displayed transactions may not be correct!  You may need to "
        "upgrade, or other nodes may need to upgrade.";
  }

  // Alerts
  CRITICAL_BLOCK(cs_mapAlerts) {
    foreach (PAIRTYPE(const uint256, CAlert) & item, mapAlerts) {
      const CAlert &alert = item.second;
      if (alert.AppliesToMe() && alert.nPriority > nPriority) {
        nPriority = alert.nPriority;
        strStatusBar = alert.strStatusBar;
      }
    }
  }

  if (strFor == "statusbar")
    return strStatusBar;
  else if (strFor == "rpc")
    return strRPC;
  assert(("GetWarnings() : invalid parameter", false));
  return "error";
}

bool CAlert::ProcessAlert() {
  if (!CheckSignature())
    return false;
  if (!IsInEffect())
    return false;

  CRITICAL_BLOCK(cs_mapAlerts) {
    // Cancel previous alerts
    for (map<uint256, CAlert>::iterator mi = mapAlerts.begin();
         mi != mapAlerts.end();) {
      const CAlert &alert = (*mi).second;
      if (Cancels(alert)) {
        printf("cancelling alert %d\n", alert.nID);
        mapAlerts.erase(mi++);
      } else if (!alert.IsInEffect()) {
        printf("expiring alert %d\n", alert.nID);
        mapAlerts.erase(mi++);
      } else
        mi++;
    }

    // Check if this alert has been cancelled
    foreach (PAIRTYPE(const uint256, CAlert) & item, mapAlerts) {
      const CAlert &alert = item.second;
      if (alert.Cancels(*this)) {
        printf("alert already cancelled by %d\n", alert.nID);
        return false;
      }
    }

    // Add to mapAlerts
    mapAlerts.insert(make_pair(GetHash(), *this));
  }

  printf("accepted alert %d, AppliesToMe()=%d\n", nID, AppliesToMe());
  MainFrameRepaint();
  return true;
}

//////////////////////////////////////////////////////////////////////////////
//
// Messages
//

bool AlreadyHave(CTxDB &txdb, const CInv &inv) {
  switch (inv.type) {
  case MSG_TX:
    return mapTransactions.count(inv.hash) ||
           mapOrphanTransactions.count(inv.hash) || txdb.ContainsTx(inv.hash);
  case MSG_BLOCK:
    return mapBlockIndex.count(inv.hash) || mapOrphanBlocks.count(inv.hash);
  }
  // Don't know what it is, just say we already got one
  return true;
}

// The message start string is designed to be unlikely to occur in normal data.
// The characters are rarely used upper ascii, not valid as UTF-8, and produce
// a large 4-byte int at any alignment.
char pchMessageStart[4] = {0xf9, 0xbe, 0xb4, 0xd9};

bool ProcessMessages(CNode *pfrom) {
  CDataStream &vRecv = pfrom->vRecv;
  if (vRecv.empty())
    return true;
  // if (fDebug)
  //     printf("ProcessMessages(%u bytes)\n", vRecv.size());

  //
  // Message format
  //  (4) message start
  //  (12) command
  //  (4) size
  //  (4) checksum
  //  (x) data
  //

  loop {
    // Scan for message start
    CDataStream::iterator pstart =
        search(vRecv.begin(), vRecv.end(), BEGIN(pchMessageStart),
               END(pchMessageStart));
    int nHeaderSize = vRecv.GetSerializeSize(CMessageHeader());
    if (vRecv.end() - pstart < nHeaderSize) {
      if (vRecv.size() > nHeaderSize) {
        printf("\n\nPROCESSMESSAGE MESSAGESTART NOT FOUND\n\n");
        vRecv.erase(vRecv.begin(), vRecv.end() - nHeaderSize);
      }
      break;
    }
    if (pstart - vRecv.begin() > 0)
      printf("\n\nPROCESSMESSAGE SKIPPED %d BYTES\n\n", pstart - vRecv.begin());
    vRecv.erase(vRecv.begin(), pstart);

    // Read header
    vector<char> vHeaderSave(vRecv.begin(), vRecv.begin() + nHeaderSize);
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
    if (nMessageSize > MAX_SIZE) {
      printf("ProcessMessage(%s, %u bytes) : nMessageSize > MAX_SIZE\n",
             strCommand.c_str(), nMessageSize);
      continue;
    }
    if (nMessageSize > vRecv.size()) {
      // Rewind and wait for rest of message
      vRecv.insert(vRecv.begin(), vHeaderSave.begin(), vHeaderSave.end());
      break;
    }

    // Checksum
    if (vRecv.GetVersion() >= 209) {
      uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
      unsigned int nChecksum = 0;
      memcpy(&nChecksum, &hash, sizeof(nChecksum));
      if (nChecksum != hdr.nChecksum) {
        printf("ProcessMessage(%s, %u bytes) : CHECKSUM ERROR nChecksum=%08x "
               "hdr.nChecksum=%08x\n",
               strCommand.c_str(), nMessageSize, nChecksum, hdr.nChecksum);
        continue;
      }
    }

    // Copy message to its own buffer
    CDataStream vMsg(vRecv.begin(), vRecv.begin() + nMessageSize, vRecv.nType,
                     vRecv.nVersion);
    vRecv.ignore(nMessageSize);

    // Process message
    bool fRet = false;
    try {
      CRITICAL_BLOCK(cs_main)
      fRet = ProcessMessage(pfrom, strCommand, vMsg);
      if (fShutdown)
        return true;
    } catch (std::ios_base::failure &e) {
      if (strstr(e.what(), "end of data")) {
        // Allow exceptions from underlength message on vRecv
        printf("ProcessMessage(%s, %u bytes) : Exception '%s' caught, normally "
               "caused by a message being shorter than its stated length\n",
               strCommand.c_str(), nMessageSize, e.what());
      } else if (strstr(e.what(), "size too large")) {
        // Allow exceptions from overlong size
        printf("ProcessMessage(%s, %u bytes) : Exception '%s' caught\n",
               strCommand.c_str(), nMessageSize, e.what());
      } else {
        PrintExceptionContinue(&e, "ProcessMessage()");
      }
    } catch (std::exception &e) {
      PrintExceptionContinue(&e, "ProcessMessage()");
    } catch (...) {
      PrintExceptionContinue(NULL, "ProcessMessage()");
    }

    if (!fRet)
      printf("ProcessMessage(%s, %u bytes) FAILED\n", strCommand.c_str(),
             nMessageSize);
  }

  vRecv.Compact();
  return true;
}

bool ProcessMessage(CNode *pfrom, string strCommand, CDataStream &vRecv) {
  static map<unsigned int, vector<unsigned char>> mapReuseKey;
  RandAddSeedPerfmon();
  if (fDebug)
    printf("%s ", DateTimeStrFormat("%x %H:%M:%S", GetTime()).c_str());
  printf("received: %s (%d bytes)\n", strCommand.c_str(), vRecv.size());
  if (mapArgs.count("-dropmessagestest") &&
      GetRand(atoi(mapArgs["-dropmessagestest"])) == 0) {
    printf("dropmessagestest DROPPING RECV MESSAGE\n");
    return true;
  }

  if (strCommand == "version") {
    // Each connection can only send one version message
    if (pfrom->nVersion != 0)
      return false;

    int64 nTime;
    CAddress addrMe;
    CAddress addrFrom;
    uint64 nNonce = 1;
    vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;
    if (pfrom->nVersion == 10300)
      pfrom->nVersion = 300;
    if (pfrom->nVersion >= 106 && !vRecv.empty())
      vRecv >> addrFrom >> nNonce;
    if (pfrom->nVersion >= 106 && !vRecv.empty())
      vRecv >> pfrom->strSubVer;
    if (pfrom->nVersion >= 209 && !vRecv.empty())
      vRecv >> pfrom->nStartingHeight;

    if (pfrom->nVersion == 0)
      return false;

    // Disconnect if we connected to ourself
    if (nNonce == nLocalHostNonce && nNonce > 1) {
      printf("connected to self at %s, disconnecting\n",
             pfrom->addr.ToString().c_str());
      pfrom->fDisconnect = true;
      return true;
    }

    pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);

    AddTimeData(pfrom->addr.ip, nTime);

    // Change version
    if (pfrom->nVersion >= 209)
      pfrom->PushMessage("verack");
    pfrom->vSend.SetVersion(min(pfrom->nVersion, VERSION));
    if (pfrom->nVersion < 209)
      pfrom->vRecv.SetVersion(min(pfrom->nVersion, VERSION));

    if (!pfrom->fInbound) {
      // Advertise our address
      if (addrLocalHost.IsRoutable() && !fUseProxy) {
        CAddress addr(addrLocalHost);
        addr.nTime = GetAdjustedTime();
        pfrom->PushAddress(addr);
      }

      // Get recent addresses
      if (pfrom->nVersion >= 31402 || mapAddresses.size() < 1000) {
        pfrom->PushMessage("getaddr");
        pfrom->fGetAddr = true;
      }
    }

    // Ask the first connected node for block updates
    static int nAskedForBlocks;
    if (!pfrom->fClient && (nAskedForBlocks < 1 || vNodes.size() <= 1)) {
      nAskedForBlocks++;
      pfrom->PushGetBlocks(pindexBest, uint256(0));
    }

    // Relay alerts
    CRITICAL_BLOCK(cs_mapAlerts)
    foreach (PAIRTYPE(const uint256, CAlert) & item, mapAlerts)
      item.second.RelayTo(pfrom);

    pfrom->fSuccessfullyConnected = true;

    printf("version message: version %d, blocks=%d\n", pfrom->nVersion,
           pfrom->nStartingHeight);
  }

  else if (pfrom->nVersion == 0) {
    // Must have a version message before anything else
    return false;
  }

  else if (strCommand == "verack") {
    pfrom->vRecv.SetVersion(min(pfrom->nVersion, VERSION));
  }

  else if (strCommand == "addr") {
    vector<CAddress> vAddr;
    vRecv >> vAddr;

    // Don't want addr from older versions unless seeding
    if (pfrom->nVersion < 209)
      return true;
    if (pfrom->nVersion < 31402 && mapAddresses.size() > 1000)
      return true;
    if (vAddr.size() > 1000)
      return error("message addr size() = %d", vAddr.size());

    // Store the new addresses
    int64 nNow = GetAdjustedTime();
    int64 nSince = nNow - 10 * 60;
    foreach (CAddress &addr, vAddr) {
      if (fShutdown)
        return true;
      // ignore IPv6 for now, since it isn't implemented anyway
      if (!addr.IsIPv4())
        continue;
      if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
        addr.nTime = nNow - 5 * 24 * 60 * 60;
      AddAddress(addr, 2 * 60 * 60);
      pfrom->AddAddressKnown(addr);
      if (addr.nTime > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 &&
          addr.IsRoutable()) {
        // Relay to a limited number of other nodes
        CRITICAL_BLOCK(cs_vNodes) {
          // Use deterministic randomness to send to the same nodes for 24 hours
          // at a time so the setAddrKnowns of the chosen nodes prevent repeats
          static uint256 hashSalt;
          if (hashSalt == 0)
            RAND_bytes((unsigned char *)&hashSalt, sizeof(hashSalt));
          uint256 hashRand = hashSalt ^ (((int64)addr.ip) << 32) ^
                             ((GetTime() + addr.ip) / (24 * 60 * 60));
          hashRand = Hash(BEGIN(hashRand), END(hashRand));
          multimap<uint256, CNode *> mapMix;
          foreach (CNode *pnode, vNodes) {
            if (pnode->nVersion < 31402)
              continue;
            unsigned int nPointer;
            memcpy(&nPointer, &pnode, sizeof(nPointer));
            uint256 hashKey = hashRand ^ nPointer;
            hashKey = Hash(BEGIN(hashKey), END(hashKey));
            mapMix.insert(make_pair(hashKey, pnode));
          }
          int nRelayNodes = 2;
          for (multimap<uint256, CNode *>::iterator mi = mapMix.begin();
               mi != mapMix.end() && nRelayNodes-- > 0; ++mi)
            ((*mi).second)->PushAddress(addr);
        }
      }
    }
    if (vAddr.size() < 1000)
      pfrom->fGetAddr = false;
  }

  else if (strCommand == "inv") {
    vector<CInv> vInv;
    vRecv >> vInv;
    if (vInv.size() > 50000)
      return error("message inv size() = %d", vInv.size());

    CTxDB txdb("r");
    foreach (const CInv &inv, vInv) {
      if (fShutdown)
        return true;
      pfrom->AddInventoryKnown(inv);

      bool fAlreadyHave = AlreadyHave(txdb, inv);
      printf("  got inventory: %s  %s\n", inv.ToString().c_str(),
             fAlreadyHave ? "have" : "new");

      if (!fAlreadyHave)
        pfrom->AskFor(inv);
      else if (inv.type == MSG_BLOCK && mapOrphanBlocks.count(inv.hash))
        pfrom->PushGetBlocks(pindexBest,
                             GetOrphanRoot(mapOrphanBlocks[inv.hash]));

      // Track requests for our stuff
      CRITICAL_BLOCK(cs_mapRequestCount) {
        map<uint256, int>::iterator mi = mapRequestCount.find(inv.hash);
        if (mi != mapRequestCount.end())
          (*mi).second++;
      }
    }
  }

  else if (strCommand == "getdata") {
    vector<CInv> vInv;
    vRecv >> vInv;
    if (vInv.size() > 50000)
      return error("message getdata size() = %d", vInv.size());

    foreach (const CInv &inv, vInv) {
      if (fShutdown)
        return true;
      printf("received getdata for: %s\n", inv.ToString().c_str());

      if (inv.type == MSG_BLOCK) {
        // Send block from disk
        map<uint256, CBlockIndex *>::iterator mi = mapBlockIndex.find(inv.hash);
        if (mi != mapBlockIndex.end()) {
          CBlock block;
          block.ReadFromDisk((*mi).second);
          pfrom->PushMessage("block", block);

          // Trigger them to send a getblocks request for the next batch of
          // inventory
          if (inv.hash == pfrom->hashContinue) {
            // Bypass PushInventory, this must send even if redundant,
            // and we want it right after the last block so they don't
            // wait for other stuff first.
            vector<CInv> vInv;
            vInv.push_back(CInv(MSG_BLOCK, hashBestChain));
            pfrom->PushMessage("inv", vInv);
            pfrom->hashContinue = 0;
          }
        }
      } else if (inv.IsKnownType()) {
        // Send stream from relay memory
        CRITICAL_BLOCK(cs_mapRelay) {
          map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
          if (mi != mapRelay.end())
            pfrom->PushMessage(inv.GetCommand(), (*mi).second);
        }
      }

      // Track requests for our stuff
      CRITICAL_BLOCK(cs_mapRequestCount) {
        map<uint256, int>::iterator mi = mapRequestCount.find(inv.hash);
        if (mi != mapRequestCount.end())
          (*mi).second++;
      }
    }
  }

  else if (strCommand == "getblocks") {
    CBlockLocator locator;
    uint256 hashStop;
    vRecv >> locator >> hashStop;

    // Find the last block the caller has in the main chain
    CBlockIndex *pindex = locator.GetBlockIndex();

    // Send the rest of the chain
    if (pindex)
      pindex = pindex->pnext;
    int nLimit = 500 + locator.GetDistanceBack();
    printf("getblocks %d to %s limit %d\n", (pindex ? pindex->nHeight : -1),
           hashStop.ToString().substr(0, 20).c_str(), nLimit);
    for (; pindex; pindex = pindex->pnext) {
      if (pindex->GetBlockHash() == hashStop) {
        printf("  getblocks stopping at %d %s\n", pindex->nHeight,
               pindex->GetBlockHash().ToString().substr(0, 20).c_str());
        break;
      }
      pfrom->PushInventory(CInv(MSG_BLOCK, pindex->GetBlockHash()));
      if (--nLimit <= 0) {
        // When this block is requested, we'll send an inv that'll make them
        // getblocks the next batch of inventory.
        printf("  getblocks stopping at limit %d %s\n", pindex->nHeight,
               pindex->GetBlockHash().ToString().substr(0, 20).c_str());
        pfrom->hashContinue = pindex->GetBlockHash();
        break;
      }
    }
  }

  else if (strCommand == "getheaders") {
    CBlockLocator locator;
    uint256 hashStop;
    vRecv >> locator >> hashStop;

    CBlockIndex *pindex = NULL;
    if (locator.IsNull()) {
      // If locator is null, return the hashStop block
      map<uint256, CBlockIndex *>::iterator mi = mapBlockIndex.find(hashStop);
      if (mi == mapBlockIndex.end())
        return true;
      pindex = (*mi).second;
    } else {
      // Find the last block the caller has in the main chain
      pindex = locator.GetBlockIndex();
      if (pindex)
        pindex = pindex->pnext;
    }

    vector<CBlock> vHeaders;
    int nLimit = 2000 + locator.GetDistanceBack();
    printf("getheaders %d to %s limit %d\n", (pindex ? pindex->nHeight : -1),
           hashStop.ToString().substr(0, 20).c_str(), nLimit);
    for (; pindex; pindex = pindex->pnext) {
      vHeaders.push_back(pindex->GetBlockHeader());
      if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
        break;
    }
    pfrom->PushMessage("headers", vHeaders);
  }

  else if (strCommand == "tx") {
    vector<uint256> vWorkQueue;
    CDataStream vMsg(vRecv);
    CTransaction tx;
    vRecv >> tx;

    CInv inv(MSG_TX, tx.GetHash());
    pfrom->AddInventoryKnown(inv);

    bool fMissingInputs = false;
    if (tx.AcceptToMemoryPool(true, &fMissingInputs)) {
      AddToWalletIfMine(tx, NULL);
      RelayMessage(inv, vMsg);
      mapAlreadyAskedFor.erase(inv);
      vWorkQueue.push_back(inv.hash);

      // Recursively process any orphan transactions that depended on this one
      for (int i = 0; i < vWorkQueue.size(); i++) {
        uint256 hashPrev = vWorkQueue[i];
        for (multimap<uint256, CDataStream *>::iterator mi =
                 mapOrphanTransactionsByPrev.lower_bound(hashPrev);
             mi != mapOrphanTransactionsByPrev.upper_bound(hashPrev); ++mi) {
          const CDataStream &vMsg = *((*mi).second);
          CTransaction tx;
          CDataStream(vMsg) >> tx;
          CInv inv(MSG_TX, tx.GetHash());

          if (tx.AcceptToMemoryPool(true)) {
            printf("   accepted orphan tx %s\n",
                   inv.hash.ToString().substr(0, 10).c_str());
            AddToWalletIfMine(tx, NULL);
            RelayMessage(inv, vMsg);
            mapAlreadyAskedFor.erase(inv);
            vWorkQueue.push_back(inv.hash);
          }
        }
      }

      foreach (uint256 hash, vWorkQueue)
        EraseOrphanTx(hash);
    } else if (fMissingInputs) {
      printf("storing orphan tx %s\n",
             inv.hash.ToString().substr(0, 10).c_str());
      AddOrphanTx(vMsg);
    }
  }

  else if (strCommand == "block") {
    CBlock block;
    vRecv >> block;

    printf("received block %s\n",
           block.GetHash().ToString().substr(0, 20).c_str());
    // block.print();

    CInv inv(MSG_BLOCK, block.GetHash());
    pfrom->AddInventoryKnown(inv);

    if (ProcessBlock(pfrom, &block))
      mapAlreadyAskedFor.erase(inv);
  }

  else if (strCommand == "getaddr") {
    // Nodes rebroadcast an addr every 24 hours
    pfrom->vAddrToSend.clear();
    int64 nSince = GetAdjustedTime() - 3 * 60 * 60; // in the last 3 hours
    CRITICAL_BLOCK(cs_mapAddresses) {
      unsigned int nCount = 0;
      foreach (const PAIRTYPE(vector<unsigned char>, CAddress) & item,
               mapAddresses) {
        const CAddress &addr = item.second;
        if (addr.nTime > nSince)
          nCount++;
      }
      foreach (const PAIRTYPE(vector<unsigned char>, CAddress) & item,
               mapAddresses) {
        const CAddress &addr = item.second;
        if (addr.nTime > nSince && GetRand(nCount) < 2500)
          pfrom->PushAddress(addr);
      }
    }
  }

  else if (strCommand == "checkorder") {
    uint256 hashReply;
    vRecv >> hashReply;

    if (!GetBoolArg("-allowreceivebyip")) {
      pfrom->PushMessage("reply", hashReply, (int)2, string(""));
      return true;
    }

    CWalletTx order;
    vRecv >> order;

    /// we have a chance to check the order here

    // Keep giving the same key to the same ip until they use it
    if (!mapReuseKey.count(pfrom->addr.ip))
      mapReuseKey[pfrom->addr.ip] = GetKeyFromKeyPool();

    // Send back approval of order and pubkey to use
    CScript scriptPubKey;
    scriptPubKey << mapReuseKey[pfrom->addr.ip] << OP_CHECKSIG;
    pfrom->PushMessage("reply", hashReply, (int)0, scriptPubKey);
  }

  else if (strCommand == "submitorder") {
    uint256 hashReply;
    vRecv >> hashReply;

    if (!GetBoolArg("-allowreceivebyip")) {
      pfrom->PushMessage("reply", hashReply, (int)2);
      return true;
    }

    CWalletTx wtxNew;
    vRecv >> wtxNew;
    wtxNew.fFromMe = false;

    // Broadcast
    if (!wtxNew.AcceptWalletTransaction()) {
      pfrom->PushMessage("reply", hashReply, (int)1);
      return error(
          "submitorder AcceptWalletTransaction() failed, returning error 1");
    }
    wtxNew.fTimeReceivedIsTxTime = true;
    AddToWallet(wtxNew);
    wtxNew.RelayWalletTransaction();
    mapReuseKey.erase(pfrom->addr.ip);

    // Send back confirmation
    pfrom->PushMessage("reply", hashReply, (int)0);
  }

  else if (strCommand == "reply") {
    uint256 hashReply;
    vRecv >> hashReply;

    CRequestTracker tracker;
    CRITICAL_BLOCK(pfrom->cs_mapRequests) {
      map<uint256, CRequestTracker>::iterator mi =
          pfrom->mapRequests.find(hashReply);
      if (mi != pfrom->mapRequests.end()) {
        tracker = (*mi).second;
        pfrom->mapRequests.erase(mi);
      }
    }
    if (!tracker.IsNull())
      tracker.fn(tracker.param1, vRecv);
  }

  else if (strCommand == "ping") {
  }

  else if (strCommand == "alert") {
    CAlert alert;
    vRecv >> alert;

    if (alert.ProcessAlert()) {
      // Relay
      pfrom->setKnown.insert(alert.GetHash());
      CRITICAL_BLOCK(cs_vNodes)
      foreach (CNode *pnode, vNodes)
        alert.RelayTo(pnode);
    }
  }

  else {
    // Ignore unknown commands for extensibility
  }

  // Update the last seen time for this node's address
  if (pfrom->fNetworkNode)
    if (strCommand == "version" || strCommand == "addr" ||
        strCommand == "inv" || strCommand == "getdata" || strCommand == "ping")
      AddressCurrentlyConnected(pfrom->addr);

  return true;
}

bool SendMessages(CNode *pto, bool fSendTrickle) {
  CRITICAL_BLOCK(cs_main) {
    // Don't send anything until we get their version message
    if (pto->nVersion == 0)
      return true;

    // Keep-alive ping
    if (pto->nLastSend && GetTime() - pto->nLastSend > 30 * 60 &&
        pto->vSend.empty())
      pto->PushMessage("ping");

    // Resend wallet transactions that haven't gotten in a block yet
    ResendWalletTransactions();

    // Address refresh broadcast
    static int64 nLastRebroadcast;
    if (GetTime() - nLastRebroadcast > 24 * 60 * 60) {
      nLastRebroadcast = GetTime();
      CRITICAL_BLOCK(cs_vNodes) {
        foreach (CNode *pnode, vNodes) {
          // Periodically clear setAddrKnown to allow refresh broadcasts
          pnode->setAddrKnown.clear();

          // Rebroadcast our address
          if (addrLocalHost.IsRoutable() && !fUseProxy) {
            CAddress addr(addrLocalHost);
            addr.nTime = GetAdjustedTime();
            pnode->PushAddress(addr);
          }
        }
      }
    }

    // Clear out old addresses periodically so it's not too much work at once
    static int64 nLastClear;
    if (nLastClear == 0)
      nLastClear = GetTime();
    if (GetTime() - nLastClear > 10 * 60 && vNodes.size() >= 3) {
      nLastClear = GetTime();
      CRITICAL_BLOCK(cs_mapAddresses) {
        CAddrDB addrdb;
        int64 nSince = GetAdjustedTime() - 14 * 24 * 60 * 60;
        for (map<vector<unsigned char>, CAddress>::iterator mi =
                 mapAddresses.begin();
             mi != mapAddresses.end();) {
          const CAddress &addr = (*mi).second;
          if (addr.nTime < nSince) {
            if (mapAddresses.size() < 1000 || GetTime() > nLastClear + 20)
              break;
            addrdb.EraseAddress(addr);
            mapAddresses.erase(mi++);
          } else
            mi++;
        }
      }
    }

    //
    // Message: addr
    //
    if (fSendTrickle) {
      vector<CAddress> vAddr;
      vAddr.reserve(pto->vAddrToSend.size());
      foreach (const CAddress &addr, pto->vAddrToSend) {
        // returns true if wasn't already contained in the set
        if (pto->setAddrKnown.insert(addr).second) {
          vAddr.push_back(addr);
          // receiver rejects addr messages larger than 1000
          if (vAddr.size() >= 1000) {
            pto->PushMessage("addr", vAddr);
            vAddr.clear();
          }
        }
      }
      pto->vAddrToSend.clear();
      if (!vAddr.empty())
        pto->PushMessage("addr", vAddr);
    }

    //
    // Message: inventory
    //
    vector<CInv> vInv;
    vector<CInv> vInvWait;
    CRITICAL_BLOCK(pto->cs_inventory) {
      vInv.reserve(pto->vInventoryToSend.size());
      vInvWait.reserve(pto->vInventoryToSend.size());
      foreach (const CInv &inv, pto->vInventoryToSend) {
        if (pto->setInventoryKnown.count(inv))
          continue;

        // trickle out tx inv to protect privacy
        if (inv.type == MSG_TX && !fSendTrickle) {
          // 1/4 of tx invs blast to all immediately
          static uint256 hashSalt;
          if (hashSalt == 0)
            RAND_bytes((unsigned char *)&hashSalt, sizeof(hashSalt));
          uint256 hashRand = inv.hash ^ hashSalt;
          hashRand = Hash(BEGIN(hashRand), END(hashRand));
          bool fTrickleWait = ((hashRand & 3) != 0);

          // always trickle our own transactions
          if (!fTrickleWait) {
            TRY_CRITICAL_BLOCK(cs_mapWallet) {
              map<uint256, CWalletTx>::iterator mi = mapWallet.find(inv.hash);
              if (mi != mapWallet.end()) {
                CWalletTx &wtx = (*mi).second;
                if (wtx.fFromMe)
                  fTrickleWait = true;
              }
            }
          }

          if (fTrickleWait) {
            vInvWait.push_back(inv);
            continue;
          }
        }

        // returns true if wasn't already contained in the set
        if (pto->setInventoryKnown.insert(inv).second) {
          vInv.push_back(inv);
          if (vInv.size() >= 1000) {
            pto->PushMessage("inv", vInv);
            vInv.clear();
          }
        }
      }
      pto->vInventoryToSend = vInvWait;
    }
    if (!vInv.empty())
      pto->PushMessage("inv", vInv);

    //
    // Message: getdata
    //
    vector<CInv> vGetData;
    int64 nNow = GetTime() * 1000000;
    CTxDB txdb("r");
    while (!pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow) {
      const CInv &inv = (*pto->mapAskFor.begin()).second;
      if (!AlreadyHave(txdb, inv)) {
        printf("sending getdata: %s\n", inv.ToString().c_str());
        vGetData.push_back(inv);
        if (vGetData.size() >= 1000) {
          pto->PushMessage("getdata", vGetData);
          vGetData.clear();
        }
      }
      pto->mapAskFor.erase(pto->mapAskFor.begin());
    }
    if (!vGetData.empty())
      pto->PushMessage("getdata", vGetData);
  }
  return true;
}

//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

void GenerateBitcoins(bool fGenerate) {
  if (fGenerateBitcoins != fGenerate) {
    fGenerateBitcoins = fGenerate;
    CWalletDB().WriteSetting("fGenerateBitcoins", fGenerateBitcoins);
    MainFrameRepaint();
  }
  if (fGenerateBitcoins) {
    int nProcessors = boost::thread::hardware_concurrency();
    printf("%d processors\n", nProcessors);
    if (nProcessors < 1)
      nProcessors = 1;
    if (fLimitProcessors && nProcessors > nLimitProcessors)
      nProcessors = nLimitProcessors;
    int nAddThreads = nProcessors - vnThreadsRunning[3];
    printf("Starting %d BitcoinMiner threads\n", nAddThreads);
    for (int i = 0; i < nAddThreads; i++) {
      if (!CreateThread(ThreadBitcoinMiner, NULL))
        printf("Error: CreateThread(ThreadBitcoinMiner) failed\n");
      Sleep(10);
    }
  }
}

// 挖矿线程入口函数
// 参数 parg: 线程参数（未使用）
// 功能: 启动比特币挖矿线程，增加运行中的挖矿线程计数，调用主挖矿函数，
//       最后减少线程计数。
void ThreadBitcoinMiner(void *parg) {
  try {
    vnThreadsRunning[3]++; // 增加运行中的挖矿线程计数
    BitcoinMiner();        // 调用主挖矿函数
    vnThreadsRunning[3]--; // 减少线程计数
  } catch (std::exception &e) {
    vnThreadsRunning[3]--;
    PrintException(&e, "ThreadBitcoinMiner()"); // 打印异常信息
  } catch (...) {
    vnThreadsRunning[3]--;
    PrintException(NULL, "ThreadBitcoinMiner()");
  }

  // 更新UI状态和哈希速率统计
  UIThreadCall(boost::bind(CalledSetStatusBar, "", 0));
  nHPSTimerStart = 0;
  if (vnThreadsRunning[3] == 0)
    dHashesPerSec = 0; // 无挖矿线程时清除哈希速率

  printf("ThreadBitcoinMiner exiting, %d threads remaining\n",
         vnThreadsRunning[3]);
}

#if defined(__GNUC__) && defined(CRYPTOPP_X86_ASM_AVAILABLE)
void CallCPUID(int in, int &aret, int &cret) {
  int a, c;
  asm("mov %2, %%eax; " // in into eax
      "cpuid;"
      "mov %%eax, %0;"   // eax into a
      "mov %%ecx, %1;"   // ecx into c
      : "=r"(a), "=r"(c) /* output */
      : "r"(in)          /* input */
      : "%eax", "%ecx"   /* clobbered register */
  );
  aret = a;
  cret = c;
}

bool Detect128BitSSE2() {
  int a, c, nBrand;
  CallCPUID(0, a, nBrand);
  bool fIntel = (nBrand == 0x6c65746e); // ntel
  bool fAMD = (nBrand == 0x444d4163);   // cAMD

  struct {
    unsigned int nStepping : 4;
    unsigned int nModel : 4;
    unsigned int nFamily : 4;
    unsigned int nProcessorType : 2;
    unsigned int nUnused : 2;
    unsigned int nExtendedModel : 4;
    unsigned int nExtendedFamily : 8;
  } cpu;
  CallCPUID(1, a, c);
  memcpy(&cpu, &a, sizeof(cpu));
  int nFamily = cpu.nExtendedFamily + cpu.nFamily;
  int nModel = cpu.nExtendedModel * 16 + cpu.nModel;

  // We need Intel Nehalem or AMD K10 or better for 128bit SSE2
  // Nehalem = i3/i5/i7 and some Xeon
  // K10 = Opterons with 4 or more cores, Phenom, Phenom II, Athlon II
  //  Intel Core i5  family 6, model 26 or 30
  //  Intel Core i7  family 6, model 26 or 30
  //  Intel Core i3  family 6, model 37
  //  AMD Phenom    family 16, model 10
  bool fUseSSE2 = ((fIntel && nFamily * 10000 + nModel >= 60026) ||
                   (fAMD && nFamily * 10000 + nModel >= 160010));

  // AMD reports a lower model number in 64-bit mode
  if (fAMD && sizeof(void *) > 4 && nFamily * 10000 + nModel >= 160000)
    fUseSSE2 = true;

  static bool fPrinted;
  if (!fPrinted) {
    fPrinted = true;
    printf("CPUID %08x family %d, model %d, stepping %d, fUseSSE2=%d\n", nBrand,
           nFamily, nModel, cpu.nStepping, fUseSSE2);
  }
  return fUseSSE2;
}
#else
bool Detect128BitSSE2() { return false; }
#endif

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

static const unsigned int pSHA256InitState[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

inline void SHA256Transform(void *pstate, void *pinput, const void *pinit) {
  memcpy(pstate, pinit, 32);
  CryptoPP::SHA256::Transform((CryptoPP::word32 *)pstate,
                              (CryptoPP::word32 *)pinput);
}

//
// ScanHash scans nonces looking for a hash with at least some zero bits.
// It operates on big endian data.  Caller does the byte reversing.
// All input buffers are 16-byte aligned.  nNonce is usually preserved
// between calls, but periodically or if nNonce is 0xffff0000 or above,
// the block is rebuilt and nNonce starts over at zero.
//
// ScanHash 会扫描非加密码，寻找至少包含一些零位的哈希值。
// 它处理的是大端序数据。调用者需要进行字节反转操作。
// 所有输入缓冲区均为 16 字节对齐。nNonce 通常会在调用之间保持不变，
// 但有时会周期性地更新，或者当 nNonce 为 0xffff0000 或更高时，
// 将会重新构建区块并从零开始重新计数 nNonce。

// 哈希扫描函数（Crypto++版本）
// 参数说明：
//   pmidstate: SHA256中间状态缓冲区，包含预计算的哈希状态，用于加速计算
//   pdata: 区块数据缓冲区，包含区块头信息（版本、父块哈希、Merkle根、时间戳、难度、nonce）
//   phash1: 第一次SHA256变换的结果缓冲区
//   phash: 最终的双SHA256哈希结果缓冲区
//   nHashesDone: 输出参数，记录本次扫描完成的哈希尝试次数
// 返回值：找到的有效nonce值，或-1表示未找到满足条件的nonce
unsigned int ScanHash_CryptoPP(char *pmidstate, char *pdata, char *phash1,
                               char *phash, unsigned int &nHashesDone) {
  // 获取区块数据缓冲区中nonce字段的引用（偏移量12字节处）
  // 这是区块头中的nonce字段，初始值为0，每次循环递增
  unsigned int &nNonce = *(unsigned int *)(pdata + 12);
  
  // 无限循环：持续尝试不同的nonce值，直到找到满足条件的nonce或达到退出条件
  for (;;) {
    // Crypto++ SHA-256
    // Hash pdata using pmidstate as the starting state into
    // preformatted buffer phash1, then hash phash1 into phash
    
    // 步骤1：递增nonce值（工作量证明的核心机制）
    // 每次循环尝试一个不同的nonce值，从0开始递增
    nNonce++;
    
    // 步骤2：第一次SHA256变换
    // 使用pmidstate作为中间状态，对区块数据进行第一次哈希计算
    // pmidstate包含预计算的SHA256状态，可避免重复计算区块头的不变部分
    SHA256Transform(phash1, pdata, pmidstate);
    
    // 步骤3：第二次SHA256变换
    // 对第一次哈希结果进行第二次SHA256计算，实现比特币的双SHA256哈希
    // phash1作为输入，pSHA256InitState作为初始状态
    SHA256Transform(phash, phash1, pSHA256InitState);

    // Return the nonce if the hash has at least some zero bits,
    // caller will check if it has enough to reach the target
    
    // 步骤4：快速预筛选检查
    // 检查哈希结果的最后16位（索引14处的16位字）是否为零
    // 这是一个快速筛选机制：如果连最后16位都不是零，则肯定不满足难度要求
    // 只有通过这个快速检查的nonce才需要进一步验证是否满足目标难度
    if (((unsigned short *)phash)[14] == 0)
      return nNonce;

    // If nothing found after trying for a while, return -1
    
    // 步骤5：循环退出条件检查
    // 每当nonce的低16位全部为1（即nonce & 0xffff == 0）时，表示已完成一轮完整扫描
    // 此时记录扫描的哈希次数并返回-1，让调用者决定是否重建区块或继续搜索
    // 这种设计避免无限循环，确保系统在适当时候能够调整搜索策略
    if ((nNonce & 0xffff) == 0) {
      nHashesDone = 0xffff + 1; // 记录本轮完成的哈希尝试次数（65536次）
      return -1; // 返回-1表示需要重建区块或调整搜索参数
    }
  }
}

extern unsigned int ScanHash_4WaySSE2(char *pmidstate, char *pblock,
                                      char *phash1, char *phash,
                                      unsigned int &nHashesDone);

class COrphan {
public:
  CTransaction *ptx;
  set<uint256> setDependsOn;
  double dPriority;

  COrphan(CTransaction *ptxIn) {
    ptx = ptxIn;
    dPriority = 0;
  }

  void print() const {
    printf("COrphan(hash=%s, dPriority=%.1f)\n",
           ptx->GetHash().ToString().substr(0, 10).c_str(), dPriority);
    foreach (uint256 hash, setDependsOn)
      printf("   setDependsOn %s\n", hash.ToString().substr(0, 10).c_str());
  }
};

// 创建新的待挖矿区块
// 流程：创建创币交易 → 收集内存池交易 → 计算手续费 → 设置区块奖励
// 创建新区块的核心方法
// 该方法负责构建一个完整的、符合网络标准的比特币区块
// 是比特币挖矿过程中最重要的环节之一，实现了从内存池交易到新区块的转换
// 设计目的：在保证区块安全性和完整性的前提下，最大化矿工收益并维护网络效率
CBlock *CreateNewBlock(CReserveKey &reservekey) {
  // 获取当前区块链的最新区块索引
  // pindexBest 是全局变量，指向当前最长链的最后一个区块
  // 这是新区块链接的基础，确保新区块在正确的链上延伸
  CBlockIndex *pindexPrev = pindexBest;

  // 创建新区块对象并使用智能指针管理生命周期
  // auto_ptr 是 C++ 标准库中的智能指针，用于自动管理对象的生命周期
  // 当 auto_ptr 超出作用域时，会自动调用 delete 释放内存
  // 这种设计避免了手动内存管理可能导致的内存泄漏
  auto_ptr<CBlock> pblock(new CBlock());

  // 检查内存分配是否成功
  // new 运算符可能在系统内存不足时返回 NULL
  // 这种检查对于防止空指针解引用至关重要
  if (!pblock.get())
    return NULL;

  // ========================================
  // 第一步：创建创币交易（Coinbase Transaction）
  // ========================================
  // 创币交易是比特币区块中唯一的特殊交易，具有以下特点：
  // 1. 没有输入（prevout.SetNull()）
  // 2. 生成新比特币作为挖矿奖励
  // 3. 包含矿工指定的输出地址

  CTransaction txNew;
  txNew.vin.resize(1);            // 创币交易只有一个输入位置
  txNew.vin[0].prevout.SetNull(); // 创币交易没有输入引用（特殊标记）
  txNew.vout.resize(1);           // 通常只有一个输出，但理论上可以有多个
  // 输出锁定脚本：将新生成的比特币锁定到指定地址
  // reservekey.GetReservedKey() 获取新生成的地址公钥
  // OP_CHECKSIG 确保只有拥有对应私钥的人才能花费这些比特币
  txNew.vout[0].scriptPubKey << reservekey.GetReservedKey() << OP_CHECKSIG;

  // 将创币交易添加到区块交易列表的第一个位置
  // 根据比特币协议，创币交易必须是区块的第一笔交易
  pblock->vtx.push_back(txNew);

  // ========================================
  // 第二步：从内存池收集交易到区块
  // ========================================
  // 这个阶段是区块构建的核心，需要：
  // 1. 从内存池中选择合适的交易
  // 2. 按优先级排序交易
  // 3. 验证交易的合法性
  // 4. 确保区块不超出大小和复杂度限制

  int64 nFees = 0; // 累计所有有效交易的交易手续费

  // 使用临界区保护并发访问
  // cs_main 保护区块链状态，cs_mapTransactions 保护内存池交易
  // 在高并发环境中这是必要的，防止数据竞争和不一致状态
  CRITICAL_BLOCK(cs_main)
  CRITICAL_BLOCK(cs_mapTransactions) {
    // 打开交易数据库用于读取历史交易
    // "r" 参数表示只读模式，这可以提高性能并避免写入冲突
    CTxDB txdb("r");

    // 初始化交易处理所需的数据结构

    // vOrphan: 存储依赖未确认交易的孤儿交易
    // 当一个交易的输入引用了尚未确认的交易时，该交易就成为孤儿交易
    list<COrphan> vOrphan;

    // mapDependers: 维护交易依赖关系图
    // key: 被依赖的交易哈希，value: 依赖于该交易的孤儿交易列表
    map<uint256, vector<COrphan *>> mapDependers;

    // mapPriority: 优先级队列，存储已验证交易的优先级信息
    // multimap 允许相同优先级的多个交易存在
    // 负的优先级值实现最大堆（优先级高的在前）
    multimap<double, CTransaction *> mapPriority;

    // ========================================
    // 阶段 2.1: 遍历内存池交易并计算优先级
    // ========================================

    // 遍历内存池中的所有交易
    // mapTransactions 是全局内存池，包含所有待确认的交易
    for (map<uint256, CTransaction>::iterator mi = mapTransactions.begin();
         mi != mapTransactions.end(); ++mi) {
      CTransaction &tx = (*mi).second;

      // 跳过无效交易
      // IsCoinBase(): 跳过已有的创币交易（内存池中不应该有）
      // !IsFinal(): 跳过尚未满足时间锁要求的交易
      if (tx.IsCoinBase() || !tx.IsFinal())
        continue;

      // ========================================
      // 处理交易依赖关系和计算优先级
      // ========================================

      COrphan *porphan = NULL; // 当前交易的孤儿状态（如果适用）
      double dPriority = 0;    // 交易的累计优先级（币龄 × 金额）

      // 遍历交易的每个输入，计算优先级
      foreach (const CTxIn &txin, tx.vin) {
        // 尝试从磁盘读取被引用的前序交易
        CTransaction txPrev; // 前序交易
        CTxIndex txindex;    // 前序交易在磁盘中的位置信息

        // ReadFromDisk(): 从区块链数据库中读取历史交易
        // txin.prevout 包含前序交易的哈希和输出索引
        if (!txPrev.ReadFromDisk(txdb, txin.prevout, txindex)) {
          // 前序交易未找到或未确认，这使得当前交易成为孤儿交易

          // 创建孤儿交易条目
          if (!porphan) {
            vOrphan.push_back(COrphan(&tx));
            porphan = &vOrphan.back(); // 获取刚添加的孤儿交易指针
          }

          // 维护依赖关系：被依赖的交易 -> 依赖于它的交易列表
          mapDependers[txin.prevout.hash].push_back(porphan);
          porphan->setDependsOn.insert(txin.prevout.hash);

          continue; // 跳过后续计算，等待依赖交易确认
        }

        // 获取前序交易输出中的比特币金额
        int64 nValueIn = txPrev.vout[txin.prevout.n].nValue;

        // ========================================
        // 计算交易确认数（币龄的重要组成）
        // ========================================

        int nConf = 0; // 确认数，表示前序交易在多少个区块之前确认

        // 读取包含前序交易的区块
        CBlock block;
        if (block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos,
                               false)) {
          // 在区块链索引中查找该区块
          map<uint256, CBlockIndex *>::iterator it =
              mapBlockIndex.find(block.GetHash());
          if (it != mapBlockIndex.end()) {
            CBlockIndex *pindex = (*it).second;
            // 检查该区块是否在主链上
            if (pindex->IsInMainChain())
              // 计算确认数：当前链高度 - 交易确认区块高度 + 1
              // +1 是因为确认从1开始计算
              nConf = 1 + nBestHeight - pindex->nHeight;
          }
        }

        // ========================================
        // 优先级计算：币龄 × 金额
        // ========================================
        // 币龄 = 确认数 × 比特币数量
        // 确认时间越长、金额越大的输入，优先级越高
        dPriority += (double)nValueIn * nConf;

        // 调试输出：显示优先级计算过程
        if (fDebug && GetBoolArg("-printpriority"))
          printf(
              "priority     nValueIn=%-12I64d nConf=%-5d dPriority=%-20.1f\n",
              nValueIn, nConf, dPriority);
      }

      // ========================================
      // 优先级归一化：除以交易大小
      // ========================================
      // 优先级公式：币龄 × 金额 / 交易大小
      // 这样既考虑了币龄和金额，也考虑了交易占用的网络资源
      dPriority /= ::GetSerializeSize(tx, SER_NETWORK);

      // 将交易加入相应的队列
      if (porphan)
        // 孤儿交易：存储优先级以便后续处理
        porphan->dPriority = dPriority;
      else
        // 已验证交易：直接加入优先级队列
        // 使用负值实现最大堆（multimap默认升序排列）
        mapPriority.insert(make_pair(-dPriority, &(*mi).second));

      // 调试输出：显示交易优先级信息
      if (fDebug && GetBoolArg("-printpriority")) {
        printf("priority %-20.1f %s\n%s", dPriority,
               tx.GetHash().ToString().substr(0, 10).c_str(),
               tx.ToString().c_str());
        if (porphan)
          porphan->print();
        printf("\n");
      }
    }

    // ========================================
    // 阶段 2.2: 按优先级选择交易构建区块
    // ========================================

    // mapTestPool: 临时UTXO池，存储已验证交易的输入状态
    // 用于防止双重支付和确保UTXO状态一致性
    map<uint256, CTxIndex> mapTestPool;

    // 区块资源限制变量
    uint64 nBlockSize = 1000; // 当前区块大小（初始包含创币交易和基本结构）
    int nBlockSigOps = 100;   // 当前区块签名操作数量（基础开销）

    // ========================================
    // 主选择循环：按优先级从高到低处理交易
    // ========================================
    while (!mapPriority.empty()) {
      // 取出最高优先级交易
      double dPriority = -(*mapPriority.begin()).first;
      CTransaction &tx = *(*mapPriority.begin()).second;
      mapPriority.erase(mapPriority.begin());

      // ========================================
      // 区块大小限制检查
      // ========================================

      // 计算交易的序列化大小
      unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK);

      // 检查是否超出区块大小限制（1MB）
      // 这里是硬限制，不能违反
      if (nBlockSize + nTxSize >= MAX_BLOCK_SIZE_GEN)
        continue; // 跳过该交易，继续处理下一个

      // 计算交易的签名操作数量
      int nTxSigOps = tx.GetSigOpCount();

      // 检查是否超出签名操作限制
      // 限制签名操作数量可以防止恶意构造的复杂交易
      if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
        continue; // 跳过该交易

      // ========================================
      // 交易手续费计算和验证
      // ========================================

      // 确定是否允许免费交易
      // 条件：小交易（<4000字节）或高优先级交易可以免费
      bool fAllowFree =
          (nBlockSize + nTxSize < 4000 || dPriority > COIN * 144 / 250);

      // 计算最小所需手续费
      // 手续费计算考虑了当前区块的拥挤程度
      int64 nMinFee = tx.GetMinFee(nBlockSize, fAllowFree);

      // ========================================
      // 交易验证：UTXO连接和双重支付检查
      // ========================================

      // 创建临时UTXO池用于验证
      map<uint256, CTxIndex> mapTestPoolTmp(mapTestPool);

      // ConnectInputs(): 验证交易的输入引用
      // - 检查引用的UTXO是否存在且未被花费
      // - 验证交易签名的有效性
      // - 计算实际的手续费
      // - 更新临时UTXO池状态
      if (!tx.ConnectInputs(txdb, mapTestPoolTmp, CDiskTxPos(1, 1, 1),
                            pindexPrev, nFees, false, true, nMinFee))
        continue; // 验证失败，跳过此交易

      // 验证成功，更新UTXO池状态
      swap(mapTestPool, mapTestPoolTmp);

      // ========================================
      // 交易通过所有检查，添加到区块
      // ========================================

      pblock->vtx.push_back(tx); // 添加到区块交易列表
      nBlockSize += nTxSize;     // 更新区块大小统计
      nBlockSigOps += nTxSigOps; // 更新签名操作统计

      // ========================================
      // 处理依赖此交易的孤儿交易
      // ========================================

      uint256 hash = tx.GetHash(); // 获取交易哈希

      // 检查是否有交易依赖于刚处理的交易
      if (mapDependers.count(hash)) {
        // 遍历所有依赖于当前交易的孤儿交易
        foreach (COrphan *porphan, mapDependers[hash]) {
          if (!porphan->setDependsOn.empty()) {
            // 移除当前依赖
            porphan->setDependsOn.erase(hash);

            // 如果所有依赖都已满足，将孤儿交易加入优先级队列
            if (porphan->setDependsOn.empty())
              mapPriority.insert(make_pair(-porphan->dPriority, porphan->ptx));
          }
        }
      }
    }
  } // 临界区结束

  // ========================================
  // 第三步：设置创币交易输出金额
  // ========================================
  // 创币交易奖励 = 基础出块奖励 + 所有交易的手续费总和
  // GetBlockValue() 根据区块高度计算基础奖励（每4年减半）
  // 交易手续费激励矿工包含更多交易
  pblock->vtx[0].vout[0].nValue = GetBlockValue(pindexPrev->nHeight + 1, nFees);

  // ========================================
  // 第四步：填充区块头信息
  // ========================================

  // 设置前一区块哈希，形成区块链链接
  // 确保新区块在当前最长链上延伸
  pblock->hashPrevBlock = pindexPrev->GetBlockHash();

  // 构建并设置梅克尔树根哈希
  // 这是所有交易完整性的关键验证点
  pblock->hashMerkleRoot = pblock->BuildMerkleTree();

  // 设置区块时间戳
  // 使用中位数时间避免时间操纵，确保时间戳的合理性
  // pindexPrev->GetMedianTimePast(): 前11个区块的中位数时间
  // GetAdjustedTime(): 网络校正后的本地时间
  pblock->nTime = max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());

  // 设置工作量证明难度目标
  // GetNextWorkRequired(): 根据前一个区块的时间间隔自动调整难度
  // 维持平均10分钟的出块时间
  pblock->nBits = GetNextWorkRequired(pindexPrev);

  // 初始化随机数为0，挖矿过程会逐步增加
  pblock->nNonce = 0;

  // 释放智能指针管理的内存，返回裸指针
  // 调用者负责释放返回的区块对象
  return pblock.release();
}

// 增加额外非ce值
// 该函数用于在挖矿过程中增加额外的非ce值，以增加区块的工作量证明难度
//- CBlock *pblock : 指向当前正在挖掘的区块的指针
// - CBlockIndex *pindexPrev : 指向前一个区块的索引，用于获取时间信息
// - unsigned int &nExtraNonce : 对额外nonce值的引用，用于在函数调用之间保持状态
// - int64 &nPrevTime : 对前一次时间的引用，用于追踪时间变化
void IncrementExtraNonce(CBlock *pblock, CBlockIndex *pindexPrev,
                         unsigned int &nExtraNonce, int64 &nPrevTime) {
  // Update nExtraNonce
  int64 nNow = max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());
  if (++nExtraNonce >= 0x7f && nNow > nPrevTime + 1) {
    nExtraNonce = 1;
    nPrevTime = nNow;
  }
  pblock->vtx[0].vin[0].scriptSig = CScript()
                                    << pblock->nBits << CBigNum(nExtraNonce);
  pblock->hashMerkleRoot = pblock->BuildMerkleTree();
}

void FormatHashBuffers(CBlock *pblock, char *pmidstate, char *pdata,
                       char *phash1) {
  //
  // Prebuild hash buffers
  //
  struct {
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
  memset(&tmp, 0, sizeof(tmp));

  tmp.block.nVersion = pblock->nVersion;
  tmp.block.hashPrevBlock = pblock->hashPrevBlock;
  tmp.block.hashMerkleRoot = pblock->hashMerkleRoot;
  tmp.block.nTime = pblock->nTime;
  tmp.block.nBits = pblock->nBits;
  tmp.block.nNonce = pblock->nNonce;

  FormatHashBlocks(&tmp.block, sizeof(tmp.block));
  FormatHashBlocks(&tmp.hash1, sizeof(tmp.hash1));

  // Byte swap all the input buffer
  for (int i = 0; i < sizeof(tmp) / 4; i++)
    ((unsigned int *)&tmp)[i] = ByteReverse(((unsigned int *)&tmp)[i]);

  // Precalc the first half of the first hash, which stays constant
  SHA256Transform(pmidstate, &tmp.block, pSHA256InitState);

  memcpy(pdata, &tmp.block, 128);
  memcpy(phash1, &tmp.hash1, 64);
}

// 验证工作量证明并提交区块
// 流程：双重验证 → 保留密钥 → 广播区块
bool CheckWork(CBlock *pblock, CReserveKey &reservekey) {
  uint256 hash = pblock->GetHash(); // 获取区块哈希
  uint256 hashTarget =
      CBigNum().SetCompact(pblock->nBits).getuint256(); // 难度目标

  // 再次验证工作量证明
  if (hash > hashTarget)
    return false;

  // 打印成功信息
  printf("BitcoinMiner:\n");
  printf("proof-of-work found  \n  hash: %s  \ntarget: %s\n",
         hash.GetHex().c_str(), hashTarget.GetHex().c_str());
  pblock->print();
  printf("%s ", DateTimeStrFormat("%x %H:%M", GetTime()).c_str());
  printf("generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue).c_str());

  // 关键验证：确保父区块还是最佳链
  CRITICAL_BLOCK(cs_main) {
    if (pblock->hashPrevBlock != hashBestChain)
      return error("BitcoinMiner : generated block is stale");

    // 销毁预留密钥（创币交易输出已生效）
    reservekey.KeepKey();

    // 统计区块请求次数
    CRITICAL_BLOCK(cs_mapRequestCount)
    mapRequestCount[pblock->GetHash()] = 0;

    // 像接收其他节点区块一样处理此区块
    if (!ProcessBlock(NULL, pblock))
      return error("BitcoinMiner : ProcessBlock, block not accepted");
  }

  Sleep(2000); // 等待2秒再继续挖矿
  return true;
}

// 主挖矿函数
// 流程：创建区块 → 准备哈希缓冲区 → 循环扫描随机数 → 验证并提交
void BitcoinMiner() {
  printf("BitcoinMiner started\n");          // good luck!
  SetThreadPriority(THREAD_PRIORITY_LOWEST); // 设置低优先级，避免影响其他操作

  // 检测CPU是否支持128位SSE2（用于加速SHA256计算）
  bool f4WaySSE2 = Detect128BitSSE2();
  if (mapArgs.count("-4way"))
    f4WaySSE2 = GetBoolArg(mapArgs["-4way"]);

  // 每个挖矿线程有独立的密钥和额外随机数
  CReserveKey reservekey;       // 预留密钥（用于创币交易）
  unsigned int nExtraNonce = 0; // 额外随机数（扩展搜索空间）
  int64 nPrevTime = 0;          // 上次时间（用于检测时间变化）

  // 主循环：持续挖矿直到被停止
  // 每次循环都创建一个新的区块，然后挖矿
  /**
  - fGenerateBitcoins ：用户手动停止挖矿
- fShutdown ：系统关闭信号
- vNodes.empty() ：网络断开
- IsInitialBlockDownload() ：区块链同步中
   */

  while (fGenerateBitcoins) {
    // 线程检查？没看懂是做什么的
    if (AffinityBugWorkaround(ThreadBitcoinMiner))
      return;
    // 关闭信号检查
    if (fShutdown)
      return;

    // 等待网络连接同步完成，必须完成同步才能挖矿
    while (vNodes.empty() || IsInitialBlockDownload()) {
      Sleep(1000);
      if (fShutdown)
        return;
      if (!fGenerateBitcoins)
        return;
    }

    //
    // 第一步：创建新区块，基础信息（版本、父块哈希、时间戳、难度目标）
    //
    unsigned int nTransactionsUpdatedLast = nTransactionsUpdated;
    CBlockIndex *pindexPrev = pindexBest; // 获取最新区块

    // 创建包含交易的新区块，此时nonce还为0
    // 每次创建新区块时，都需要更新额外随机数，并不是等确认好了基础信息再更新Nonce，这里是之前很大的误解
    // 你看CreateNewBlock这个函数的调用时写在while循环中的，而不是while循环之外
    auto_ptr<CBlock> pblock(CreateNewBlock(reservekey));
    if (!pblock.get())
      return;

    // 更新额外随机数
    IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce, nPrevTime);

    printf("Running BitcoinMiner with %d transactions in block\n",
           pblock->vtx.size());

    //
    // 第二步：准备哈希计算缓冲区
    //
    char pmidstatebuf[32 + 16];
    char *pmidstate = alignup<16>(pmidstatebuf); // 中间状态缓冲区
    char pdatabuf[128 + 16];
    char *pdata = alignup<16>(pdatabuf); // 数据缓冲区
    char phash1buf[64 + 16];
    char *phash1 = alignup<16>(phash1buf); // 哈希结果缓冲区

    // 格式化哈希缓冲区
    FormatHashBuffers(pblock.get(), pmidstate, pdata, phash1);

    // 获取区块时间戳和随机数字段的引用（用于快速更新）
    unsigned int &nBlockTime = *(unsigned int *)(pdata + 64 + 4);
    unsigned int &nBlockNonce = *(unsigned int *)(pdata + 64 + 12);

    //
    // 第三步：扫描随机数（工作量证明计算）
    //
    int64 nStart = GetTime(); // 记录开始时间
    uint256 hashTarget =
        CBigNum()
            .SetCompact(pblock->nBits)
            .getuint256(); // 难度目标，nBits是难度目标的紧凑表示,这里转化为256位整数Target
    uint256 hashbuf[2];
    uint256 &hash = *alignup<16>(hashbuf); // 哈希结果

    loop {
      unsigned int nHashesDone = 0; // 本轮完成的哈希数量
      unsigned int nNonceFound;     // 找到的随机数

#ifdef FOURWAYSSE2
      if (f4WaySSE2)
        // 使用4-way SSE2加速（如果可用）
        nNonceFound = ScanHash_4WaySSE2(pmidstate, pdata + 64, phash1,
                                        (char *)&hash, nHashesDone);
      else
#endif
        // 使用Crypto++库进行SHA256计算
        nNonceFound = ScanHash_CryptoPP(pmidstate, pdata + 64, phash1,
                                        (char *)&hash, nHashesDone);

      // 检查是否找到有效随机数
      if (nNonceFound != -1) {
        // 字节序转换（比特币使用大端序）
        for (int i = 0; i < sizeof(hash) / 4; i++)
          ((unsigned int *)&hash)[i] = ByteReverse(((unsigned int *)&hash)[i]);

        // 核心验证：哈希值必须小于等于目标值（满足难度目标）
        if (hash <= hashTarget) {
          // 找到有效工作量证明！
          pblock->nNonce = ByteReverse(nNonceFound);
          assert(hash == pblock->GetHash());

          SetThreadPriority(THREAD_PRIORITY_NORMAL); // 提高优先级处理
          CheckWork(pblock.get(), reservekey);       // 验证并提交区块
          SetThreadPriority(THREAD_PRIORITY_LOWEST); // 恢复低优先级
          break;
        }
      }

      // 后面就是一些收尾的工作了
      // 统计哈希速率（每4秒更新一次UI）
      static int64 nHashCounter;
      if (nHPSTimerStart == 0) {
        nHPSTimerStart = GetTimeMillis();
        nHashCounter = 0;
      } else
        nHashCounter += nHashesDone;

      if (GetTimeMillis() - nHPSTimerStart > 4000) {
        static CCriticalSection cs;
        CRITICAL_BLOCK(cs) {
          if (GetTimeMillis() - nHPSTimerStart > 4000) {
            dHashesPerSec =
                1000.0 * nHashCounter / (GetTimeMillis() - nHPSTimerStart);
            nHPSTimerStart = GetTimeMillis();
            nHashCounter = 0;
            string strStatus =
                strprintf("    %.0f khash/s", dHashesPerSec / 1000.0);
            UIThreadCall(boost::bind(CalledSetStatusBar, strStatus, 0));
            // 每30分钟打印一次日志
            static int64 nLogTime;
            if (GetTime() - nLogTime > 30 * 60) {
              nLogTime = GetTime();
              printf("%s ", DateTimeStrFormat("%x %H:%M", GetTime()).c_str());
              printf("hashmeter %3d CPUs %6.0f khash/s\n", vnThreadsRunning[3],
                     dHashesPerSec / 1000.0);
            }
          }
        }
      }

      // 检查是否需要退出或重建区块
      if (fShutdown)
        return;
      if (!fGenerateBitcoins)
        return;
      if (fLimitProcessors && vnThreadsRunning[3] > nLimitProcessors)
        return;
      if (vNodes.empty())
        break; // 断开网络，停止挖矿
      if (nBlockNonce >= 0xffff0000)
        break; // 随机数溢出，需要更新时间戳
      if (nTransactionsUpdated != nTransactionsUpdatedLast &&
          GetTime() - nStart > 60)
        break; // 交易池变化超过60秒，重建区块
      if (pindexPrev != pindexBest)
        break; // 区块链分叉，重建区块

      // 每几秒更新一次时间戳（影响区块头）
      pblock->nTime =
          max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());
      nBlockTime = ByteReverse(pblock->nTime);
    }
  }
}

//////////////////////////////////////////////////////////////////////////////
//
// Actions
//

int64 GetBalance() {
  int64 nStart = GetTimeMillis();

  int64 nTotal = 0;
  CRITICAL_BLOCK(cs_mapWallet) {
    for (map<uint256, CWalletTx>::iterator it = mapWallet.begin();
         it != mapWallet.end(); ++it) {
      CWalletTx *pcoin = &(*it).second;
      if (!pcoin->IsFinal() || pcoin->fSpent || !pcoin->IsConfirmed())
        continue;
      nTotal += pcoin->GetCredit();
    }
  }

  // printf("GetBalance() %"PRI64d"ms\n", GetTimeMillis() - nStart);
  return nTotal;
}

bool SelectCoinsMinConf(int64 nTargetValue, int nConfMine, int nConfTheirs,
                        set<CWalletTx *> &setCoinsRet) {
  setCoinsRet.clear();

  // List of values less than target
  int64 nLowestLarger = INT64_MAX;
  CWalletTx *pcoinLowestLarger = NULL;
  vector<pair<int64, CWalletTx *>> vValue;
  int64 nTotalLower = 0;

  CRITICAL_BLOCK(cs_mapWallet) {
    vector<CWalletTx *> vCoins;
    vCoins.reserve(mapWallet.size());
    for (map<uint256, CWalletTx>::iterator it = mapWallet.begin();
         it != mapWallet.end(); ++it)
      vCoins.push_back(&(*it).second);
    random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);

    foreach (CWalletTx *pcoin, vCoins) {
      if (!pcoin->IsFinal() || pcoin->fSpent || !pcoin->IsConfirmed())
        continue;

      int nDepth = pcoin->GetDepthInMainChain();
      if (nDepth < (pcoin->IsFromMe() ? nConfMine : nConfTheirs))
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

bool SelectCoins(int64 nTargetValue, set<CWalletTx *> &setCoinsRet) {
  return (SelectCoinsMinConf(nTargetValue, 1, 6, setCoinsRet) ||
          SelectCoinsMinConf(nTargetValue, 1, 1, setCoinsRet) ||
          SelectCoinsMinConf(nTargetValue, 0, 1, setCoinsRet));
}

bool CreateTransaction(CScript scriptPubKey, int64 nValue, CWalletTx &wtxNew,
                       CReserveKey &reservekey, int64 &nFeeRet) {
  CRITICAL_BLOCK(cs_main) {
    // txdb must be opened before the mapWallet lock
    CTxDB txdb("r");
    CRITICAL_BLOCK(cs_mapWallet) {
      nFeeRet = nTransactionFee;
      loop {
        wtxNew.vin.clear();
        wtxNew.vout.clear();
        wtxNew.fFromMe = true;
        if (nValue < 0)
          return false;
        int64 nValueOut = nValue;
        int64 nTotalValue = nValue + nFeeRet;

        // Choose coins to use
        set<CWalletTx *> setCoins;
        if (!SelectCoins(nTotalValue, setCoins))
          return false;
        int64 nValueIn = 0;
        foreach (CWalletTx *pcoin, setCoins)
          nValueIn += pcoin->GetCredit();

        // Fill a vout to the payee
        bool fChangeFirst = GetRand(2);
        if (!fChangeFirst)
          wtxNew.vout.push_back(CTxOut(nValueOut, scriptPubKey));

        // Fill a vout back to self with any change
        int64 nChange = nValueIn - nTotalValue;
        if (nChange >= CENT) {
          // Note: We use a new key here to keep it from being obvious which
          // side is the change.
          //  The drawback is that by not reusing a previous key, the change may
          //  be lost if a backup is restored, if the backup doesn't have the
          //  new private key for the change. If we reused the old key, it would
          //  be possible to add code to look for and rediscover unknown
          //  transactions that were written with keys of ours to recover
          //  post-backup change.

          // Reserve a new key pair from key pool
          vector<unsigned char> vchPubKey = reservekey.GetReservedKey();
          assert(mapKeys.count(vchPubKey));

          // Fill a vout to ourself, using same address type as the payment
          CScript scriptChange;
          if (scriptPubKey.GetBitcoinAddressHash160() != 0)
            scriptChange.SetBitcoinAddress(vchPubKey);
          else
            scriptChange << vchPubKey << OP_CHECKSIG;
          wtxNew.vout.push_back(CTxOut(nChange, scriptChange));
        } else
          reservekey.ReturnKey();

        // Fill a vout to the payee
        if (fChangeFirst)
          wtxNew.vout.push_back(CTxOut(nValueOut, scriptPubKey));

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
              if (!SignSignature(*pcoin, wtxNew, nIn++))
                return false;

        // Limit size
        unsigned int nBytes =
            ::GetSerializeSize(*(CTransaction *)&wtxNew, SER_NETWORK);
        if (nBytes >= MAX_BLOCK_SIZE_GEN / 5)
          return false;

        // Check that enough fee is included
        int64 nPayFee = nTransactionFee * (1 + (int64)nBytes / 1000);
        int64 nMinFee = wtxNew.GetMinFee();
        if (nFeeRet < max(nPayFee, nMinFee)) {
          nFeeRet = max(nPayFee, nMinFee);
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
bool CommitTransaction(CWalletTx &wtxNew, CReserveKey &reservekey) {
  CRITICAL_BLOCK(cs_main) {
    printf("CommitTransaction:\n%s", wtxNew.ToString().c_str());
    CRITICAL_BLOCK(cs_mapWallet) {
      // This is only to keep the database open to defeat the auto-flush for the
      // duration of this scope.  This is the only place where this optimization
      // maybe makes sense; please don't do it anywhere else.
      CWalletDB walletdb("r");

      // Take key pair from key pool so it won't be used again
      reservekey.KeepKey();

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
        vWalletUpdated.push_back(pcoin->GetHash());
      }
    }

    // Track how many getdata requests our transaction gets
    CRITICAL_BLOCK(cs_mapRequestCount)
    mapRequestCount[wtxNew.GetHash()] = 0;

    // Broadcast
    if (!wtxNew.AcceptToMemoryPool()) {
      // This must not fail. The transaction has already been signed and
      // recorded.
      printf("CommitTransaction() : Error: Transaction not valid");
      return false;
    }
    wtxNew.RelayWalletTransaction();
  }
  MainFrameRepaint();
  return true;
}

string SendMoney(CScript scriptPubKey, int64 nValue, CWalletTx &wtxNew,
                 bool fAskFee) {
  CRITICAL_BLOCK(cs_main) {
    CReserveKey reservekey;
    int64 nFeeRequired;
    if (!CreateTransaction(scriptPubKey, nValue, wtxNew, reservekey,
                           nFeeRequired)) {
      string strError;
      if (nValue + nFeeRequired > GetBalance())
        strError = strprintf(_("Error: This is an oversized transaction that "
                               "requires a transaction fee of %s  "),
                             FormatMoney(nFeeRequired).c_str());
      else
        strError = _("Error: Transaction creation failed  ");
      printf("SendMoney() : %s", strError.c_str());
      return strError;
    }

    if (fAskFee && !ThreadSafeAskFee(nFeeRequired, _("Sending..."), NULL))
      return "ABORTED";

    if (!CommitTransaction(wtxNew, reservekey))
      return _("Error: The transaction was rejected.  This might happen if "
               "some of the coins in your wallet were already spent, such as "
               "if you used a copy of wallet.dat and coins were spent in the "
               "copy but not marked as spent here.");
  }
  MainFrameRepaint();
  return "";
}

string SendMoneyToBitcoinAddress(string strAddress, int64 nValue,
                                 CWalletTx &wtxNew, bool fAskFee) {
  // Check amount
  if (nValue <= 0)
    return _("Invalid amount");
  if (nValue + nTransactionFee > GetBalance())
    return _("Insufficient funds");

  // Parse bitcoin address
  CScript scriptPubKey;
  if (!scriptPubKey.SetBitcoinAddress(strAddress))
    return _("Invalid bitcoin address");

  return SendMoney(scriptPubKey, nValue, wtxNew, fAskFee);
}
