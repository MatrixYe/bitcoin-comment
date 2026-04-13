---
tags: []
title: 06-main.h源码分析(一)：交易
date: 2026-04-06 03:54:50
updated: 2026-04-12 10:29:26
---

## 与交易相关的结构体
![Pasted image 20260408174943](https://raw.githubusercontent.com/MatrixYe/images/master/Pasted%20image%2020260408174943.png)

与交易相关的结构体其实比较多。大体可以分成四个层次：
1. 围绕 `CTranscation` 组成核心类。包括 `CTranscation`、`CTxIn`、`CTxOut`, `COutPoint`, `CInPoint`。这些类共同组成了交易的核心结构。
2. 围绕 `CTranscation` 进行功能拓展的类。包括 `CMerkleTx`，`CWalletTx`。这些类都继承至 `CTranscation`
3. 围绕交易数据存储相关的类，包括 `CTxIndex`，`CDiskTxPos`。这些类与交易查询读取相关。
4. 围绕 Script 相关的类，这部分内容单独分析。
这些有分别有自己的成员属性，最重要的是 `CTranscation` 的成员属性。在 `CTranscation` 中，交易输入列表 (vIn) 和交易输出列表 (vOut) 无疑是最重要的，输入列表中存在多个 `CTxIn`，每个 `CTxin` 中包含了上一个交易输出点 (`COutPoint`), 解锁脚本 `CScript` 和序列号。输出列表中存在多个 `CTxOut`，每个 `CTxOut` 包含了比特币价值 `nValue` 和锁定脚本 `CScript`。如果仔细观察 `CTtranscation` 的结构，会发现在这个结构中是没有所谓的 CInPoint 的，在代码中定义的 CInPoint 更像是 COutPoint 的一种别名。
![Pasted image 20260409011652](https://raw.githubusercontent.com/MatrixYe/images/master/Pasted%20image%2020260409011652.png)

这些类分别有自己的成员方法，数量很多，大部分根据方法名就可以明确知道相关的功能。但有一些方法需要单独拿出来认真分析。
## 如何区分普通交易和 Coinbase 交易
只需要判断交易的输入列表是否存在唯一的 CTxIn，且此 CTxIn 的引用上一个交易的输出点为 Null。
```cpp
//mian.h IsCoinBase

/**

* 检查交易是否为币基交易

* 币基交易是区块中的第一个交易，用于创建新的比特币

* @return 如果是币基交易，返回true，否则返回false

*/

bool IsCoinBase() const {

return (vin.size() == 1 && vin[0].prevout.IsNull());

}
```
## 不依赖上下文的交易检测 CTrasaction::CheckTransaction

不依赖上下文，只对交易的检查非常简单。输入和输出不能为空，金额不能是负数（但可以是 0 也是有趣），如果是 Coinbase 交易，那么限制解锁脚本的大小。如果是普通交易，那么输入不能为空。coinbase 交易的限制是比较 t45r  特殊的，因为 coinbase 交易不是解锁的现有交易，而是系统自己派发的，所以 coinbase 是不需要解锁脚本的，或者任意形式的脚本都可以。但这个字段又不能移除，因此才限制了解锁脚本的大小。按道理普通交易的解锁脚本也需要限制大小，但是这部分限制规则被放到区块验证上去了。

```cpp
  // main.h bool CheckTransaction() const
  /**
   * 检查交易的基本有效性
   * 不依赖于上下文的基本检查
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
    // 币基交易需要检查解锁脚本大小
      if (vin[0].scriptSig.size() < 2 || vin[0].scriptSig.size() > 100)
        return error("CTransaction::CheckTransaction() : coinbase script size");
    } else {
    // 非币基交易不能输入为空
      foreach (const CTxIn &txin, vin)
        if (txin.prevout.IsNull())
          return error("CTransaction::CheckTransaction() : prevout is null");
    }

    return true;
  }
```

![交易流程-CheckTransaction().drawio](https://raw.githubusercontent.com/MatrixYe/images/master/交易流程-CheckTransaction().drawio.png)

## 接收交易检测 CTransaction::AcceptTransaction
实际的交易验证当然不只是基础验证这么简单，中本聪在 main. cpp 中给出了节点接收一个交易的完整逻辑 CTransaction::AcceptTransaction。
- 主要验证步骤：
- 1. 检查是否为币基交易（币基交易不能作为独立交易被接受）
- 2. 执行基本交易检查（CheckTransaction）
- 3. 检查交易是否已存在于内存池或数据库中
- 4. 检查与内存中交易的冲突（支持用新版本替换旧版本）
- 5. 验证交易输入（ConnectInputs）
- 6. 将交易添加到内存池

上述流程中，除了基础的交易验证外，还包含了对 Coinbase 交易的特殊处理，重复交易的处理，以及交易输入的详细检查。第 4 步是比较特殊的，它并非验证交易的合法性，而是提供了一种交易替换策略，可以让新的交易 (当然是相同的)，替换旧的交易。后面会详细解释这部分功能。
```cpp
// main.cpp bool CTransaction::AcceptTransaction
/**
 * 接受交易
 * 验证交易的有效性，并将其添加到内存池
 *
 * @param txdb 交易数据库，用于查询已有交易和验证输入
 * @param fCheckInputs 是否检查输入，如果为false则跳过输入验证
 * @param pfMissingInputs 可选的输出参数，用于标记是否有缺失的输入
 * @return 如果交易被成功接受，返回true；否则返回false
 *
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
```

![[asset/attachments/交易流程-CTransaction AcceptTransaction.drawio 1.png]]

### 交易如何替换及如何判断交易的新旧
因为交易的输入列表中是可能存在多个 CTxIn 的，既而存在多个 COutPoint，从代码逻辑上看，交易替换只有在交易的第一个输入（i == 0）可以触发。而且新交易必须比旧交易更新（通过 IsNewerThan 判断），新交易的所有输入必须都指向同一个旧交易。

```c++
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
```

这个逻辑其实是比较奇怪的，回顾一下 `CTranscation`、`CTxIn`、`CTxOut`、`COutPoint` 的结构，一笔交易包含了多个 `CTxIn` 作为输入列表，多个 `CTxOut` 作为输出列表。而交易替换策略表明，系统可以接受一种特殊的交易，它的输入列表与旧的交易相同（单指 `COutPoint`），输出列表可以不同。而且更奇怪的是，判断新旧的标准是在输入列表中的第一个 `CTxIn` 中的一个字段 `nSequence`, 除了这个，其余的不认。从判断新旧的函数 `IsNewerThan` 可以了解具体过程。
```c++
bool IsNewerThan(const CTransaction &old) const {
  // 输入数量必须相同
  if (vin.size() != old.vin.size())
    return false;
  
  // 所有输入的前一个输出点必须相同，就是COutPoint
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
```
平心而论，这是我第一次知道有这个设计，之前我只知道交易能被替换的原因是双花攻击。这个设计在 0.1 这个版本就已经出现证明中本聪一定是思考过这个问题的，即未确认的交易可以被更新。交易从发送出去，到被节点打包进入区块的过程中，并非一成不变。就像一根箭矢，从发射到命中目标，飞行的过程中可以被修改（出发点不可以改，但目的地可以改）。

交易替换机制给交易极大的灵活性，交易只要还未确认，就可以通过构造新的交易来修改输出列表，包括接收者的列表，接收者的金额分配，重置手续费等。当然为了防止滥用，中本聪还是做了一点限制。
交易替换机制就是后来的 Replace-By-Fee (RBF) 的前身。RBF 也经过了多轮改进，目前流行的 BIP 125 为“Opt-in RBF”（选择性 RBF），交易需要显式设置“可替代”标志，否则大部分节点会拒绝替代请求。参考 [选择性加入费用替代法（Opt-in RBF）常见问答](https://bitcoincore.org/zh_CN/faq/optin_rbf/#:~:text=Bitcoin%20Core%20::%20%E9%80%89%E6%8B%A9%E6%80%A7%E5%8A%A0%E5%85%A5%E8%B4%B9%E7%94%A8%E6%9B%BF%E4%BB%A3%E6%B3%95%EF%BC%88Opt%2Din%20RBF%EF%BC%89%E5%B8%B8%E8%A7%81%E9%97%AE%E7%AD%94)
顺便吐槽一下中本聪的代码风格，总是喜欢 for 循环里面各种嵌套 if，造成很大的阅读困难。
## 交易输入列表检测 CTransaction:: ConnectInputs
验证交易的最重要的一部分是验证交易的输入 `vin`。`CTransaction:: ConnectInputs` 承担了最核心的功能。这个函数非常长，逻辑也比较复杂, 理解起来比较困难。`vin` 是一个列表，里面的元素类型是 `CTxIn`。CTxIn 包含了前序交易的输出点，以及解锁脚本。因此验证每一个 CTxIn 的关键在于，验证每一个前序交易输出点是否合法，以及解锁脚本是否与前序交易匹配。在梳理函数流程之前，有必要介绍一下这个函数中出现的关键概念。
### 1. 区块模式 (fBlock) 和挖矿模式 (fMiner)
ConnectInputs 函数设计了两种运行模式，对应比特币网络中交易处理的两个不同阶段。当一个新区块被成功挖掘并添加到区块链时 (节点接收新区块)，需要验证交易输入，采用区块模式 (fBlock)。而当处于挖矿状态时，验证交易输入采用挖矿模式 (fMiner)。区块模式下，函数主要操作数据库；挖矿模式下，函数主要操作内存。这样区分的原因是，- 矿工在挖矿时可能会尝试多个交易组合，如果直接修改数据库，挖矿失败时需要回滚这些修改。同时，大量的交易验证也会产生 IO 上的压力，采用内存可以减少对数据库的读写，提高系统性能。
### 2. 测试池 (mapTestPool) 和内存池 (mapTransaction)
`mapTestPool` 是挖矿函数中的局部变量，不是全局变量。这个变量是在挖矿时定义的：
```cpp
// mian.cpp
// 在 BitcoinMiner 挖矿函数中
CRITICAL_BLOCK(cs_main)
CRITICAL_BLOCK(cs_mapTransactions) {
  CTxDB txdb("r");
  map<uint256, CTxIndex> mapTestPool;  // <-- 这里定义，是局部变量
  ...
}
```
内存池 (mapTransaction) 是定义的全局变量：
```cpp
// main.cpp:14-15 - 全局变量
map<uint256, CTransaction> mapTransactions;
CCriticalSection cs_mapTransactions;
```

- 内存池的数据结构是 map<交易哈希, 交易>，测试池的数据结构是 map<交易哈希, 交易索引>
- 内存池中存储的是完整的交易对象 `CTransaction`，测试池中存储的是交易索引 CTxIndex（含花费状态）
- 内存池在程序运行期间一直存在，测试池仅仅在挖矿时期存在，而且每一次重新挖矿都会被重新创建
- 内存池存储着所有未确认的交易，测试池仅记录挖矿过程中 UTXO 的花费状态

### 交易输入验证流程
无论是哪种模式，交易输入验证满足如下流程：
```
获取前序交易 → 验证签名 → 检查双重花费 → 更新花费状态 → 计算手续费
```
![交易流程-ConnectInputs.drawio](https://raw.githubusercontent.com/MatrixYe/images/master/交易流程-ConnectInputs.drawio.png)

```cpp
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
```

## 交易如何加入内存池的
//todo
## 交易如何移除内存池的
//todo
