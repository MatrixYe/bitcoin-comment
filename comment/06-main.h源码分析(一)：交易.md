---
tags: []
title: 06-main.h源码分析(一)：交易
date: 2026-04-06 03:54:50
updated: 2026-04-09 07:54:37
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
  /**
   * 检查交易是否为币基交易
   * 币基交易是区块中的第一个交易，用于创建新的比特币
   * @return 如果是币基交易，返回true，否则返回false
   */
  bool IsCoinBase() const {
    return (vin.size() == 1 && vin[0].prevout.IsNull());
  }
```
## 如何检查交易的正确性

交易的验证和脚本验证、区块的验证实际上是分开的，不依赖上下文，只对交易的检查非常简单。输入和输出不能为空，金额不能是负数（但可以是 0 也是有趣），如果是 Coinbase 交易，那么限制解锁脚本的大小。如果是普通交易，那么输入不能为空。coinbase 交易的限制是比较特殊的，因为 coinbase 交易不是解锁的现有交易，而是系统自己派发的，所以 coinbase 是不需要解锁脚本的，或者任意形式的脚本都可以。但这个字段又不能移除，因此才限制了解锁脚本的大小。按道理普通交易的解锁脚本也需要限制大小，但是这部分限制规则被放到区块验证上去了。

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

实际的交易验证当然不只是基础验证这么简单，中本聪在 main. cpp 中给出了节点接收一个交易的完整逻辑。
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

## 交易如何替换及如何判断交易的新旧
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
## 如何验证交易输入
交易的验证绝大部分的逻辑是验证交易的输入。

## 如何判断是否为 Coinbase 交易

## 交易如何加入内存池的

## 交易如何移除内存池的
