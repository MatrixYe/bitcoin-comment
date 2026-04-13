---
tags: []
title: 07-main.h源码分析(二)：区块
date: 2026-04-06 03:54:50
updated: 2026-04-12 05:01:33
---

## 与区块相关的类
`CBlock()`：区块核心
`CBlockIndex()` 区块索引
`CBlockLocator`：没看懂 //todo

## Block 成员属性
```cpp
  // header
  int nVersion; // 版本号
  uint256 hashPrevBlock; // 前一个区块哈希
  uint256 hashMerkleRoot; //默克尔树根
  unsigned int nTime; // 时间戳
  unsigned int nBits; //难度指标
  unsigned int nNonce; // 一次性随机数
  // network and disk
  vector<CTransaction> vtx; // 交易列表
  // memory only
  mutable vector<uint256> vMerkleTree; // 默克尔树
```

![[asset/attachments/Pasted image 20260412133530.png]]

简称为 "6+1+1"，其中版本号、前区块哈希、默克尔根、时间戳、难度指标、随机数，构成区块头。交易列表也有，但不参与序列化。默克尔树是临时计算时使用。区块头中最重要的是难度指标和一次性随机数，二者共同构成了区块的工作量证明。

比特币中最重要的基础数据只有两个 ' 交易 ' 和 ' 区块 '，也只有这两种数据在节点之间进行传播。对这两种基础数据的检测工作遵循相类似的流程。第一步是不依赖上下文的检测，交易使用 `CTrasaction::CheckTransaction`，区块使用 `CBlock::CheckBlock()` 第二步是更全面的验证，包括上下文检查。交易使用 `CTransaction::AcceptTransaction`，区块使用 `CBlock::AcceptBlock()`。第三步是最严格的输入检查，交易使用 `CTransaction:: ConnectInputs()`, 区块使用 `CBlock::ConnectBlock()`。

## 不依赖上下文的区块检测 CBlock::CheckBlock()
`CheckBlock()` 方法是区块验证的第一道防线，执行不依赖上下文的基本验证，确保区块满足比特币网络的基本规则。
验证步骤：
1. 大小限制检查。交易列表不能为空，交易数量不能过大，区块序列化后不能超过最大限制。
2. 时间戳检查。`nTime` 的取值不能超过当前时间的未来两小时，这主要考量到网络同步。
3. Coinbase 交易检测。交易列表中，第一笔必须是 coinbase 交易。其余的所有交易都不能是 coinbase 交易。
4. 交易列表检测。遍历所有交易，依次调用 `CheckTransaction()` 方法。
5. 检查难度值是否符合基本要求。难度值不能低于最小工作量要求，区块哈希值必须小于目标难度值。
6. 最后检测默克尔根是否与计算一致，这主要是防止数据被篡改。
```cpp
bool CBlock::CheckBlock() const {
  // These are checks that are independent of context
  // that can be verified before saving an orphan block.

  // Size limits
  // 检查区块大小限制
  // 1. 交易列表不能为空
  // 2. 交易数量不能超过最大限制
  // 3. 区块序列化后的大小不能超过最大限制
  if (vtx.empty() || vtx.size() > MAX_SIZE ||
      ::GetSerializeSize(*this, SER_DISK) > MAX_SIZE)
    return error("CheckBlock() : size limits failed");

  // Check timestamp
  // 检查时间戳：区块时间不能超过当前调整时间后2小时
  // 防止区块时间设置得过于未来，影响网络同步
  if (nTime > GetAdjustedTime() + 2 * 60 * 60)
    return error("CheckBlock() : block timestamp too far in the future");

  // First transaction must be coinbase, the rest must not be
  // 检查币基交易规则：
  // 1. 第一个交易必须是币基交易
  // 2. 其余交易不能是币基交易
  if (vtx.empty() || !vtx[0].IsCoinBase())
    return error("CheckBlock() : first tx is not coinbase");
  for (int i = 1; i < vtx.size(); i++)
    if (vtx[i].IsCoinBase())
      return error("CheckBlock() : more than one coinbase");

  // Check transactions
  // 检查区块中的所有交易是否合法
  foreach (const CTransaction &tx, vtx)
    if (!tx.CheckTransaction())
      return error("CheckBlock() : CheckTransaction failed");

  // Check proof of work matches claimed amount
  // 检查工作量证明是否符合要求：
  // 1. 难度值不能低于最小工作量要求
  // 2. 区块哈希值必须小于目标难度值
  if (CBigNum().SetCompact(nBits) > bnProofOfWorkLimit)
    return error("CheckBlock() : nBits below minimum work");
  if (GetHash() > CBigNum().SetCompact(nBits).getuint256())
    return error("CheckBlock() : hash doesn't match nBits");

  // Check merkleroot
  // 检查默克尔树根是否与实际计算的一致
  // 确保交易列表没有被篡改
  if (hashMerkleRoot != BuildMerkleTree())
    return error("CheckBlock() : hashMerkleRoot mismatch");

  return true;
}
```

## 接受区块检测 AcceptBlock
与 CheckBlock() 不同，AcceptBlock() 需要区块链的上下文信息。检测流程如下：
1. 检查区块是否已经存在于区块索引中，如果有就不重复添加了。注意此处没有使用全局变量，因为对于区块来说，没有内存池这个概念。
2. 获取前一个区块的索引，找不到就报错。
3. 检查前一个区块的时间长是否遭遇前一个区块的中位数时间，确保区块的时间是递增的
4. 检查工作量证明是否正确，核心是检查难度值 nBits 是否符合网络要求
5. 如果这是最佳区块，还需要对外进行广播
6. 结束，返回 True


上面的流程相对于交易的 accepttranscation 而言，就显得简单多了。
```cpp
// main.cpp bool CBlock::AcceptBlock()
/**
 * 接受区块到区块链中
 * 
 * 执行依赖上下文的区块验证，包括区块连接性、时间戳、工作量证明等检查
 * 并将区块写入磁盘，添加到区块索引中
 *
 * @return 如果区块被成功接受返回 true，否则返回 false
 */
bool CBlock::AcceptBlock() {
  // Check for duplicate
  // 检查区块是否已存在于区块索引中
  uint256 hash = GetHash();
  if (mapBlockIndex.count(hash))
    return error("AcceptBlock() : block already in mapBlockIndex");

  // Get prev block index
  // 获取前一个区块的索引
  map<uint256, CBlockIndex *>::iterator mi = mapBlockIndex.find(hashPrevBlock);
  if (mi == mapBlockIndex.end())
    return error("AcceptBlock() : prev block not found");
  CBlockIndex *pindexPrev = (*mi).second;

  // Check timestamp against prev
  // 检查区块时间戳是否早于前一个区块的中位数时间
  // 确保区块时间是递增的
  if (nTime <= pindexPrev->GetMedianTimePast())
    return error("AcceptBlock() : block's timestamp is too early");

  // Check proof of work
  // 检查工作量证明是否正确
  // 验证区块的难度值是否符合网络要求
  if (nBits != GetNextWorkRequired(pindexPrev))
    return error("AcceptBlock() : incorrect proof of work");

  // Write block to history file
  // 将区块写入历史文件
  unsigned int nFile;
  unsigned int nBlockPos;
  if (!WriteToDisk(!fClient, nFile, nBlockPos))
    return error("AcceptBlock() : WriteToDisk failed");
  // 将区块添加到区块索引
  if (!AddToBlockIndex(nFile, nBlockPos))
    return error("AcceptBlock() : AddToBlockIndex failed");

  // 如果这是最佳链，广播区块
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
```
## 默克尔树的构建

## 难度值网络要求
