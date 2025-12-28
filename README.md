# 比特币注释
本项目致力于收集并注释中本聪的代码和邮件，帮助爱好者系统阅读、理解比特币核心代码的演进脉络。


## 1. 代码版本
关于中本聪在邮件列表中提及的比特币核心代码的多个版本。现代比特币源代码可以在[比特币核心仓库](https://github.com/bitcoin/bitcoin)中找到。


| 版本号         | 时间         | 邮件提及                                                                                                                                                               | 源代码下载                                                                                   |
| ----------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Pre-Release | 2008-11-15 | 预览版-未知邮件                                                                                                                                                               | [bitcoin/bitcoin at nov08](https://cdn.nakamotoinstitute.org/code/bitcoin-nov08.rar)   |
| 0.1.0       | 2009-01-11 | [\[bitcoin-list\] Bitcoin v0.1 Alpha release notes - Thread \| Satoshi Nakamoto Institute](https://satoshi.nakamotoinstitute.org/emails/bitcoin-list/threads/6/) | [bitcoin/bitcoin at v0.1.0](https://cdn.nakamotoinstitute.org/code/bitcoin-0.1.0.rar)  |
| 0.1.2       | 2009-01-11 | [\[bitcoin-list\] Bitcoin v0.1.2 now available - Thread \| Satoshi Nakamoto Institute](https://satoshi.nakamotoinstitute.org/emails/bitcoin-list/threads/5/)     | 找不到                                                                                     |
| 0.1.3       | 2009-01-12 | [\[bitcoin-list\] Bitcoin v0.1.3 - Thread \| Satoshi Nakamoto Institute](https://satoshi.nakamotoinstitute.org/emails/bitcoin-list/threads/7/)                   | [bitcoin/bitcoin at v0.1.3](https://cdn.nakamotoinstitute.org/code/bitcoin-0.1.3.rar)  |
| 0.1.5       | 2009-01-12 | [\[bitcoin-list\] Bitcoin v0.1.5 released - Thread \| Satoshi Nakamoto Institute](https://satoshi.nakamotoinstitute.org/emails/bitcoin-list/threads/9/)          | [GitHub - bitcoin/bitcoin at v0.1.5](https://github.com/bitcoin/bitcoin/tree/v0.1.5)   |
| 0.2.0       | 2009-12-17 | [\[bitcoin-list\] Bitcoin 0.2 released - Thread \| Satoshi Nakamoto Institute](https://satoshi.nakamotoinstitute.org/emails/bitcoin-list/threads/11/)            | [GitHub - bitcoin/bitcoin at v0.2.0](https://github.com/bitcoin/bitcoin/tree/v0.2.0)   |
| 0.3.0       | 2010-07-06 | [\[bitcoin-list\] Bitcoin 0.3 released! - Thread \| Satoshi Nakamoto Institute](https://satoshi.nakamotoinstitute.org/emails/bitcoin-list/threads/12/)           | [GitHub - bitcoin/bitcoin at v0.3.0](https://github.com/bitcoin/bitcoin/tree/v0.3.0)   |
| 0.3.18      | 2010-12-08 | [\[bitcoin-list\] Bitcoin 0.3.18 is released - Thread \| Satoshi Nakamoto Institute](https://satoshi.nakamotoinstitute.org/emails/bitcoin-list/threads/15/)\|    | [GitHub - bitcoin/bitcoin at v0.3.18](https://github.com/bitcoin/bitcoin/tree/v0.3.18) |
| 0.3.19      | 2010-12-13 | [\[bitcoin-list\] Bitcoin 0.3.19 is released - Thread \| Satoshi Nakamoto Institute](https://satoshi.nakamotoinstitute.org/emails/bitcoin-list/threads/16/)      | [GitHub - bitcoin/bitcoin at v0.3.19](https://github.com/bitcoin/bitcoin/tree/v0.3.19) |

## 2. 邮件翻译

包含中本聪在多个邮件组中发布的邮件，可以更好地理解中本聪关于比特币系统的时间发展和设计决策。
1. [Bitcoin P2P e-cash paper](emails/Bitcoin%20P2P%20e-cash%20paper.md)

2. TODO: 补充其他邮件并写入emails目录

## 3. 重读比特币
包含对比特币核心代码的详细注解，可以更好地理解中本聪关于比特币系统的设计和实现。
 
TODO: 写入comment目录

- 关于未完成的p2p market 的设计
- 关于默克尔树的实现
- 关于区块的结构和验证
- 关于交易的结构和验证
- 关于难度调整机制的设计
- 。。。 。。。
- TODO:补充其他代码细节

## 零碎笔记
1. [核心数据结构](notes/核心数据结构.md)

## 把比特币的代码重写一遍
为了更好地理解比特币的核心代码，我计划用rust语言重写一遍比特币的代码。

[MatrixYe/bitcoin-y](https://github.com/MatrixYe/bitcoin-y)
