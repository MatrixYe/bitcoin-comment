# 重读比特币核心代码

## 源码阅读笔记

- [00-系统架构优化版](./comment/00-系统架构优化版.md)
- [01-uint256.h源码分析](./comment/01-uint256.h源码分析.md)
- [02-bignum.h源码分析](./comment/02-bignum.h源码分析.md)
- [03-base58.h源码分析](./comment/03-base58.h源码分析.md)
- [04-Serialize.h源码分析](./comment/04-Serialize.h源码分析.md)
- [05-key.h源码分析](./comment/05-key.h源码分析.md)
- [06-main.h源码分析(一)：交易](./comment/06-main.h源码分析\(一\)：交易.md)
- [07-main.h源码分析(二)：区块](./comment/07-main.h源码分析\(二\)：区块.md)
- [08-main.h源码分析(三)：区块链](./comment/08-main.h源码分析\(三\)：区块链.md)
- [09-main.h源码分析(四)：挖矿](./comment/09-main.h源码分析\(四\)：挖矿.md)

## 1. 代码版本

关于中本聪在邮件列表中提及的比特币核心代码的多个版本。现代比特币源代码可以在[比特币核心仓库](https://github.com/bitcoin/bitcoin)中找到。

| 版本号         | 时间         | 邮件提及                                                                                                                                                             | 源代码下载                                                                                  |
| ----------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Pre-Release | 2008-11-15 | 预览版-未知邮件                                                                                                                                                         | [bitcoin/bitcoin at nov08](https://cdn.nakamotoinstitute.org/code/bitcoin-nov08.rar)   |
| 0.1.0       | 2009-01-11 | [\[bitcoin-list\] Bitcoin v0.1 Alpha release notes - Thread \| Satoshi Nakamoto Institute](https://satoshi.nakamotoinstitute.org/emails/bitcoin-list/threads/6/) | [bitcoin/bitcoin at v0.1.0](https://cdn.nakamotoinstitute.org/code/bitcoin-0.1.0.rar)  |
| 0.1.2       | 2009-01-11 | [\[bitcoin-list\] Bitcoin v0.1.2 now available - Thread \| Satoshi Nakamoto Institute](https://satoshi.nakamotoinstitute.org/emails/bitcoin-list/threads/5/)     | 找不到                                                                                    |
| 0.1.3       | 2009-01-12 | [\[bitcoin-list\] Bitcoin v0.1.3 - Thread \| Satoshi Nakamoto Institute](https://satoshi.nakamotoinstitute.org/emails/bitcoin-list/threads/7/)                   | [bitcoin/bitcoin at v0.1.3](https://cdn.nakamotoinstitute.org/code/bitcoin-0.1.3.rar)  |
| 0.1.5       | 2009-01-12 | [\[bitcoin-list\] Bitcoin v0.1.5 released - Thread \| Satoshi Nakamoto Institute](https://satoshi.nakamotoinstitute.org/emails/bitcoin-list/threads/9/)          | [GitHub - bitcoin/bitcoin at v0.1.5](https://github.com/bitcoin/bitcoin/tree/v0.1.5)   |
| 0.2.0       | 2009-12-17 | [\[bitcoin-list\] Bitcoin 0.2 released - Thread \| Satoshi Nakamoto Institute](https://satoshi.nakamotoinstitute.org/emails/bitcoin-list/threads/11/)            | [GitHub - bitcoin/bitcoin at v0.2.0](https://github.com/bitcoin/bitcoin/tree/v0.2.0)   |
| 0.3.0       | 2010-07-06 | [\[bitcoin-list\] Bitcoin 0.3 released! - Thread \| Satoshi Nakamoto Institute](https://satoshi.nakamotoinstitute.org/emails/bitcoin-list/threads/12/)           | [GitHub - bitcoin/bitcoin at v0.3.0](https://github.com/bitcoin/bitcoin/tree/v0.3.0)   |
| 0.3.18      | 2010-12-08 | [\[bitcoin-list\] Bitcoin 0.3.18 is released - Thread \| Satoshi Nakamoto Institute](https://satoshi.nakamotoinstitute.org/emails/bitcoin-list/threads/15/)\|    | [GitHub - bitcoin/bitcoin at v0.3.18](https://github.com/bitcoin/bitcoin/tree/v0.3.18) |
| 0.3.19      | 2010-12-13 | [\[bitcoin-list\] Bitcoin 0.3.19 is released - Thread \| Satoshi Nakamoto Institute](https://satoshi.nakamotoinstitute.org/emails/bitcoin-list/threads/16/)      | [GitHub - bitcoin/bitcoin at v0.3.19](https://github.com/bitcoin/bitcoin/tree/v0.3.19) |

## 2. 重写比特币

TODO: <https://github.com/MatrixYe/bitcoin-y>

<br />

<br />

> <br />

