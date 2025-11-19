// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

class CUser;    // 声明：用户类
class CReview;  // 声明：评论类
class CProduct; // 声明：产品类
// 流量控制参数，用于限制用户在单位时间内可以发送的原子数量
static const unsigned int nFlowthroughRate = 2;

// 声明：广告插入函数
bool AdvertInsert(const CProduct &product);
// 声明：广告删除函数
void AdvertErase(const CProduct &product);
// 声明：添加原子并传播函数
bool AddAtomsAndPropagate(uint256 hashUserStart,
                          const vector<unsigned short> &vAtoms, bool fOrigin);

// 表示 “用户”，维护与 “原子（atoms）”
// 相关的三个列表（vAtomsIn输入原子、
// vAtomsNew新原子、vAtomsOut输出原子）和用户链接vLinksOut。
// 提供原子添加（AddAtom）和原子计数（GetAtomCount）功能。
class CUser {
public:
  vector<unsigned short> vAtomsIn;  // 收到的原子数量
  vector<unsigned short> vAtomsNew; // 新获得的原子（待处理）
  vector<unsigned short> vAtomsOut; // 发出的原子（用于传播）
  vector<uint256> vLinksOut;        // 用户关联的对象（用于原子传播）

  CUser() {} // 构造函数，初始化用户对象

  // 序列化函数，用于将用户对象转换为字节流
  IMPLEMENT_SERIALIZE(if (!(nType & SER_GETHASH)) READWRITE(nVersion);
                      READWRITE(vAtomsIn); READWRITE(vAtomsNew);
                      READWRITE(vAtomsOut); READWRITE(vLinksOut);)

  // 清空用户对象的所有原子数据
  void SetNull() {
    vAtomsIn.clear();  // 清空收到的原子数量
    vAtomsNew.clear(); // 清空新获得的原子（待处理）
    vAtomsOut.clear(); // 清空发出的原子（用于传播）
    vLinksOut.clear(); // 清空用户关联的对象（用于原子传播）
  }
  // 计算用户对象的哈希值，这不是用户的公钥，而是用户对象的序列化哈希值
  // 再强调一遍，这不是用户的标识符，用户的真正的标识符号是公钥哈希，是公钥哈希
  uint256 GetHash() const { return SerializeHash(*this); }

  // 计算用户的原子总数（活跃度/信誉的量化值）
  // 活跃度 = 收到的原子数量 + 新获得的原子数量
  // 信誉 = 发出的原子数量
  int GetAtomCount() const { return (vAtomsIn.size() + vAtomsNew.size()); }
  // 计算用户的信誉总数（发出的原子数量），
  // 用于评估用户的贡献度和信誉度。（这个方法我加的）
  int GetCreditCount() const { return vAtomsOut.size(); }
  // 添加原子的方法
  void AddAtom(unsigned short nAtom, bool fOrigin);
};

// 定义评论类
class CReview {
public:
  int nVersion;                        // 评论版本号，默认值为1
  uint256 hashTo;                      // 评论目标哈希值
  map<string, string> mapValue;        // 评论内容键值对
  vector<unsigned char> vchPubKeyFrom; // 评论者公钥
  vector<unsigned char> vchSig;        // 评论者签名

  // memory only（仅在内存中使用，不写入数据库）
  unsigned int nTime; // 评论时间戳，默认值为0
  int nAtoms;         // 评论中包含的原子数量，默认值为0

  CReview() {
    nVersion = 1; // 评论版本号，默认值为1
    hashTo = 0;   // 评论目标哈希值，默认值为0
    nTime = 0;    // 评论时间戳，默认值为0
    nAtoms = 0;   // 评论中包含的原子数量，默认值为0
  }

  // 序列化函数，用于将评论对象转换为字节流
  IMPLEMENT_SERIALIZE(READWRITE(this->nVersion); nVersion = this->nVersion;
                      if (!(nType & SER_DISK)) READWRITE(hashTo);
                      READWRITE(mapValue); READWRITE(vchPubKeyFrom);
                      if (!(nType & SER_GETHASH)) READWRITE(vchSig);)

  // 计算评论对象的哈希值（用于标识评论）
  uint256 GetHash() const { return SerializeHash(*this); }
  // 计算评论对象的签名哈希值（用于验证签名）
  uint256 GetSigHash() const {
    return SerializeHash(*this, SER_GETHASH | SER_SKIPSIG);
  }
  // 计算评论者公钥的哈希值（用于标识评论者）
  uint256 GetUserHash() const {
    return Hash(vchPubKeyFrom.begin(), vchPubKeyFrom.end());
  }
  // 验证评论者签名是否有效
  bool AcceptReview();
};

// 定义 “产品”，包含产品基本信息（地址、键值对属性mapValue）、
// 详细信息mapDetails、
// 订单表单vOrderForm、
// 发布者公钥vchPubKeyFrom及签名vchSig。
// 支持签名验证（CheckSignature）和产品合法性检查（CheckProduct）。
class CProduct {
public:
  int nVersion;                   // 产品版本号，默认值为1
  CAddress addr;                  // 产品地址
  map<string, string> mapValue;   // 产品键值对属性
  map<string, string> mapDetails; // 产品详细信息键值对
  vector<pair<string, string>>
      vOrderForm;         // 订单表单，每个元素为键值对（属性名-属性值）
  unsigned int nSequence; // 产品发布顺序号，默认值为0
  vector<unsigned char> vchPubKeyFrom; // 产品发布者公钥
  vector<unsigned char> vchSig;        // 产品发布者签名

  // disk only
  int nAtoms; // 产品包含的原子数量，默认值为0

  // memory only
  set<unsigned int> setSources; // 产品来源原子的顺序号集合

  // 构造函数，初始化产品对象
  CProduct() {
    nVersion = 1;  // 产品版本号，默认值为1
    nAtoms = 0;    // 产品包含的原子数量，默认值为0
    nSequence = 0; // 产品发布顺序号，默认值为0
  }

  // 序列化函数，用于将产品对象转换为字节流
  IMPLEMENT_SERIALIZE(READWRITE(this->nVersion); nVersion = this->nVersion;
                      READWRITE(addr); READWRITE(mapValue);
                      if (!(nType & SER_GETHASH)) {
                        READWRITE(mapDetails);
                        READWRITE(vOrderForm);
                        READWRITE(nSequence);
                      } READWRITE(vchPubKeyFrom);
                      if (!(nType & SER_GETHASH)) READWRITE(vchSig);
                      if (nType & SER_DISK) READWRITE(nAtoms);)

  // 计算产品对象的哈希值（用于标识产品）
  uint256 GetHash() const { return SerializeHash(*this); }
  // 计算产品对象的签名哈希值（用于验证签名）
  uint256 GetSigHash() const {
    return SerializeHash(*this, SER_GETHASH | SER_SKIPSIG);
  }
  // 计算产品发布者公钥的哈希值（用于标识产品发布者）
  uint256 GetUserHash() const {
    return Hash(vchPubKeyFrom.begin(), vchPubKeyFrom.end());
  }
  // 验证产品发布者签名是否有效
  bool CheckSignature();
  // 检查产品是否合法（包含必要的属性、详细信息、订单表单等）
  bool CheckProduct();
};

extern map<uint256, CProduct> mapProducts; // 产品哈希值到产品对象的映射
extern CCriticalSection cs_mapProducts;    // 产品映射的临界区，用于线程安全访问
extern map<uint256, CProduct> mapMyProducts; // 我的产品哈希值到产品对象的映射
