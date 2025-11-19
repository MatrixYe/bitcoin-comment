// Copyright (c) 2009 Satoshi Nakamoto
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "headers.h"
#include <winsock2.h>

void ThreadMessageHandler2(void* parg);
void ThreadSocketHandler2(void* parg);
void ThreadOpenConnections2(void* parg);






//
//
// Global state variables
//
bool fClient = false;                                           // -client=1: 以客户端模式运行，不接受传入连接
uint64 nLocalServices = (fClient ? 0 : NODE_NETWORK);           // 本节点提供的服务，如NODE_NETWORK表示是全节点
CAddress addrLocalHost(0, DEFAULT_PORT, nLocalServices);        // 本机地址信息
CNode nodeLocalHost(INVALID_SOCKET, CAddress("127.0.0.1", nLocalServices)); // 代表本机的节点对象
CNode* pnodeLocalHost = &nodeLocalHost;                         // 指向本机节点对象的指针
bool fShutdown = false;                                         // 程序是否正在关闭的标志
array<bool, 10> vfThreadRunning;                                // 标记各个后台线程是否正在运行
vector<CNode*> vNodes;                                          // 存储所有已连接的远程节点
CCriticalSection cs_vNodes;                                     // 用于保护vNodes的临界区，保证线程安全
map<vector<unsigned char>, CAddress> mapAddresses;              // 地址池，存储已知的网络节点地址
CCriticalSection cs_mapAddresses;                               // 用于保护mapAddresses的临界区
map<CInv, CDataStream> mapRelay;                                // 中继缓冲区，暂存待转发的数据（交易或区块）
deque<pair<int64, CInv> > vRelayExpiration;                     // 中继数据的过期时间队列，用于清理mapRelay
CCriticalSection cs_mapRelay;                                   // 用于保护mapRelay和vRelayExpiration的临界区
map<CInv, int64> mapAlreadyAskedFor;                            // 跟踪已向其他节点请求过的数据，避免重复请求



CAddress addrProxy;

// 建立一个到目标地址的套接字连接。
// 这个函数会创建一个套接字并尝试连接到指定的地址(addrConnect)。
// 如果配置了代理(addrProxy)，它会通过SOCKS4代理进行连接。
// 连接成功后，会返回创建的套接字句柄。
// @param addrConnect 要连接的目标CAddress对象。
// @param hSocketRet 用于返回成功连接后的套接字句柄的引用。
// @return bool 如果连接成功，返回true；否则返回false。
bool ConnectSocket(const CAddress& addrConnect, SOCKET& hSocketRet)
{
    hSocketRet = INVALID_SOCKET;

    // 创建一个TCP/IP套接字
    SOCKET hSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (hSocket == INVALID_SOCKET)
        return false;

    // 判断地址是否为可路由的公网地址（非私有IP）
    bool fRoutable = !(addrConnect.GetByte(3) == 10 || (addrConnect.GetByte(3) == 192 && addrConnect.GetByte(2) == 168));
    // 判断是否需要使用代理（仅对公网地址使用）
    bool fProxy = (addrProxy.ip && fRoutable);
    // 根据是否使用代理，设置连接的目标地址
    struct sockaddr_in sockaddr = (fProxy ? addrProxy.GetSockAddr() : addrConnect.GetSockAddr());

    // 连接到目标地址（或代理服务器）
    if (connect(hSocket, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == SOCKET_ERROR)
    {
        closesocket(hSocket);
        return false;
    }

    // 如果使用了代理，需要进行SOCKS4握手
    if (fProxy)
    {
        printf("Proxy connecting to %s\n", addrConnect.ToString().c_str());
        // 构建SOCKS4连接请求
        // 协议格式: [版本(0x04)][命令(0x01)][端口][IP地址][用户ID][0x00]
        char pszSocks4IP[] = "\4\1\0\0\0\0\0\0user";
        memcpy(pszSocks4IP + 2, &addrConnect.port, 2); // 端口
        memcpy(pszSocks4IP + 4, &addrConnect.ip, 4);   // IP地址
        char* pszSocks4 = pszSocks4IP;
        int nSize = sizeof(pszSocks4IP);

        // 发送SOCKS4请求
        int ret = send(hSocket, pszSocks4, nSize, 0);
        if (ret != nSize)
        {
            closesocket(hSocket);
            return error("Error sending to proxy\n");
        }
        // 接收代理服务器的响应
        char pchRet[8];
        if (recv(hSocket, pchRet, 8, 0) != 8)
        {
            closesocket(hSocket);
            return error("Error reading proxy response\n");
        }
        // 检查响应状态，0x5a表示成功
        if (pchRet[1] != 0x5a)
        {
            closesocket(hSocket);
            return error("Proxy returned error %d\n", pchRet[1]);
        }
        printf("Proxy connection established %s\n", addrConnect.ToString().c_str());
    }

    // 返回成功连接的套接字
    hSocketRet = hSocket;
    return true;
}


// 从套接字接收一行数据
//
// 这个函数从指定的套接字中读取数据，直到遇到换行符'\n'为止。
// 它处理了\r\n和\n两种换行符格式，并将接收到的行内容（不包括换行符）
// 存储在strLine中。
//
// @param hSocket 要读取的套接字。
// @param strLine 用于存储接收到的一行数据的字符串。
// @return bool 如果成功接收一行，返回true；如果连接关闭或发生错误，返回false。
bool RecvLine(SOCKET hSocket, string& strLine)
{
    strLine.clear();
    while (true)
    {
        char c;
        // 从套接字接收一个字节
        int nBytes = recv(hSocket, &c, 1, 0);
        if (nBytes > 0)
        {
            // 如果是换行符，结束循环
            if (c == '\n')
                break;
            // 如果不是回车符，则追加到字符串
            if (c != '\r')
                strLine += c;
        }
        else if (nBytes == 0)
        {
            // 连接已关闭
            return false;
        }
        else
        {
            // 发生错误
            return false;
        }
    }
    return true;
}


// 获取本机的公网IP地址
//
// 这个函数通过连接到一个已知的外部服务(whatismyip.com)并解析其返回的HTTP响应
// 来确定本机的公网IP地址。这对于在NAT设备后面的节点发现自己的外部地址至关重要。
//
// @param ipRet 用于返回获取到的公网IP地址（网络字节序）。
// @return bool 如果成功获取IP，返回true；否则返回false。
bool GetMyExternalIP(unsigned int& ipRet)
{
    // 连接到whatismyip.com服务
    CAddress addrConnect("72.233.89.199:80"); // whatismyip.com 198-200

    SOCKET hSocket;
    if (!ConnectSocket(addrConnect, hSocket))
        return error("GetMyExternalIP() : connection to %s failed\n", addrConnect.ToString().c_str());

    // 发送HTTP GET请求
    char* pszGet =
        "GET /automation/n09230945.asp HTTP/1.1\r\n"
        "Host: www.whatismyip.com\r\n"
        "User-Agent: Bitcoin/0.1\r\n"
        "Connection: close\r\n"
        "\r\n";
    send(hSocket, pszGet, strlen(pszGet), 0);

    // 逐行读取HTTP响应
    string strLine;
    while (RecvLine(hSocket, strLine))
    {
        // 响应头结束后，下一行就是IP地址
        if (strLine.empty())
        {
            if (!RecvLine(hSocket, strLine))
            {
                closesocket(hSocket);
                return false;
            }
            closesocket(hSocket);
            // 将返回的字符串IP地址转换为CAddress对象
            CAddress addr(strLine.c_str());
            printf("GetMyExternalIP() received [%s] %s\n", strLine.c_str(), addr.ToString().c_str());
            if (addr.ip == 0)
                return false;
            // 返回获取到的IP地址
            ipRet = addr.ip;
            return true;
        }
    }
    closesocket(hSocket);
    return error("GetMyExternalIP() : connection closed\n");
}






// 将一个新地址添加到地址管理器中。
// 这个函数首先检查地址是否可路由且不是本地地址。
// 然后，它会检查该地址是否已经存在于地址池(mapAddresses)中。
// 如果是新地址，则将其插入地址池并写入地址数据库(addrdb)。
// 如果地址已存在但提供了新的服务，则更新其服务标志。
// @param addrdb 地址数据库对象，用于持久化地址。
// @param addr 要添加的CAddress对象。
// @return bool 如果地址是新的或被更新，返回true；否则返回false。
// 将地址添加到地址数据库
//
// 这个函数负责将一个新的对等节点地址添加到地址管理器(mapAddresses)中，
// 并将其持久化到磁盘上的 "addr.dat" 文件中。它会检查地址是否已存在，
// 如果不存在，则将其添加并序列化到数据库。
//
// @param addrdb CAddrDB 类型的地址数据库对象，用于读写 addr.dat 文件。
// @param addr 要添加的 CAddress 对象。
// @return bool 如果地址是新的并成功添加，返回true；如果地址已存在，返回false。
bool AddAddress(CAddrDB& addrdb, const CAddress& addr)
{
    // 检查地址是否已存在于内存中的地址映射
    if (mapAddresses.count(addr))
        return false;

    // 将新地址插入到地址映射中
    mapAddresses.insert(make_pair(addr, 1));

    // 将新地址写入到 addr.dat 数据库文件
    addrdb.WriteAddress(addr);

    return true;
}





void AbandonRequests(void (*fn)(void*, CDataStream&), void* param1)
{
    // If the dialog might get closed before the reply comes back,
    // call this in the destructor so it doesn't get called after it's deleted.
    CRITICAL_BLOCK(cs_vNodes)
    {
        foreach(CNode* pnode, vNodes)
        {
            CRITICAL_BLOCK(pnode->cs_mapRequests)
            {
                for (map<uint256, CRequestTracker>::iterator mi = pnode->mapRequests.begin(); mi != pnode->mapRequests.end();)
                {
                    CRequestTracker& tracker = (*mi).second;
                    if (tracker.fn == fn && tracker.param1 == param1)
                        pnode->mapRequests.erase(mi++);
                    else
                        mi++;
                }
            }
        }
    }
}







//
// Subscription methods for the broadcast and subscription system.
// Channel numbers are message numbers, i.e. MSG_TABLE and MSG_PRODUCT.
//
// The subscription system uses a meet-in-the-middle strategy.
// With 100,000 nodes, if senders broadcast to 1000 random nodes and receivers
// subscribe to 1000 random nodes, 99.995% (1 - 0.99^1000) of messages will get through.
//

bool AnySubscribed(unsigned int nChannel)
{
    if (pnodeLocalHost->IsSubscribed(nChannel))
        return true;
    CRITICAL_BLOCK(cs_vNodes)
        foreach(CNode* pnode, vNodes)
            if (pnode->IsSubscribed(nChannel))
                return true;
    return false;
}

bool CNode::IsSubscribed(unsigned int nChannel)
{
    if (nChannel >= vfSubscribe.size())
        return false;
    return vfSubscribe[nChannel];
}

void CNode::Subscribe(unsigned int nChannel, unsigned int nHops)
{
    if (nChannel >= vfSubscribe.size())
        return;

    if (!AnySubscribed(nChannel))
    {
        // Relay subscribe
        CRITICAL_BLOCK(cs_vNodes)
            foreach(CNode* pnode, vNodes)
                if (pnode != this)
                    pnode->PushMessage("subscribe", nChannel, nHops);
    }

    vfSubscribe[nChannel] = true;
}

void CNode::CancelSubscribe(unsigned int nChannel)
{
    if (nChannel >= vfSubscribe.size())
        return;

    // Prevent from relaying cancel if wasn't subscribed
    if (!vfSubscribe[nChannel])
        return;
    vfSubscribe[nChannel] = false;

    if (!AnySubscribed(nChannel))
    {
        // Relay subscription cancel
        CRITICAL_BLOCK(cs_vNodes)
            foreach(CNode* pnode, vNodes)
                if (pnode != this)
                    pnode->PushMessage("sub-cancel", nChannel);

        // Clear memory, no longer subscribed
        if (nChannel == MSG_PRODUCT)
            CRITICAL_BLOCK(cs_mapProducts)
                mapProducts.clear();
    }
}









CNode* FindNode(unsigned int ip)
{
    CRITICAL_BLOCK(cs_vNodes)
    {
        foreach(CNode* pnode, vNodes)
            if (pnode->addr.ip == ip)
                return (pnode);
    }
    return NULL;
}

CNode* FindNode(CAddress addr)
{
    CRITICAL_BLOCK(cs_vNodes)
    {
        foreach(CNode* pnode, vNodes)
            if (pnode->addr == addr)
                return (pnode);
    }
    return NULL;
}

// 连接到一个新的节点，或者返回一个已存在的连接。
//
// 这个函数负责管理到其他节点的出站连接。
// 它的逻辑是：
// 1. 检查是否是连接到本机，如果是则忽略。
// 2. 检查是否已经存在到该IP的连接，如果存在，则增加其引用计数并返回现有节点。
// 3. 如果不存在连接，则调用 ConnectSocket() 尝试建立一个新的套接字连接。
// 4. 连接成功后，创建一个新的 CNode 对象，并将其添加到全局节点列表 vNodes 中，
//    以便由主套接字处理线程进行管理。
// 5. 连接失败时，更新地址的最后失败时间。
//
// @param addrConnect 要连接的目标地址。
// @param nTimeout (可选) 引用计数的超时时间。
// @return CNode* 如果连接成功或已存在，返回指向 CNode 对象的指针；否则返回 NULL。
CNode* ConnectNode(CAddress addrConnect, int64 nTimeout)
{
    if (addrConnect.ip == addrLocalHost.ip)
        return NULL;

    // 查找是否已存在连接
    CNode* pnode = FindNode(addrConnect.ip);
    if (pnode)
    {
        // 如果已存在，增加引用计数并返回
        if (nTimeout != 0)
            pnode->AddRef(nTimeout);
        else
            pnode->AddRef();
        return pnode;
    }

    /// debug print
    printf("trying %s\n", addrConnect.ToString().c_str());

    // 建立新连接
    SOCKET hSocket;
    if (ConnectSocket(addrConnect, hSocket))
    {
        /// debug print
        printf("connected %s\n", addrConnect.ToString().c_str());

        // 添加新节点
        CNode* pnode = new CNode(hSocket, addrConnect, false);
        if (nTimeout != 0)
            pnode->AddRef(nTimeout);
        else
            pnode->AddRef();
        CRITICAL_BLOCK(cs_vNodes)
            vNodes.push_back(pnode);

        // 重置该地址的最后失败时间
        CRITICAL_BLOCK(cs_mapAddresses)
            mapAddresses[addrConnect.GetKey()].nLastFailed = 0;
        return pnode;
    }
    else
    {
        // 连接失败，记录失败时间
        CRITICAL_BLOCK(cs_mapAddresses)
            mapAddresses[addrConnect.GetKey()].nLastFailed = GetTime();
        return NULL;
    }
}

void CNode::Disconnect()
{
    printf("disconnecting node %s\n", addr.ToString().c_str());

    closesocket(hSocket);

    // All of a nodes broadcasts and subscriptions are automatically torn down
    // 所有节点的广播和订阅都会自动解除。
    // when it goes down, so a node has to stay up to keep its broadcast going.
    // 当网络出现故障时，某个节点就必须保持运行状态，以确保其广播功能能够持续进行。

    CRITICAL_BLOCK(cs_mapProducts)
        for (map<uint256, CProduct>::iterator mi = mapProducts.begin(); mi != mapProducts.end();)
            AdvertRemoveSource(this, MSG_PRODUCT, 0, (*(mi++)).second);

    // Cancel subscriptions
    for (unsigned int nChannel = 0; nChannel < vfSubscribe.size(); nChannel++)
        if (vfSubscribe[nChannel])
            CancelSubscribe(nChannel);
}













// 启动套接字处理线程
//
// 这个函数是套接字处理线程的入口点。它在一个无限循环中调用 ThreadSocketHandler2()，
// 并捕获任何可能发生的异常，以确保线程的健壮性。
//
// @param parg 未使用的参数。
void ThreadSocketHandler(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadSocketHandler(parg));

    loop
    {
        vfThreadRunning[0] = true;
        CheckForShutdown(0);
        try
        {
            ThreadSocketHandler2(parg);
        }
        CATCH_PRINT_EXCEPTION("ThreadSocketHandler()")
        vfThreadRunning[0] = false;
        Sleep(5000);
    }
}

// 套接字处理的核心逻辑函数。
// 这个函数是网络处理的主循环。它执行以下关键任务：
// 1. 断开需要关闭的节点（包括重复连接、不活跃的节点等）。
// 2. 使用select()模型来监听所有套接字的可读和可写事件。
// 3. 接受新的传入连接。
// 4. 从可读的套接字接收数据到节点的vRecv缓冲区。
// 5. 将节点vSend缓冲区中的数据发送到可写的套接字。
// 这个函数是整个P2P网络通信的引擎。
// 套接字处理的核心逻辑
//
// 这个函数是网络处理的核心，负责管理所有节点的套接字连接。
// 它使用 select() 模型来监听所有套接字上的I/O事件（读、写、异常）。
//
// 主要功能包括：
// 1. 遍历所有节点，标记需要断开连接的节点。
// 2. 使用 select() 监听所有套接字的可读、可写和异常事件。
// 3. 接受新的入站连接请求。
// 4. 处理现有连接上的数据接收和发送。
//
// @param parg 未使用的参数。
void ThreadSocketHandler2(void* parg)
{
    printf("ThreadSocketHandler started\n");
    SOCKET hListenSocket = *(SOCKET*)parg;
    list<CNode*> vNodesDisconnected;
    int nPrevNodeCount = 0;

    loop
    {
        //
        // Disconnect nodes
        //
        // 断开需要关闭的节点
        CRITICAL_BLOCK(cs_vNodes)
        {
            // Disconnect duplicate connections
            // 断开重复的连接：如果两个节点同时互相连接，IP地址较小的一方会断开其出站连接
            map<unsigned int, CNode*> mapFirst;
            foreach(CNode* pnode, vNodes)
            {
                if (pnode->fDisconnect)
                    continue;
                unsigned int ip = pnode->addr.ip;
                if (mapFirst.count(ip) && addrLocalHost.ip < ip)
                {
                    // In case two nodes connect to each other at once,
                    // the lower ip disconnects its outbound connection
                    CNode* pnodeExtra = mapFirst[ip];

                    if (pnodeExtra->GetRefCount() > (pnodeExtra->fNetworkNode ? 1 : 0))
                        swap(pnodeExtra, pnode);

                    if (pnodeExtra->GetRefCount() <= (pnodeExtra->fNetworkNode ? 1 : 0))
                    {
                        printf("(%d nodes) disconnecting duplicate: %s\n", vNodes.size(), pnodeExtra->addr.ToString().c_str());
                        if (pnodeExtra->fNetworkNode && !pnode->fNetworkNode)
                        {
                            pnode->AddRef();
                            swap(pnodeExtra->fNetworkNode, pnode->fNetworkNode);
                            pnodeExtra->Release();
                        }
                        pnodeExtra->fDisconnect = true;
                    }
                }
                mapFirst[ip] = pnode;
            }

            // Disconnect unused nodes
            // 断开未使用的节点：如果一个节点准备好断开，并且其接收和发送缓冲区都为空，则断开它
            vector<CNode*> vNodesCopy = vNodes;
            foreach(CNode* pnode, vNodesCopy)
            {
                if (pnode->ReadyToDisconnect() && pnode->vRecv.empty() && pnode->vSend.empty())
                {
                    // remove from vNodes
                    vNodes.erase(remove(vNodes.begin(), vNodes.end(), pnode), vNodes.end());
                    pnode->Disconnect();

                    // hold in disconnected pool until all refs are released
                    // 将节点保留在断开连接池中，直到所有引用都被释放
                    pnode->nReleaseTime = max(pnode->nReleaseTime, GetTime() + 5 * 60);
                    if (pnode->fNetworkNode)
                        pnode->Release();
                    vNodesDisconnected.push_back(pnode);
                }
            }

            // Delete disconnected nodes
            // 删除已断开连接的节点：等待所有线程都使用完毕后，再安全地删除节点对象
            list<CNode*> vNodesDisconnectedCopy = vNodesDisconnected;
            foreach(CNode* pnode, vNodesDisconnectedCopy)
            {
                // wait until threads are done using it
                if (pnode->GetRefCount() <= 0)
                {
                    bool fDelete = false;
                    TRY_CRITICAL_BLOCK(pnode->cs_vSend)
                     TRY_CRITICAL_BLOCK(pnode->cs_vRecv)
                      TRY_CRITICAL_BLOCK(pnode->cs_mapRequests)
                       TRY_CRITICAL_BLOCK(pnode->cs_inventory)
                        fDelete = true;
                    if (fDelete)
                    {
                        vNodesDisconnected.remove(pnode);
                        delete pnode;
                    }
                }
            }
        }
        if (vNodes.size() != nPrevNodeCount)
        {
            nPrevNodeCount = vNodes.size();
            MainFrameRepaint();
        }


        //
        // Find which sockets have data to receive
        //
        // 准备 select() 需要的 fd_set，用于I/O多路复用
        struct timeval timeout;
        timeout.tv_sec  = 0;
        timeout.tv_usec = 50000; // 50ms 的超时时间，用于轮询发送缓冲区

        struct fd_set fdsetRecv;
        struct fd_set fdsetSend;
        FD_ZERO(&fdsetRecv);
        FD_ZERO(&fdsetSend);
        SOCKET hSocketMax = 0;
        // 将监听套接字加入到接收 fd_set 中
        FD_SET(hListenSocket, &fdsetRecv);
        hSocketMax = max(hSocketMax, hListenSocket);
        CRITICAL_BLOCK(cs_vNodes)
        {
            // 将所有节点的套接字加入到接收和发送 fd_set 中
            foreach(CNode* pnode, vNodes)
            {
                FD_SET(pnode->hSocket, &fdsetRecv);
                hSocketMax = max(hSocketMax, pnode->hSocket);
                TRY_CRITICAL_BLOCK(pnode->cs_vSend)
                    if (!pnode->vSend.empty())
                        FD_SET(pnode->hSocket, &fdsetSend);
            }
        }

        vfThreadRunning[0] = false;
        // 执行 select()，等待I/O事件
        int nSelect = select(hSocketMax + 1, &fdsetRecv, &fdsetSend, NULL, &timeout);
        vfThreadRunning[0] = true;
        CheckForShutdown(0);
        if (nSelect == SOCKET_ERROR)
        {
            int nErr = WSAGetLastError();
            printf("select failed: %d\n", nErr);
            for (int i = 0; i <= hSocketMax; i++)
            {
                FD_SET(i, &fdsetRecv);
                FD_SET(i, &fdsetSend);
            }
            Sleep(timeout.tv_usec/1000);
        }
        RandAddSeed();

        //// debug print
        //foreach(CNode* pnode, vNodes)
        //{
        //    printf("vRecv = %-5d ", pnode->vRecv.size());
        //    printf("vSend = %-5d    ", pnode->vSend.size());
        //}
        //printf("\n");


        //
        // Accept new connections
        //
        // 接受新的入站连接
        if (FD_ISSET(hListenSocket, &fdsetRecv))
        {
            struct sockaddr_in sockaddr;
            int len = sizeof(sockaddr);
            SOCKET hSocket = accept(hListenSocket, (struct sockaddr*)&sockaddr, &len);
            CAddress addr(sockaddr);
            if (hSocket == INVALID_SOCKET)
            {
                if (WSAGetLastError() != WSAEWOULDBLOCK)
                    printf("ERROR ThreadSocketHandler accept failed: %d\n", WSAGetLastError());
            }
            else
            {
                // 为新连接创建一个CNode对象
                printf("accepted connection from %s\n", addr.ToString().c_str());
                CNode* pnode = new CNode(hSocket, addr, true);
                pnode->AddRef();
                CRITICAL_BLOCK(cs_vNodes)
                    vNodes.push_back(pnode);
            }
        }


        //
        // Service each socket
        //
        vector<CNode*> vNodesCopy;
        CRITICAL_BLOCK(cs_vNodes)
            vNodesCopy = vNodes;
        foreach(CNode* pnode, vNodesCopy)
        {
            CheckForShutdown(0);
            SOCKET hSocket = pnode->hSocket;

            //
            // Receive
            //
            if (FD_ISSET(hSocket, &fdsetRecv))
            {
                TRY_CRITICAL_BLOCK(pnode->cs_vRecv)
                {
                    CDataStream& vRecv = pnode->vRecv;
                    unsigned int nPos = vRecv.size();

                    // typical socket buffer is 8K-64K
                    const unsigned int nBufSize = 0x10000;
                    vRecv.resize(nPos + nBufSize);
                    int nBytes = recv(hSocket, &vRecv[nPos], nBufSize, 0);
                    vRecv.resize(nPos + max(nBytes, 0));
                    if (nBytes == 0)
                    {
                        // socket closed gracefully
                        if (!pnode->fDisconnect)
                            printf("recv: socket closed\n");
                        pnode->fDisconnect = true;
                    }
                    else if (nBytes < 0)
                    {
                        // socket error
                        int nErr = WSAGetLastError();
                        if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS)
                        {
                            if (!pnode->fDisconnect)
                                printf("recv failed: %d\n", nErr);
                            pnode->fDisconnect = true;
                        }
                    }
                }
            }

            //
            // Send
            //
            if (FD_ISSET(hSocket, &fdsetSend))
            {
                TRY_CRITICAL_BLOCK(pnode->cs_vSend)
                {
                    CDataStream& vSend = pnode->vSend;
                    if (!vSend.empty())
                    {
                        int nBytes = send(hSocket, &vSend[0], vSend.size(), 0);
                        if (nBytes > 0)
                        {
                            vSend.erase(vSend.begin(), vSend.begin() + nBytes);
                        }
                        else if (nBytes == 0)
                        {
                            if (pnode->ReadyToDisconnect())
                                pnode->vSend.clear();
                        }
                        else
                        {
                            printf("send error %d\n", nBytes);
                            if (pnode->ReadyToDisconnect())
                                pnode->vSend.clear();
                        }
                    }
                }
            }
        }


        Sleep(10);
    }
}










// 打开新连接线程的入口函数。
// 这个线程负责主动向网络中的其他节点发起连接请求。
// 它在一个无限循环中调用ThreadOpenConnections2，并捕获所有异常，
// 确保线程在遇到错误时能够自动恢复，从而维持节点的网络连接能力。
// 打开新连接线程的入口函数。
// 这个线程负责主动向网络中的其他节点发起连接请求。
// 它在一个无限循环中调用ThreadOpenConnections2，并捕获所有异常，
// 确保线程在遇到错误时能够自动恢复，从而维持节点的网络连接能力。
void ThreadOpenConnections(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadOpenConnections(parg));

    loop
    {
        vfThreadRunning[1] = true;
        CheckForShutdown(1);
        try
        {
            ThreadOpenConnections2(parg);
        }
        CATCH_PRINT_EXCEPTION("ThreadOpenConnections()")
        vfThreadRunning[1] = false;
        Sleep(5000);
    }
}

// 打开新连接的核心逻辑函数。
// 这个函数负责维持节点的出站连接数，确保网络的连通性。
// 它的主要逻辑包括：
// 1. 从地址池中随机选择一个目标地址。
// 2. 检查总连接数是否超过限制，以及是否已经连接到该地址。
// 3. 为了去中心化和连接多样性，避免连接到同一C类IP地址范围内的多个节点。
// 4. 如果满足所有条件，则调用ConnectSocket尝试建立连接。
// 5. 在每次循环之间随机休眠，以避免过于频繁地发起连接。
// 打开新连接的核心逻辑函数。
// 这个函数负责维持节点的出站连接数，确保网络的连通性。
// 它的主要逻辑包括：
// 1. 从地址池中随机选择一个目标地址。
// 2. 检查总连接数是否超过限制，以及是否已经连接到该地址。
// 3. 为了去中心化和连接多样性，避免连接到同一C类IP地址范围内的多个节点。
// 4. 如果满足所有条件，则调用ConnectSocket尝试建立连接。
// 5. 在每次循环之间随机休眠，以避免过于频繁地发起连接。
void ThreadOpenConnections2(void* parg)
{
    printf("ThreadOpenConnections started\n");

    // Initiate network connections
    const int nMaxConnections = 15;
    loop
    {
        // Wait
        vfThreadRunning[1] = false;
        Sleep(500);
        while (vNodes.size() >= nMaxConnections || vNodes.size() >= mapAddresses.size())
        {
            CheckForShutdown(1);
            Sleep(2000);
        }
        vfThreadRunning[1] = true;
        CheckForShutdown(1);


        // Make a list of unique class C's
        unsigned char pchIPCMask[4] = { 0xff, 0xff, 0xff, 0x00 };
        unsigned int nIPCMask = *(unsigned int*)pchIPCMask;
        vector<unsigned int> vIPC;
        CRITICAL_BLOCK(cs_mapAddresses)
        {
            vIPC.reserve(mapAddresses.size());
            unsigned int nPrev = 0;
            foreach(const PAIRTYPE(vector<unsigned char>, CAddress)& item, mapAddresses)
            {
                const CAddress& addr = item.second;
                if (!addr.IsIPv4())
                    continue;

                // Taking advantage of mapAddresses being in sorted order,
                // with IPs of the same class C grouped together.
                unsigned int ipC = addr.ip & nIPCMask;
                if (ipC != nPrev)
                    vIPC.push_back(nPrev = ipC);
            }
        }

        //
        // The IP selection process is designed to limit vulnerability to address flooding.
        // Any class C (a.b.c.?) has an equal chance of being chosen, then an IP is
        // chosen within the class C.  An attacker may be able to allocate many IPs, but
        // they would normally be concentrated in blocks of class C's.  They can hog the
        // attention within their class C, but not the whole IP address space overall.
        // A lone node in a class C will get as much attention as someone holding all 255
        // IPs in another class C.
        //
        bool fSuccess = false;
        int nLimit = vIPC.size();
        while (!fSuccess && nLimit-- > 0)
        {
            // Choose a random class C
            unsigned int ipC = vIPC[GetRand(vIPC.size())];

            // Organize all addresses in the class C by IP
            map<unsigned int, vector<CAddress> > mapIP;
            CRITICAL_BLOCK(cs_mapAddresses)
            {
                unsigned int nDelay = ((30 * 60) << vNodes.size());
                if (nDelay > 8 * 60 * 60)
                    nDelay = 8 * 60 * 60;
                for (map<vector<unsigned char>, CAddress>::iterator mi = mapAddresses.lower_bound(CAddress(ipC, 0).GetKey());
                     mi != mapAddresses.upper_bound(CAddress(ipC | ~nIPCMask, 0xffff).GetKey());
                     ++mi)
                {
                    const CAddress& addr = (*mi).second;
                    unsigned int nRandomizer = (addr.nLastFailed * addr.ip * 7777U) % 20000;
                    if (GetTime() - addr.nLastFailed > nDelay * nRandomizer / 10000)
                        mapIP[addr.ip].push_back(addr);
                }
            }
            if (mapIP.empty())
                break;

            // Choose a random IP in the class C
            map<unsigned int, vector<CAddress> >::iterator mi = mapIP.begin();
            advance(mi, GetRand(mapIP.size()));

            // Once we've chosen an IP, we'll try every given port before moving on
            foreach(const CAddress& addrConnect, (*mi).second)
            {
                if (addrConnect.ip == addrLocalHost.ip || !addrConnect.IsIPv4() || FindNode(addrConnect.ip))
                    continue;

                CNode* pnode = ConnectNode(addrConnect);
                if (!pnode)
                    continue;
                pnode->fNetworkNode = true;

                if (addrLocalHost.IsRoutable())
                {
                    // Advertise our address
                    vector<CAddress> vAddrToSend;
                    vAddrToSend.push_back(addrLocalHost);
                    pnode->PushMessage("addr", vAddrToSend);
                }

                // Get as many addresses as we can
                pnode->PushMessage("getaddr");

                ////// should the one on the receiving end do this too?
                // Subscribe our local subscription list
                const unsigned int nHops = 0;
                for (unsigned int nChannel = 0; nChannel < pnodeLocalHost->vfSubscribe.size(); nChannel++)
                    if (pnodeLocalHost->vfSubscribe[nChannel])
                        pnode->PushMessage("subscribe", nChannel, nHops);

                fSuccess = true;
                break;
            }
        }
    }
}








void ThreadMessageHandler(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadMessageHandler(parg));

    loop
    {
        vfThreadRunning[2] = true;
        CheckForShutdown(2);
        try
        {
            ThreadMessageHandler2(parg);
        }
        CATCH_PRINT_EXCEPTION("ThreadMessageHandler()")
        vfThreadRunning[2] = false;
        Sleep(5000);
    }
}

void ThreadMessageHandler2(void* parg)
{
    printf("ThreadMessageHandler started\n");
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    loop
    {
        // Poll the connected nodes for messages
        vector<CNode*> vNodesCopy;
        CRITICAL_BLOCK(cs_vNodes)
            vNodesCopy = vNodes;
        foreach(CNode* pnode, vNodesCopy)
        {
            pnode->AddRef();

            // Receive messages
            TRY_CRITICAL_BLOCK(pnode->cs_vRecv)
                ProcessMessages(pnode);

            // Send messages
            TRY_CRITICAL_BLOCK(pnode->cs_vSend)
                SendMessages(pnode);

            pnode->Release();
        }

        // Wait and allow messages to bunch up
        vfThreadRunning[2] = false;
        Sleep(100);
        vfThreadRunning[2] = true;
        CheckForShutdown(2);
    }
}









//// todo: start one thread per processor, use getenv("NUMBER_OF_PROCESSORS")
void ThreadBitcoinMiner(void* parg)
{
    vfThreadRunning[3] = true;
    CheckForShutdown(3);
    try
    {
        bool fRet = BitcoinMiner();
        printf("BitcoinMiner returned %s\n\n\n", fRet ? "true" : "false");
    }
    CATCH_PRINT_EXCEPTION("BitcoinMiner()")
    vfThreadRunning[3] = false;
}











bool StartNode(string& strError)
{
    strError = "";

    // Sockets startup
    WSADATA wsadata;
    int ret = WSAStartup(MAKEWORD(2,2), &wsadata);
    if (ret != NO_ERROR)
    {
        strError = strprintf("Error: TCP/IP socket library failed to start (WSAStartup returned error %d)", ret);
        printf("%s\n", strError.c_str());
        return false;
    }

    // Get local host ip
    char pszHostName[255];
    if (gethostname(pszHostName, 255) == SOCKET_ERROR)
    {
        strError = strprintf("Error: Unable to get IP address of this computer (gethostname returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }
    struct hostent* pHostEnt = gethostbyname(pszHostName);
    if (!pHostEnt)
    {
        strError = strprintf("Error: Unable to get IP address of this computer (gethostbyname returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }
    addrLocalHost = CAddress(*(long*)(pHostEnt->h_addr_list[0]),
                             DEFAULT_PORT,
                             nLocalServices);
    printf("addrLocalHost = %s\n", addrLocalHost.ToString().c_str());

    // Create socket for listening for incoming connections
    SOCKET hListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (hListenSocket == INVALID_SOCKET)
    {
        strError = strprintf("Error: Couldn't open socket for incoming connections (socket returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }

    // Set to nonblocking, incoming connections will also inherit this
    u_long nOne = 1;
    if (ioctlsocket(hListenSocket, FIONBIO, &nOne) == SOCKET_ERROR)
    {
        strError = strprintf("Error: Couldn't set properties on socket for incoming connections (ioctlsocket returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }

    // The sockaddr_in structure specifies the address family,
    // IP address, and port for the socket that is being bound
    int nRetryLimit = 15;
    struct sockaddr_in sockaddr = addrLocalHost.GetSockAddr();
    if (bind(hListenSocket, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) == SOCKET_ERROR)
    {
        int nErr = WSAGetLastError();
        if (nErr == WSAEADDRINUSE)
            strError = strprintf("Error: Unable to bind to port %s on this computer. The program is probably already running.", addrLocalHost.ToString().c_str());
        else
            strError = strprintf("Error: Unable to bind to port %s on this computer (bind returned error %d)", addrLocalHost.ToString().c_str(), nErr);
        printf("%s\n", strError.c_str());
        return false;
    }
    printf("bound to addrLocalHost = %s\n\n", addrLocalHost.ToString().c_str());

    // Listen for incoming connections
    if (listen(hListenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        strError = strprintf("Error: Listening for incoming connections failed (listen returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }

    // Get our external IP address for incoming connections
    if (addrIncoming.ip)
        addrLocalHost.ip = addrIncoming.ip;

    if (GetMyExternalIP(addrLocalHost.ip))
    {
        addrIncoming = addrLocalHost;
        CWalletDB().WriteSetting("addrIncoming", addrIncoming);
    }

    // Get addresses from IRC and advertise ours
    if (_beginthread(ThreadIRCSeed, 0, NULL) == -1)
        printf("Error: _beginthread(ThreadIRCSeed) failed\n");

    //
    // Start threads
    //
    if (_beginthread(ThreadSocketHandler, 0, new SOCKET(hListenSocket)) == -1)
    {
        strError = "Error: _beginthread(ThreadSocketHandler) failed";
        printf("%s\n", strError.c_str());
        return false;
    }

    if (_beginthread(ThreadOpenConnections, 0, NULL) == -1)
    {
        strError = "Error: _beginthread(ThreadOpenConnections) failed";
        printf("%s\n", strError.c_str());
        return false;
    }

    if (_beginthread(ThreadMessageHandler, 0, NULL) == -1)
    {
        strError = "Error: _beginthread(ThreadMessageHandler) failed";
        printf("%s\n", strError.c_str());
        return false;
    }

    return true;
}

bool StopNode()
{
    printf("StopNode()\n");
    fShutdown = true;
    nTransactionsUpdated++;
    while (count(vfThreadRunning.begin(), vfThreadRunning.end(), true))
        Sleep(10);
    Sleep(50);

    // Sockets shutdown
    WSACleanup();
    return true;
}

void CheckForShutdown(int n)
{
    if (fShutdown)
    {
        if (n != -1)
            vfThreadRunning[n] = false;
        _endthread();
    }
}
