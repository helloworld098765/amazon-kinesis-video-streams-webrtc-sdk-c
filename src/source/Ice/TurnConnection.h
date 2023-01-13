/*******************************************
TurnConnection internal include file
*******************************************/
#ifndef __KINESIS_VIDEO_WEBRTC_CLIENT_TURN_CONNECTION__
#define __KINESIS_VIDEO_WEBRTC_CLIENT_TURN_CONNECTION__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
// udp 协议
#define TURN_REQUEST_TRANSPORT_UDP               17
// tcp 协议
#define TURN_REQUEST_TRANSPORT_TCP               6
// allocation 存活时间
#define DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS 600
// required by rfc5766 to be 300s

// 许可存活时间
#define TURN_PERMISSION_LIFETIME                 (300 * HUNDREDS_OF_NANOS_IN_A_SECOND)
#define DEFAULT_TURN_TIMER_INTERVAL_BEFORE_READY (50 * HUNDREDS_OF_NANOS_IN_A_MILLISECOND)
#define DEFAULT_TURN_TIMER_INTERVAL_AFTER_READY  (1 * HUNDREDS_OF_NANOS_IN_A_SECOND)
#define DEFAULT_TURN_SEND_REFRESH_INVERVAL       (1 * HUNDREDS_OF_NANOS_IN_A_SECOND)

// turn state timeouts
// socket连接超时时间
#define DEFAULT_TURN_SOCKET_CONNECT_TIMEOUT    (5 * HUNDREDS_OF_NANOS_IN_A_SECOND)
// 获取
#define DEFAULT_TURN_GET_CREDENTIAL_TIMEOUT    (5 * HUNDREDS_OF_NANOS_IN_A_SECOND)
// 获取
#define DEFAULT_TURN_ALLOCATION_TIMEOUT        (5 * HUNDREDS_OF_NANOS_IN_A_SECOND)
// 创建许可超时时间
#define DEFAULT_TURN_CREATE_PERMISSION_TIMEOUT (2 * HUNDREDS_OF_NANOS_IN_A_SECOND)
// 绑定DataChannel超时时间
#define DEFAULT_TURN_BIND_CHANNEL_TIMEOUT      (3 * HUNDREDS_OF_NANOS_IN_A_SECOND)

// 清理超时时间
#define DEFAULT_TURN_CLEAN_UP_TIMEOUT          (10 * HUNDREDS_OF_NANOS_IN_A_SECOND)

// allocation 刷新周期
#define DEFAULT_TURN_ALLOCATION_REFRESH_GRACE_PERIOD (30 * HUNDREDS_OF_NANOS_IN_A_SECOND)
// 许可刷新周期
#define DEFAULT_TURN_PERMISSION_REFRESH_GRACE_PERIOD (30 * HUNDREDS_OF_NANOS_IN_A_SECOND)

// Channel Data Message 最大值
#define MAX_TURN_CHANNEL_DATA_MESSAGE_SIZE                4 + 65536 /* header + data */

// 发送数据Buffer 大小
#define DEFAULT_TURN_MESSAGE_SEND_CHANNEL_DATA_BUFFER_LEN MAX_TURN_CHANNEL_DATA_MESSAGE_SIZE
// 接受数据Buffer 大小
#define DEFAULT_TURN_MESSAGE_RECV_CHANNEL_DATA_BUFFER_LEN MAX_TURN_CHANNEL_DATA_MESSAGE_SIZE
// 
#define DEFAULT_TURN_CHANNEL_DATA_BUFFER_SIZE             512
// 最大peer数量
#define DEFAULT_TURN_MAX_PEER_COUNT                       32

// all turn channel numbers must be greater than 0x4000 and less than 0x7FFF
// 0x0000 ~ 0x3FFF 永远不用于channel number
// 0x4000 ~ 0x7FFF (16383个)用于channel number
// 0x8000 ~ 0xFFFF 保留，将来使用

// 2字节channel number 必须大于0x4000 小于 0x7fff
#define TURN_CHANNEL_BIND_CHANNEL_NUMBER_BASE (UINT16) 0x4000

// 2 byte channel number 2 data byte size
// 4字节开销
// 3~4字节表示数据长度，不包含头，0 为有效长度
#define TURN_DATA_CHANNEL_SEND_OVERHEAD  4
#define TURN_DATA_CHANNEL_MSG_FIRST_BYTE 0x40

#define TURN_STATE_NEW_STR                     (PCHAR) "TURN_STATE_NEW"
#define TURN_STATE_CHECK_SOCKET_CONNECTION_STR (PCHAR) "TURN_STATE_CHECK_SOCKET_CONNECTION"
#define TURN_STATE_GET_CREDENTIALS_STR         (PCHAR) "TURN_STATE_GET_CREDENTIALS"
#define TURN_STATE_ALLOCATION_STR              (PCHAR) "TURN_STATE_ALLOCATION"
#define TURN_STATE_CREATE_PERMISSION_STR       (PCHAR) "TURN_STATE_CREATE_PERMISSION"
#define TURN_STATE_BIND_CHANNEL_STR            (PCHAR) "TURN_STATE_BIND_CHANNEL"
#define TURN_STATE_READY_STR                   (PCHAR) "TURN_STATE_READY"
#define TURN_STATE_CLEAN_UP_STR                (PCHAR) "TURN_STATE_CLEAN_UP"
#define TURN_STATE_FAILED_STR                  (PCHAR) "TURN_STATE_FAILED"
#define TURN_STATE_UNKNOWN_STR                 (PCHAR) "TURN_STATE_UNKNOWN"

typedef STATUS (*RelayAddressAvailableFunc)(UINT64, PKvsIpAddress, PSocketConnection);

// Turn 连接状态
typedef enum {
    // 新建
    TURN_STATE_NEW,
    // 检查socket 连接
    TURN_STATE_CHECK_SOCKET_CONNECTION,
    // 获取凭证
    TURN_STATE_GET_CREDENTIALS,
    // allocation
    TURN_STATE_ALLOCATION,
    // 创建许可
    TURN_STATE_CREATE_PERMISSION,
    // 绑定DataChannel
    TURN_STATE_BIND_CHANNEL,
    // 就绪
    TURN_STATE_READY,
    // 清理
    TURN_STATE_CLEAN_UP,
    // 错误
    TURN_STATE_FAILED,
} TURN_CONNECTION_STATE;

// Turn 对端连接状态
typedef enum {
    // 创建许可
    TURN_PEER_CONN_STATE_CREATE_PERMISSION,
    // 绑定DataChannel
    TURN_PEER_CONN_STATE_BIND_CHANNEL,
    // 就绪
    TURN_PEER_CONN_STATE_READY,
    // 错误
    TURN_PEER_CONN_STATE_FAILED,
} TURN_PEER_CONNECTION_STATE;

// Turn 数据发送模式
typedef enum {
    // 通过send indidation 开销较大， 36字节开销
    TURN_CONNECTION_DATA_TRANSFER_MODE_SEND_INDIDATION,
    // 通过DataChannel, 开销较小4字节头
    // channel number 2bytes
    // length 2bytes
    TURN_CONNECTION_DATA_TRANSFER_MODE_DATA_CHANNEL,
} TURN_CONNECTION_DATA_TRANSFER_MODE;

// Turn DataChannelData
typedef struct {
    PBYTE data;
    UINT32 size;
    KvsIpAddress senderAddr;
} TurnChannelData, *PTurnChannelData;

// turn 连接回调
typedef struct {
    UINT64 customData;
    RelayAddressAvailableFunc relayAddressAvailableFn;  //中继地址可用回调
} TurnConnectionCallbacks, *PTurnConnectionCallbacks;

// Turn Peer
typedef struct {
    KvsIpAddress address;
    KvsIpAddress xorAddress;    // Turn 服务器看到的对端地址
    /*
     * Steps to create a turn channel for a peer:
     *     - create permission
     *     - channel bind
     *     - ready to send data
     */
    TURN_PEER_CONNECTION_STATE connectionState; // 连接状态
    PTransactionIdStore pTransactionIdStore;    // 事务ID Store
    UINT16 channelNumber;
    UINT64 permissionExpirationTime;    // 许可过期时间
    BOOL ready;
} TurnPeer, *PTurnPeer;

// Turn 连接
typedef struct __TurnConnection TurnConnection;
struct __TurnConnection {
    volatile ATOMIC_BOOL stopTurnConnection;
    /* shutdown is complete when turn socket is closed */
    volatile ATOMIC_BOOL shutdownComplete;
    volatile ATOMIC_BOOL hasAllocation;
    volatile SIZE_T timerCallbackId;

    // realm attribute in Allocation response
    // 一个字符串，用于描述服务器或服务器中的一个上下文。
    // 告诉客户端哪一个用户名和密码组合来验证请求。
    CHAR turnRealm[STUN_MAX_REALM_LEN + 1];
    // 一个由服务器随机选择的字符串，包含在信息加密。  为了防止重放攻击，服务器应定期改变nonce
    BYTE turnNonce[STUN_MAX_NONCE_LEN];
    UINT16 nonceLen;
    BYTE longTermKey[KVS_MD5_DIGEST_LENGTH];
    BOOL credentialObtained;
    BOOL relayAddressReported;

    PSocketConnection pControlChannel;

    // Turn PeerList
    TurnPeer turnPeerList[DEFAULT_TURN_MAX_PEER_COUNT];
    UINT32 turnPeerCount;

    TIMER_QUEUE_HANDLE timerQueueHandle;

    IceServer turnServer;

    MUTEX lock;
    MUTEX sendLock;
    CVAR freeAllocationCvar;

    TURN_CONNECTION_STATE state;

    UINT64 stateTimeoutTime;

    STATUS errorStatus;

    PStunPacket pTurnPacket;
    // 许可
    PStunPacket pTurnCreatePermissionPacket;
    // DataChannel
    PStunPacket pTurnChannelBindPacket;
    // Allocation Refresh
    PStunPacket pTurnAllocationRefreshPacket;

    KvsIpAddress hostAddress;

    // 中继地址
    KvsIpAddress relayAddress;

    PConnectionListener pConnectionListener;

    TURN_CONNECTION_DATA_TRANSFER_MODE dataTransferMode;
    KVS_SOCKET_PROTOCOL protocol;

    TurnConnectionCallbacks turnConnectionCallbacks;

    // 发送数据Buffer
    PBYTE sendDataBuffer;
    UINT32 dataBufferSize;

    // 接收数据Buffer
    PBYTE recvDataBuffer;
    UINT32 recvDataBufferSize;
    UINT32 currRecvDataLen;
    // when a complete channel data have been assembled in recvDataBuffer, move it to completeChannelDataBuffer
    // to make room for subsequent partial channel data.
    // 当一个完整的channel data在recvDataBuffer中时，将其移至completeChannelDataBuffer
    PBYTE completeChannelDataBuffer;

    // allocation 过期时间
    UINT64 allocationExpirationTime;
    // 下一次刷新allocation时间
    UINT64 nextAllocationRefreshTime;

    UINT64 currentTimerCallingPeriod;
    BOOL deallocatePacketSent;
};
typedef struct __TurnConnection* PTurnConnection;

STATUS createTurnConnection(PIceServer, TIMER_QUEUE_HANDLE, TURN_CONNECTION_DATA_TRANSFER_MODE, KVS_SOCKET_PROTOCOL, PTurnConnectionCallbacks,
                            PSocketConnection, PConnectionListener, PTurnConnection*);
STATUS freeTurnConnection(PTurnConnection*);
STATUS turnConnectionAddPeer(PTurnConnection, PKvsIpAddress);
STATUS turnConnectionSendData(PTurnConnection, PBYTE, UINT32, PKvsIpAddress);
STATUS turnConnectionStart(PTurnConnection);
STATUS turnConnectionShutdown(PTurnConnection, UINT64);
BOOL turnConnectionIsShutdownComplete(PTurnConnection);
BOOL turnConnectionGetRelayAddress(PTurnConnection, PKvsIpAddress);
STATUS turnConnectionRefreshAllocation(PTurnConnection);
STATUS turnConnectionRefreshPermission(PTurnConnection, PBOOL);
STATUS turnConnectionFreePreAllocatedPackets(PTurnConnection);

STATUS turnConnectionStepState(PTurnConnection);
STATUS turnConnectionUpdateNonce(PTurnConnection);
STATUS turnConnectionTimerCallback(UINT32, UINT64, UINT64);
STATUS turnConnectionGetLongTermKey(PCHAR, PCHAR, PCHAR, PBYTE, UINT32);
STATUS turnConnectionPackageTurnAllocationRequest(PCHAR, PCHAR, PBYTE, UINT16, UINT32, PStunPacket*);
PCHAR turnConnectionGetStateStr(TURN_CONNECTION_STATE);

STATUS turnConnectionIncomingDataHandler(PTurnConnection, PBYTE, UINT32, PKvsIpAddress, PKvsIpAddress, PTurnChannelData, PUINT32);

STATUS turnConnectionHandleStun(PTurnConnection, PBYTE, UINT32);
STATUS turnConnectionHandleStunError(PTurnConnection, PBYTE, UINT32);
STATUS turnConnectionHandleChannelData(PTurnConnection, PBYTE, UINT32, PTurnChannelData, PUINT32, PUINT32);
STATUS turnConnectionHandleChannelDataTcpMode(PTurnConnection, PBYTE, UINT32, PTurnChannelData, PUINT32, PUINT32);
VOID turnConnectionFatalError(PTurnConnection, STATUS);

PTurnPeer turnConnectionGetPeerWithChannelNumber(PTurnConnection, UINT16);
PTurnPeer turnConnectionGetPeerWithIp(PTurnConnection, PKvsIpAddress);

#ifdef __cplusplus
}
#endif
#endif /* __KINESIS_VIDEO_WEBRTC_CLIENT_TURN_CONNECTION__ */
