/**
 * Kinesis Video Producer Ice Utils
 */
#define LOG_CLASS "IceUtils"
#include "../Include_i.h"

// 创建TransactionIdStore
STATUS createTransactionIdStore(UINT32 maxIdCount, PTransactionIdStore* ppTransactionIdStore)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PTransactionIdStore pTransactionIdStore = NULL;

    CHK(ppTransactionIdStore != NULL, STATUS_NULL_ARG);
    CHK(maxIdCount < MAX_STORED_TRANSACTION_ID_COUNT && maxIdCount > 0, STATUS_INVALID_ARG);

    // 分配内存
    pTransactionIdStore = (PTransactionIdStore) MEMCALLOC(1, SIZEOF(TransactionIdStore) + STUN_TRANSACTION_ID_LEN * maxIdCount);
    CHK(pTransactionIdStore != NULL, STATUS_NOT_ENOUGH_MEMORY);

    // 设置transactionIds位置、maxTransactionIdsCount
    pTransactionIdStore->transactionIds = (PBYTE) (pTransactionIdStore + 1);
    pTransactionIdStore->maxTransactionIdsCount = maxIdCount;

CleanUp:

    // 回收pTransactionIdStore资源
    if (STATUS_FAILED(retStatus) && pTransactionIdStore != NULL) {
        MEMFREE(pTransactionIdStore);
        pTransactionIdStore = NULL;
    }

    if (ppTransactionIdStore != NULL) {
        *ppTransactionIdStore = pTransactionIdStore;
    }

    LEAVES();
    return retStatus;
}

// 回收TransactionIdStore资源
STATUS freeTransactionIdStore(PTransactionIdStore* ppTransactionIdStore)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PTransactionIdStore pTransactionIdStore = NULL;

    CHK(ppTransactionIdStore != NULL, STATUS_NULL_ARG);
    pTransactionIdStore = *ppTransactionIdStore;
    CHK(pTransactionIdStore != NULL, retStatus);

    // 回收内存
    SAFE_MEMFREE(pTransactionIdStore);

    *ppTransactionIdStore = NULL;

CleanUp:

    LEAVES();
    return retStatus;
}

// 插入transactionId
VOID transactionIdStoreInsert(PTransactionIdStore pTransactionIdStore, PBYTE transactionId)
{
    PBYTE storeLocation = NULL;

    CHECK(pTransactionIdStore != NULL);

    // 查找插入ID的储存位置
    storeLocation = pTransactionIdStore->transactionIds +
        ((pTransactionIdStore->nextTransactionIdIndex % pTransactionIdStore->maxTransactionIdsCount) * STUN_TRANSACTION_ID_LEN);
    // 插入ID
    MEMCPY(storeLocation, transactionId, STUN_TRANSACTION_ID_LEN);

    pTransactionIdStore->nextTransactionIdIndex = (pTransactionIdStore->nextTransactionIdIndex + 1) % pTransactionIdStore->maxTransactionIdsCount;

    // 缓冲区已满，淘汰第1个
    if (pTransactionIdStore->nextTransactionIdIndex == pTransactionIdStore->earliestTransactionIdIndex) {
        pTransactionIdStore->earliestTransactionIdIndex =
            (pTransactionIdStore->earliestTransactionIdIndex + 1) % pTransactionIdStore->maxTransactionIdsCount;
    }

    pTransactionIdStore->transactionIdCount = MIN(pTransactionIdStore->transactionIdCount + 1, pTransactionIdStore->maxTransactionIdsCount);
}

// 是否存在transactionId
BOOL transactionIdStoreHasId(PTransactionIdStore pTransactionIdStore, PBYTE transactionId)
{
    BOOL idFound = FALSE;
    UINT32 i, j;

    CHECK(pTransactionIdStore != NULL);


    for (i = pTransactionIdStore->earliestTransactionIdIndex, j = 0; j < pTransactionIdStore->maxTransactionIdsCount && !idFound; ++j) {
        if (MEMCMP(transactionId, pTransactionIdStore->transactionIds + i * STUN_TRANSACTION_ID_LEN, STUN_TRANSACTION_ID_LEN) == 0) {
            idFound = TRUE;
        }

        i = (i + 1) % pTransactionIdStore->maxTransactionIdsCount;
    }

    return idFound;
}

// 删除事务ID
VOID transactionIdStoreRemove(PTransactionIdStore pTransactionIdStore, PBYTE transactionId)
{
    UINT32 i, j;

    CHECK(pTransactionIdStore != NULL);

    for (i = pTransactionIdStore->earliestTransactionIdIndex, j = 0; j < pTransactionIdStore->maxTransactionIdsCount; ++j) {
        // 删除事务ID
        if (MEMCMP(transactionId, pTransactionIdStore->transactionIds + i * STUN_TRANSACTION_ID_LEN, STUN_TRANSACTION_ID_LEN) == 0) {
            MEMSET(pTransactionIdStore->transactionIds + i * STUN_TRANSACTION_ID_LEN, 0x00, STUN_TRANSACTION_ID_LEN);
            return;
        }

        i = (i + 1) % pTransactionIdStore->maxTransactionIdsCount;
    }
}

// 删除所有事务ID
VOID transactionIdStoreClear(PTransactionIdStore pTransactionIdStore)
{
    CHECK(pTransactionIdStore != NULL);

    pTransactionIdStore->nextTransactionIdIndex = 0;
    pTransactionIdStore->earliestTransactionIdIndex = 0;
    pTransactionIdStore->transactionIdCount = 0;
}

// 生成事务ID
STATUS iceUtilsGenerateTransactionId(PBYTE pBuffer, UINT32 bufferLen)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 i;

    CHK(pBuffer != NULL, STATUS_NULL_ARG);
    CHK(bufferLen == STUN_TRANSACTION_ID_LEN, STATUS_INVALID_ARG);

    for (i = 0; i < STUN_TRANSACTION_ID_LEN; ++i) {
        pBuffer[i] = ((BYTE) (RAND() % 0x100));
    }

CleanUp:

    return retStatus;
}

// 打包StunPacket
STATUS iceUtilsPackageStunPacket(PStunPacket pStunPacket, PBYTE password, UINT32 passwordLen, PBYTE pBuffer, PUINT32 pBufferLen)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 stunPacketSize = 0;
    BOOL addMessageIntegrity = FALSE;

    CHK(pStunPacket != NULL && pBuffer != NULL && pBufferLen != NULL, STATUS_NULL_ARG);
    CHK((password == NULL && passwordLen == 0) || (password != NULL && passwordLen > 0), STATUS_INVALID_ARG);

    if (password != NULL) {
        addMessageIntegrity = TRUE;
    }

    CHK_STATUS(serializeStunPacket(pStunPacket, password, passwordLen, addMessageIntegrity, TRUE, NULL, &stunPacketSize));
    CHK(stunPacketSize <= *pBufferLen, STATUS_BUFFER_TOO_SMALL);

    // 序列化StunPacket 结构体-->pBuffer
    CHK_STATUS(serializeStunPacket(pStunPacket, password, passwordLen, addMessageIntegrity, TRUE, pBuffer, &stunPacketSize));
    *pBufferLen = stunPacketSize;

CleanUp:

    CHK_LOG_ERR(retStatus);

    return retStatus;
}

// 发送StunPacket
STATUS iceUtilsSendStunPacket(PStunPacket pStunPacket, PBYTE password, UINT32 passwordLen, PKvsIpAddress pDest, PSocketConnection pSocketConnection,
                              PTurnConnection pTurnConnection, BOOL useTurn)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 stunPacketSize = STUN_PACKET_ALLOCATION_SIZE;
    BYTE stunPacketBuffer[STUN_PACKET_ALLOCATION_SIZE];

    // 打包StunPacket
    CHK_STATUS(iceUtilsPackageStunPacket(pStunPacket, password, passwordLen, stunPacketBuffer, &stunPacketSize));
    // 发送数据
    CHK_STATUS(iceUtilsSendData(stunPacketBuffer, stunPacketSize, pDest, pSocketConnection, pTurnConnection, useTurn));

CleanUp:

    CHK_LOG_ERR(retStatus);

    return retStatus;
}


// IceUtils发送数据
STATUS iceUtilsSendData(PBYTE buffer, UINT32 size, PKvsIpAddress pDest, PSocketConnection pSocketConnection, PTurnConnection pTurnConnection,
                        BOOL useTurn)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK((pSocketConnection != NULL && !useTurn) || (pTurnConnection != NULL && useTurn), STATUS_INVALID_ARG);

    // 使用turn服务器
    if (useTurn) {
        retStatus = turnConnectionSendData(pTurnConnection, buffer, size, pDest);
    } else {
        retStatus = socketConnectionSendData(pSocketConnection, buffer, size, pDest);
    }

    // Fix-up the not-yet-ready socket
    CHK(STATUS_SUCCEEDED(retStatus) || retStatus == STATUS_SOCKET_CONNECTION_NOT_READY_TO_SEND, retStatus);
    retStatus = STATUS_SUCCESS;

CleanUp:

    CHK_LOG_ERR(retStatus);

    return retStatus;
}


//[
//  {
//    "urls": "stun:stun.kinesisvideo.ap-northeast-1.amazonaws.com:443"
//  },
//  {
//    "urls": [
//      "turn:3-112-13-13.t-66166e.kinesisvideo.ap-northeast-1.amazonaws.com:443?transport=udp",
//      "turns:3-112-13-13.t-66166e.kinesisvideo.ap-northeast-1.amazonaws.com:443?transport=udp",
//      "turns:3-112-13-13.t-6866e.kinesisvideo.ap-northeast-1.amazonaws.com:443?transport=tcp"
//    ],
//    "username": "1673429702:djE6YXJuOmF3czpraW5lc2lzdmlfsdfdsfXAtbm9ydGhlYXN0LTE6NDEyMjY5MjE1OTUxOmNoYW5uZWwvaGVsbfgvdgM5MDA3MjMyOA==",
//    "credential": "x5YqU1lnrGxZFsfdfsdfsfMgsdfgdsdugRBCaMY6Ko="
//  },
//  {
//    "urls": [
//      "turn:8-13-42-89.t-12.kinesisvideo.ap-northeast-1.amazonaws.com:443?transport=udp",
//      "turns:8-13-42-89.t-122.kinesisvideo.ap-northeast-1.amazonaws.com:443?transport=udp",
//      "turns:8-13-42-89.t-212.kinesisvideo.ap-northeast-1.amazonaws.com:443?transport=tcp"
//    ],
//    "username": "1673429702:djE6YXgdsgdfgdffsdfsdfsdfdsydGhlYXN0LTE6NDEyMjY5MjE1OTUxOdfgdWwvaGVsbG8vMTY3MDM5MdsfefryOA==",
//    "credential": "QsuSdgsdfgdlQj7sdfsfsdfIS77gTdfULD3oT1g="
//  }
//]

// stun:stun.kinesisvideo.ap-northeast-1.amazonaws.com:443
// 解析IceServer
STATUS parseIceServer(PIceServer pIceServer, PCHAR url, PCHAR username, PCHAR credential)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PCHAR separator = NULL, urlNoPrefix = NULL, paramStart = NULL;
    UINT32 port = ICE_STUN_DEFAULT_PORT;

    // username and credential is only mandatory for turn server
    CHK(url != NULL && pIceServer != NULL, STATUS_NULL_ARG);

    // stun
    if (STRNCMP(ICE_URL_PREFIX_STUN, url, STRLEN(ICE_URL_PREFIX_STUN)) == 0) {
        urlNoPrefix = STRCHR(url, ':') + 1;
        pIceServer->isTurn = FALSE;
    }
    // turn or turns
    else if (STRNCMP(ICE_URL_PREFIX_TURN, url, STRLEN(ICE_URL_PREFIX_TURN)) == 0 ||
               STRNCMP(ICE_URL_PREFIX_TURN_SECURE, url, STRLEN(ICE_URL_PREFIX_TURN_SECURE)) == 0) {
        CHK(username != NULL && username[0] != '\0', STATUS_ICE_URL_TURN_MISSING_USERNAME);
        CHK(credential != NULL && credential[0] != '\0', STATUS_ICE_URL_TURN_MISSING_CREDENTIAL);

        // TODO after getIceServerConfig no longer give turn: ips, do TLS only for turns:
        STRNCPY(pIceServer->username, username, MAX_ICE_CONFIG_USER_NAME_LEN);
        STRNCPY(pIceServer->credential, credential, MAX_ICE_CONFIG_CREDENTIAL_LEN);
        urlNoPrefix = STRCHR(url, ':') + 1;
        pIceServer->isTurn = TRUE;
        pIceServer->isSecure = STRNCMP(ICE_URL_PREFIX_TURN_SECURE, url, STRLEN(ICE_URL_PREFIX_TURN_SECURE)) == 0;

        pIceServer->transport = KVS_SOCKET_PROTOCOL_NONE;
        // 设置传输协议
        if (STRSTR(url, ICE_URL_TRANSPORT_UDP) != NULL) {
            pIceServer->transport = KVS_SOCKET_PROTOCOL_UDP;
        } else if (STRSTR(url, ICE_URL_TRANSPORT_TCP) != NULL) {
            pIceServer->transport = KVS_SOCKET_PROTOCOL_TCP;
        }

    } else {
        CHK(FALSE, STATUS_ICE_URL_INVALID_PREFIX);
    }

    // 有第二个:
    if ((separator = STRCHR(urlNoPrefix, ':')) != NULL) {
        separator++;
        paramStart = STRCHR(urlNoPrefix, '?');
        // 端口
        CHK_STATUS(STRTOUI32(separator, paramStart, 10, &port));
        // url
        STRNCPY(pIceServer->url, urlNoPrefix, separator - urlNoPrefix - 1);
        // need to null terminate since we are not copying the entire urlNoPrefix
        // 设置字符串结尾
        pIceServer->url[separator - urlNoPrefix - 1] = '\0';
    }
    // 没有第二个:
    else {
        STRNCPY(pIceServer->url, urlNoPrefix, MAX_ICE_CONFIG_URI_LEN);
    }

    // 获取hostname IPAddress
    CHK_STATUS(getIpWithHostName(pIceServer->url, &pIceServer->ipAddress));
    pIceServer->ipAddress.port = (UINT16) getInt16((INT16) port);

CleanUp:

    LEAVES();

    return retStatus;
}
