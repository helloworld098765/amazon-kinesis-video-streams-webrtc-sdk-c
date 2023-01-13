/**
 * Kinesis Video TurnConnection
 */
#define LOG_CLASS "TurnConnection"
#include "../Include_i.h"

// 创建TurnConnection
STATUS createTurnConnection(PIceServer pTurnServer, TIMER_QUEUE_HANDLE timerQueueHandle, TURN_CONNECTION_DATA_TRANSFER_MODE dataTransferMode,
                            KVS_SOCKET_PROTOCOL protocol, PTurnConnectionCallbacks pTurnConnectionCallbacks, PSocketConnection pTurnSocket,
                            PConnectionListener pConnectionListener, PTurnConnection* ppTurnConnection)
{
    UNUSED_PARAM(dataTransferMode);
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PTurnConnection pTurnConnection = NULL;

    CHK(pTurnServer != NULL && ppTurnConnection != NULL && pTurnSocket != NULL, STATUS_NULL_ARG);
    CHK(IS_VALID_TIMER_QUEUE_HANDLE(timerQueueHandle), STATUS_INVALID_ARG);
    CHK(pTurnServer->isTurn && !IS_EMPTY_STRING(pTurnServer->url) && !IS_EMPTY_STRING(pTurnServer->credential) &&
            !IS_EMPTY_STRING(pTurnServer->username),
        STATUS_INVALID_ARG);

    // 分配内存
    pTurnConnection = (PTurnConnection) MEMCALLOC(
        1, SIZEOF(TurnConnection) + DEFAULT_TURN_MESSAGE_RECV_CHANNEL_DATA_BUFFER_LEN * 2 + DEFAULT_TURN_MESSAGE_SEND_CHANNEL_DATA_BUFFER_LEN);
    CHK(pTurnConnection != NULL, STATUS_NOT_ENOUGH_MEMORY);

    // 创建锁
    pTurnConnection->lock = MUTEX_CREATE(FALSE);
    pTurnConnection->sendLock = MUTEX_CREATE(FALSE);
    // 创建条件变量
    pTurnConnection->freeAllocationCvar = CVAR_CREATE();
    pTurnConnection->timerQueueHandle = timerQueueHandle;
    // 设置turn Server
    pTurnConnection->turnServer = *pTurnServer;
    // 设置TurnConnection转态为NEW
    pTurnConnection->state = TURN_STATE_NEW;
    pTurnConnection->stateTimeoutTime = INVALID_TIMESTAMP_VALUE;
    pTurnConnection->errorStatus = STATUS_SUCCESS;
    pTurnConnection->timerCallbackId = MAX_UINT32;
    pTurnConnection->pTurnPacket = NULL;
    pTurnConnection->pTurnChannelBindPacket = NULL;
    pTurnConnection->pConnectionListener = pConnectionListener;
    pTurnConnection->dataTransferMode =
        TURN_CONNECTION_DATA_TRANSFER_MODE_DATA_CHANNEL; // only TURN_CONNECTION_DATA_TRANSFER_MODE_DATA_CHANNEL for now
    // 协议
    pTurnConnection->protocol = protocol;
    pTurnConnection->relayAddressReported = FALSE;
    pTurnConnection->pControlChannel = pTurnSocket;

    // 设置标志
    ATOMIC_STORE_BOOL(&pTurnConnection->stopTurnConnection, FALSE);
    ATOMIC_STORE_BOOL(&pTurnConnection->hasAllocation, FALSE);
    ATOMIC_STORE_BOOL(&pTurnConnection->shutdownComplete, FALSE);

    if (pTurnConnectionCallbacks != NULL) {
        pTurnConnection->turnConnectionCallbacks = *pTurnConnectionCallbacks;
    }
    // 设置buffer地址、大小
    pTurnConnection->recvDataBufferSize = DEFAULT_TURN_MESSAGE_RECV_CHANNEL_DATA_BUFFER_LEN;
    pTurnConnection->dataBufferSize = DEFAULT_TURN_MESSAGE_SEND_CHANNEL_DATA_BUFFER_LEN;
    pTurnConnection->sendDataBuffer = (PBYTE) (pTurnConnection + 1);
    pTurnConnection->recvDataBuffer = pTurnConnection->sendDataBuffer + pTurnConnection->dataBufferSize;
    pTurnConnection->completeChannelDataBuffer =
        pTurnConnection->sendDataBuffer + pTurnConnection->dataBufferSize + pTurnConnection->recvDataBufferSize;
    pTurnConnection->currRecvDataLen = 0;

    // 设置时间
    pTurnConnection->allocationExpirationTime = INVALID_TIMESTAMP_VALUE;
    pTurnConnection->nextAllocationRefreshTime = 0;
    pTurnConnection->currentTimerCallingPeriod = DEFAULT_TURN_TIMER_INTERVAL_BEFORE_READY;

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (STATUS_FAILED(retStatus) && pTurnConnection != NULL) {
        freeTurnConnection(&pTurnConnection);
    }

    if (ppTurnConnection != NULL) {
        *ppTurnConnection = pTurnConnection;
    }

    LEAVES();
    return retStatus;
}

// 回收TurnConnection资源
STATUS freeTurnConnection(PTurnConnection* ppTurnConnection)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PTurnConnection pTurnConnection = NULL;
    PTurnPeer pTurnPeer = NULL;
    SIZE_T timerCallbackId;
    UINT32 i;

    CHK(ppTurnConnection != NULL, STATUS_NULL_ARG);
    // free is idempotent
    CHK(*ppTurnConnection != NULL, retStatus);

    pTurnConnection = *ppTurnConnection;

    timerCallbackId = ATOMIC_EXCHANGE(&pTurnConnection->timerCallbackId, MAX_UINT32);
    
    // 取消定时器
    if (timerCallbackId != MAX_UINT32) {
        CHK_LOG_ERR(timerQueueCancelTimer(pTurnConnection->timerQueueHandle, (UINT32) timerCallbackId, (UINT64) pTurnConnection));
    }

    // shutdown control channel
    // 关闭控制通道
    if (pTurnConnection->pControlChannel) {
        // 移除socketListener
        CHK_LOG_ERR(connectionListenerRemoveConnection(pTurnConnection->pConnectionListener, pTurnConnection->pControlChannel));
        // 回收socketConnection
        CHK_LOG_ERR(freeSocketConnection(&pTurnConnection->pControlChannel));
    }

    // free transactionId store for each turn peer
    // 回收事务ID Store
    for (i = 0; i < pTurnConnection->turnPeerCount; ++i) {
        pTurnPeer = &pTurnConnection->turnPeerList[i];
        freeTransactionIdStore(&pTurnPeer->pTransactionIdStore);
    }

    //以防某些线程在轮流调用api的过程中
    if (IS_VALID_MUTEX_VALUE(pTurnConnection->lock)) {
        /* in case some thread is in the middle of a turn api call. */
        MUTEX_LOCK(pTurnConnection->lock);
        MUTEX_UNLOCK(pTurnConnection->lock);
        MUTEX_FREE(pTurnConnection->lock);
    }

    if (IS_VALID_MUTEX_VALUE(pTurnConnection->sendLock)) {
        /* in case some thread is in the middle of a turn api call. */
        MUTEX_LOCK(pTurnConnection->sendLock);
        MUTEX_UNLOCK(pTurnConnection->sendLock);
        MUTEX_FREE(pTurnConnection->sendLock);
    }

    // 释放条件变量
    if (IS_VALID_CVAR_VALUE(pTurnConnection->freeAllocationCvar)) {
        CVAR_FREE(pTurnConnection->freeAllocationCvar);
    }

    // 回收AllocationPackets
    turnConnectionFreePreAllocatedPackets(pTurnConnection);

    // 回收TurnConnection资源
    MEMFREE(pTurnConnection);

    *ppTurnConnection = NULL;

CleanUp:

    CHK_LOG_ERR(retStatus);

    LEAVES();
    return retStatus;
}

// turnConnection IncomingData处理器
STATUS turnConnectionIncomingDataHandler(PTurnConnection pTurnConnection, PBYTE pBuffer, UINT32 bufferLen, PKvsIpAddress pSrc, PKvsIpAddress pDest,
                                         PTurnChannelData channelDataList, PUINT32 pChannelDataCount)
{
    ENTERS();
    UNUSED_PARAM(pSrc);
    UNUSED_PARAM(pDest);
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 remainingDataSize = 0, processedDataLen, channelDataCount = 0, totalChannelDataCount = 0, channelDataListSize;
    PBYTE pCurrent = NULL;

    CHK(pTurnConnection != NULL && channelDataList != NULL && pChannelDataCount != NULL, STATUS_NULL_ARG);
    CHK_WARN(bufferLen > 0 && pBuffer != NULL, retStatus, "Got empty buffer");

    /* initially pChannelDataCount contains size of channelDataList */
    channelDataListSize = *pChannelDataCount;
    remainingDataSize = bufferLen;
    pCurrent = pBuffer;
    while (remainingDataSize > 0 && totalChannelDataCount < channelDataListSize) {
        processedDataLen = 0;
        channelDataCount = 0;
        // 是STUN Packet
        if (IS_STUN_PACKET(pCurrent)) {
            // STUN packet 大小
            processedDataLen = GET_STUN_PACKET_SIZE(pCurrent) + STUN_HEADER_LEN; /* size of entire STUN packet */
            // 检测STUN第1-2字节(后16bit)，是否为错误类型
            if (STUN_PACKET_IS_TYPE_ERROR(pCurrent)) {
                CHK_STATUS(turnConnectionHandleStunError(pTurnConnection, pCurrent, processedDataLen));
            } else {
                CHK_STATUS(turnConnectionHandleStun(pTurnConnection, pCurrent, processedDataLen));
            }
        }
        // 是DataChannel
        else {
            /* must be channel data if not stun */
            CHK_STATUS(turnConnectionHandleChannelData(pTurnConnection, pCurrent, remainingDataSize, &channelDataList[totalChannelDataCount],
                                                       &channelDataCount, &processedDataLen));
        }

        CHK(remainingDataSize >= processedDataLen, STATUS_INVALID_ARG_LEN);
        pCurrent += processedDataLen;
        remainingDataSize -= processedDataLen;
        /* channelDataCount will be either 1 or 0 */
        totalChannelDataCount += channelDataCount;
    }

    *pChannelDataCount = totalChannelDataCount;

CleanUp:

    CHK_LOG_ERR(retStatus);

    LEAVES();
    return retStatus;
}

// TurnConnection STUN响应包处理器(pBuffer为STUNPAcket, 非错误类型)
STATUS turnConnectionHandleStun(PTurnConnection pTurnConnection, PBYTE pBuffer, UINT32 bufferLen)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT16 stunPacketType = 0;
    PStunAttributeHeader pStunAttr = NULL;
    PStunAttributeAddress pStunAttributeAddress = NULL;
    PStunAttributeLifetime pStunAttributeLifetime = NULL;
    PStunPacket pStunPacket = NULL;
    CHAR ipAddrStr[KVS_IP_ADDRESS_STRING_BUFFER_LEN];
    BOOL locked = FALSE;
    ATOMIC_BOOL hasAllocation = FALSE;
    PTurnPeer pTurnPeer = NULL;
    UINT64 currentTime;
    UINT32 i;

    CHK(pTurnConnection != NULL, STATUS_NULL_ARG);
    CHK(pBuffer != NULL && bufferLen > 0, STATUS_INVALID_ARG);
    CHK(IS_STUN_PACKET(pBuffer) && !STUN_PACKET_IS_TYPE_ERROR(pBuffer), retStatus);

    // 加锁
    MUTEX_LOCK(pTurnConnection->lock);
    locked = TRUE;

    // 获取当前时间
    currentTime = GETTIME();
    // only handling STUN response
    // 获取STUN Packet Type (1-2字节 后16bits)
    stunPacketType = (UINT16) getInt16(*((PUINT16) pBuffer));

    switch (stunPacketType) {
        // allocation 成功响应
        case STUN_PACKET_TYPE_ALLOCATE_SUCCESS_RESPONSE:
            /* If shutdown has been initiated, ignore the allocation response */
            // 检查Turnconnection是否停止
            CHK(!ATOMIC_LOAD(&pTurnConnection->stopTurnConnection), retStatus);
            // 反序列化StunPacket
            CHK_STATUS(deserializeStunPacket(pBuffer, bufferLen, pTurnConnection->longTermKey, KVS_MD5_DIGEST_LENGTH, &pStunPacket));
            // XOR-RELAYED-ADDRESS存在于Allocate响应中。它
            // 指定服务器分配给客户的地址和端口。
            // 它的编码方式与XOR-MAPPED-ADDRESS的编码方式相同
            // 从STUN Packet 获取中继地址
            CHK_STATUS(getStunAttribute(pStunPacket, STUN_ATTRIBUTE_TYPE_XOR_RELAYED_ADDRESS, &pStunAttr));
            CHK_WARN(pStunAttr != NULL, retStatus, "No relay address attribute found in TURN allocate response. Dropping Packet");
            // 获取allocation生命周期
            CHK_STATUS(getStunAttribute(pStunPacket, STUN_ATTRIBUTE_TYPE_LIFETIME, (PStunAttributeHeader*) &pStunAttributeLifetime));
            CHK_WARN(pStunAttributeLifetime != NULL, retStatus, "Missing lifetime in Allocation response. Dropping Packet");

            // convert lifetime to 100ns and store it
            // 设置allocation 过期时间
            pTurnConnection->allocationExpirationTime = (pStunAttributeLifetime->lifetime * HUNDREDS_OF_NANOS_IN_A_SECOND) + currentTime;
            DLOGD("TURN Allocation succeeded. Life time: %u seconds. Allocation expiration epoch %" PRIu64, pStunAttributeLifetime->lifetime,
                  pTurnConnection->allocationExpirationTime / DEFAULT_TIME_UNIT_IN_NANOS);

            pStunAttributeAddress = (PStunAttributeAddress) pStunAttr;
            // 设置中继地址
            pTurnConnection->relayAddress = pStunAttributeAddress->address;
            ATOMIC_STORE_BOOL(&pTurnConnection->hasAllocation, TRUE);

            if (!pTurnConnection->relayAddressReported && pTurnConnection->turnConnectionCallbacks.relayAddressAvailableFn != NULL) {
                pTurnConnection->relayAddressReported = TRUE;

                // release lock early and report relay candidate
                // 解锁
                MUTEX_UNLOCK(pTurnConnection->lock);
                locked = FALSE;

                pTurnConnection->turnConnectionCallbacks.relayAddressAvailableFn(pTurnConnection->turnConnectionCallbacks.customData,
                                                                                 &pTurnConnection->relayAddress, pTurnConnection->pControlChannel);
            }

            break;
        // 刷新成功响应
        case STUN_PACKET_TYPE_REFRESH_SUCCESS_RESPONSE:
            // 反序列化StunPacket
            CHK_STATUS(deserializeStunPacket(pBuffer, bufferLen, pTurnConnection->longTermKey, KVS_MD5_DIGEST_LENGTH, &pStunPacket));
            // 从StUN Packet 获取allocation 生命周期
            CHK_STATUS(getStunAttribute(pStunPacket, STUN_ATTRIBUTE_TYPE_LIFETIME, (PStunAttributeHeader*) &pStunAttributeLifetime));
            CHK_WARN(pStunAttributeLifetime != NULL, retStatus, "No lifetime attribute found in TURN refresh response. Dropping Packet");

            // lifetime == 0 server 销毁allocation
            if (pStunAttributeLifetime->lifetime == 0) {
                hasAllocation = ATOMIC_EXCHANGE_BOOL(&pTurnConnection->hasAllocation, FALSE);
                CHK(hasAllocation, retStatus);
                DLOGD("TURN Allocation freed.");
                CVAR_SIGNAL(pTurnConnection->freeAllocationCvar);
            }
            // 刷新allocation 过期时间
            else {
                // convert lifetime to 100ns and store it
                pTurnConnection->allocationExpirationTime = (pStunAttributeLifetime->lifetime * HUNDREDS_OF_NANOS_IN_A_SECOND) + currentTime;
                DLOGD("Refreshed TURN allocation lifetime is %u seconds. Allocation expiration epoch %" PRIu64, pStunAttributeLifetime->lifetime,
                      pTurnConnection->allocationExpirationTime / DEFAULT_TIME_UNIT_IN_NANOS);
            }

            break;

        // 创建许可成功响应
        case STUN_PACKET_TYPE_CREATE_PERMISSION_SUCCESS_RESPONSE:
            for (i = 0; i < pTurnConnection->turnPeerCount; ++i) {
                pTurnPeer = &pTurnConnection->turnPeerList[i];
                if (transactionIdStoreHasId(pTurnPeer->pTransactionIdStore, pBuffer + STUN_PACKET_TRANSACTION_ID_OFFSET)) {
                    // 设置 TurnPeer 连接状态
                    if (pTurnPeer->connectionState == TURN_PEER_CONN_STATE_CREATE_PERMISSION) {
                        pTurnPeer->connectionState = TURN_PEER_CONN_STATE_BIND_CHANNEL;
                        CHK_STATUS(getIpAddrStr(&pTurnPeer->address, ipAddrStr, ARRAY_SIZE(ipAddrStr)));
                        DLOGD("create permission succeeded for peer %s", ipAddrStr);
                    }
                    // 设置许可过期时间
                    pTurnPeer->permissionExpirationTime = TURN_PERMISSION_LIFETIME + currentTime;
                }
            }

            break;

        // Channel绑定成功响应
        case STUN_PACKET_TYPE_CHANNEL_BIND_SUCCESS_RESPONSE:
            for (i = 0; i < pTurnConnection->turnPeerCount; ++i) {
                pTurnPeer = &pTurnConnection->turnPeerList[i];
                if (pTurnPeer->connectionState == TURN_PEER_CONN_STATE_BIND_CHANNEL &&
                    transactionIdStoreHasId(pTurnPeer->pTransactionIdStore, pBuffer + STUN_PACKET_TRANSACTION_ID_OFFSET)) {
                    // pTurnPeer->ready means this peer is ready to receive data. pTurnPeer->connectionState could
                    // change after reaching TURN_PEER_CONN_STATE_READY due to refreshing permission and channel.
                    if (!pTurnPeer->ready) {
                        pTurnPeer->ready = TRUE;
                    }
                    // 设置TurnPeer 状态为就绪
                    pTurnPeer->connectionState = TURN_PEER_CONN_STATE_READY;

                    CHK_STATUS(getIpAddrStr(&pTurnPeer->address, ipAddrStr, ARRAY_SIZE(ipAddrStr)));
                    DLOGD("Channel bind succeeded with peer %s, port: %u, channel number %u", ipAddrStr, (UINT16) getInt16(pTurnPeer->address.port),
                          pTurnPeer->channelNumber);

                    break;
                }
            }

            break;

        // Data Indication
        case STUN_PACKET_TYPE_DATA_INDICATION:
            DLOGD("Received data indication");
            // no-ops for now, turn server has to use data channel if it is established. client is free to use either.
            break;

        default:
            DLOGD("Drop unsupported TURN message with type 0x%02x", stunPacketType);
            break;
    }

CleanUp:

    CHK_LOG_ERR(retStatus);

    // 解锁
    if (locked) {
        MUTEX_UNLOCK(pTurnConnection->lock);
    }

    // 回收StunPacket资源
    if (pStunPacket != NULL) {
        freeStunPacket(&pStunPacket);
    }

    LEAVES();
    return retStatus;
}

// TurnConnection STUN响应包处理器(pBuffer为STUNPAcket, 错误类型)
STATUS turnConnectionHandleStunError(PTurnConnection pTurnConnection, PBYTE pBuffer, UINT32 bufferLen)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT16 stunPacketType = 0;
    PStunAttributeHeader pStunAttr = NULL;
    PStunAttributeErrorCode pStunAttributeErrorCode = NULL;
    PStunAttributeNonce pStunAttributeNonce = NULL;
    PStunAttributeRealm pStunAttributeRealm = NULL;
    PStunPacket pStunPacket = NULL;
    BOOL locked = FALSE, iterate = TRUE;
    PTurnPeer pTurnPeer = NULL;
    UINT32 i;

    CHK(pTurnConnection != NULL, STATUS_NULL_ARG);
    CHK(pBuffer != NULL && bufferLen > 0, STATUS_INVALID_ARG);
    CHK(STUN_PACKET_IS_TYPE_ERROR(pBuffer), retStatus);

    // 加锁
    MUTEX_LOCK(pTurnConnection->lock);
    locked = TRUE;

    // 获取STUN message type (1-2字节 14bits)
    stunPacketType = (UINT16) getInt16(*((PUINT16) pBuffer));
    /* we could get errors like expired nonce after sending the deallocation packet. The allocate would have been
     * deallocated even if the response is error response, and if we try to deallocate again we would get invalid
     * allocation error. Therefore if we get an error after we've sent the deallocation packet, consider the
     * deallocation process finished. */
    // 已经销毁allocation
    if (pTurnConnection->deallocatePacketSent) {
        ATOMIC_STORE_BOOL(&pTurnConnection->hasAllocation, FALSE);
        CHK(FALSE, retStatus);
    }

    // 已获得凭证
    if (pTurnConnection->credentialObtained) {
        // 反序列化StunPacket
        retStatus = deserializeStunPacket(pBuffer, bufferLen, pTurnConnection->longTermKey, KVS_MD5_DIGEST_LENGTH, &pStunPacket);
    }
    /* if deserializing with password didnt work, try deserialize without password again */
    // 带凭证反序列化不成功，再次尝试不带凭证的
    if (!pTurnConnection->credentialObtained || STATUS_FAILED(retStatus)) {
        CHK_STATUS(deserializeStunPacket(pBuffer, bufferLen, NULL, 0, &pStunPacket));
        retStatus = STATUS_SUCCESS;
    }

    // 获取错误代码
    CHK_STATUS(getStunAttribute(pStunPacket, STUN_ATTRIBUTE_TYPE_ERROR_CODE, &pStunAttr));
    CHK_WARN(pStunAttr != NULL, retStatus, "No error code attribute found in Stun Error response. Dropping Packet");
    pStunAttributeErrorCode = (PStunAttributeErrorCode) pStunAttr;

    // 处理错误
    switch (pStunAttributeErrorCode->errorCode) {
        // 未授权
        case STUN_ERROR_UNAUTHORIZED:
            // 获取nonce属性
            CHK_STATUS(getStunAttribute(pStunPacket, STUN_ATTRIBUTE_TYPE_NONCE, &pStunAttr));
            CHK_WARN(pStunAttr != NULL, retStatus, "No Nonce attribute found in Allocate Error response. Dropping Packet");
            pStunAttributeNonce = (PStunAttributeNonce) pStunAttr;
            CHK_WARN(pStunAttributeNonce->attribute.length <= STUN_MAX_NONCE_LEN, retStatus,
                     "Invalid Nonce found in Allocate Error response. Dropping Packet");
            pTurnConnection->nonceLen = pStunAttributeNonce->attribute.length;
            // 设置nonce
            MEMCPY(pTurnConnection->turnNonce, pStunAttributeNonce->nonce, pTurnConnection->nonceLen);

            // 用于描述服务器上下文的字符串。该Realm将告知client,并被用于用户名和口令的校验
            // 获取realm
            CHK_STATUS(getStunAttribute(pStunPacket, STUN_ATTRIBUTE_TYPE_REALM, &pStunAttr));
            CHK_WARN(pStunAttr != NULL, retStatus, "No Realm attribute found in Allocate Error response. Dropping Packet");
            pStunAttributeRealm = (PStunAttributeRealm) pStunAttr;
            CHK_WARN(pStunAttributeRealm->attribute.length <= STUN_MAX_REALM_LEN, retStatus,
                     "Invalid Realm found in Allocate Error response. Dropping Packet");
            // pStunAttributeRealm->attribute.length does not include null terminator and pStunAttributeRealm->realm is not null terminated
            STRNCPY(pTurnConnection->turnRealm, pStunAttributeRealm->realm, pStunAttributeRealm->attribute.length);
            pTurnConnection->turnRealm[pStunAttributeRealm->attribute.length] = '\0';

            pTurnConnection->credentialObtained = TRUE;

            // turnConnection更新nonce
            CHK_STATUS(turnConnectionUpdateNonce(pTurnConnection));
            break;

        // nonce失效
        case STUN_ERROR_STALE_NONCE:
            DLOGD("Updating stale nonce");
            // 获取nonce属性
            CHK_STATUS(getStunAttribute(pStunPacket, STUN_ATTRIBUTE_TYPE_NONCE, &pStunAttr));
            CHK_WARN(pStunAttr != NULL, retStatus, "No Nonce attribute found in Refresh Error response. Dropping Packet");
            pStunAttributeNonce = (PStunAttributeNonce) pStunAttr;
            CHK_WARN(pStunAttributeNonce->attribute.length <= STUN_MAX_NONCE_LEN, retStatus,
                     "Invalid Nonce found in Refresh Error response. Dropping Packet");
            pTurnConnection->nonceLen = pStunAttributeNonce->attribute.length;
            // 设置nonce
            MEMCPY(pTurnConnection->turnNonce, pStunAttributeNonce->nonce, pTurnConnection->nonceLen);
            // 更新nonce
            CHK_STATUS(turnConnectionUpdateNonce(pTurnConnection));
            break;
        // 其他错误，移除peer
        default:
            /* Remove peer for any other error */
            DLOGW("Received STUN error response. Error type: 0x%02x, Error Code: %u. attribute len %u, Error detail: %s.", stunPacketType,
                  pStunAttributeErrorCode->errorCode, pStunAttributeErrorCode->attribute.length, pStunAttributeErrorCode->errorPhrase);

            /* Find TurnPeer using transaction Id, then mark it as failed */
            for (i = 0; iterate && i < pTurnConnection->turnPeerCount; ++i) {
                pTurnPeer = &pTurnConnection->turnPeerList[i];
                if (transactionIdStoreHasId(pTurnPeer->pTransactionIdStore, pBuffer + STUN_PACKET_TRANSACTION_ID_OFFSET)) {
                    pTurnPeer->connectionState = TURN_PEER_CONN_STATE_FAILED;
                    iterate = FALSE;
                }
            }
            break;
    }

CleanUp:

    CHK_LOG_ERR(retStatus);

    // 解锁
    if (locked) {
        MUTEX_UNLOCK(pTurnConnection->lock);
    }

    // 回收StunPacket资源
    if (pStunPacket != NULL) {
        freeStunPacket(&pStunPacket);
    }

    LEAVES();
    return retStatus;
}

// turnConnection Channel Data处理器
STATUS turnConnectionHandleChannelData(PTurnConnection pTurnConnection, PBYTE pBuffer, UINT32 bufferLen, PTurnChannelData pChannelData,
                                       PUINT32 pChannelDataCount, PUINT32 pProcessedDataLen)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;

    UINT32 turnChannelDataCount = 0, hexStrLen = 0;
    UINT16 channelNumber = 0;
    PTurnPeer pTurnPeer = NULL;
    PCHAR hexStr = NULL;

    CHK(pTurnConnection != NULL && pChannelData != NULL && pChannelDataCount != NULL && pProcessedDataLen != NULL, STATUS_NULL_ARG);
    CHK(pBuffer != NULL && bufferLen > 0, STATUS_INVALID_ARG);

    // 加锁
    MUTEX_LOCK(pTurnConnection->lock);
    locked = TRUE;

    // udp
    if (pTurnConnection->protocol == KVS_SOCKET_PROTOCOL_UDP) {
        // 获取channel number (1-2字节)
        channelNumber = (UINT16) getInt16(*(PINT16) pBuffer);
        // channel Number 对应的TurnPeer存在
        if ((pTurnPeer = turnConnectionGetPeerWithChannelNumber(pTurnConnection, channelNumber)) != NULL) {
            /*
             * Not expecting fragmented channel message in UDP mode.
             * Data channel messages from UDP connection may or may not padded. Thus turnConnectionHandleChannelDataTcpMode wont
             * be able to parse it.
             */
            // 设置data 跳过4字节头
            pChannelData->data = pBuffer + TURN_DATA_CHANNEL_SEND_OVERHEAD;
            pChannelData->size = GET_STUN_PACKET_SIZE(pBuffer);
            pChannelData->senderAddr = pTurnPeer->address;
            turnChannelDataCount = 1;

            if (pChannelData->size + TURN_DATA_CHANNEL_SEND_OVERHEAD < bufferLen) {
                DLOGD("Not expecting multiple channel data messages in one UDP packet.");
            }

        }
        // channel number 对应的TurnPeer 不存在
        else {
            // 获取长度
            CHK_STATUS(hexEncode(pBuffer, bufferLen, NULL, &hexStrLen));
            // 分配空间
            hexStr = MEMCALLOC(1, hexStrLen * SIZEOF(CHAR));
            CHK(hexStr != NULL, STATUS_NOT_ENOUGH_MEMORY);
            CHK_STATUS(hexEncode(pBuffer, bufferLen, hexStr, &hexStrLen));
            DLOGE("Turn connection does not have channel number, dumping payload: %s", hexStr);
            turnChannelDataCount = 0;

            SAFE_MEMFREE(hexStr);
        }
        *pProcessedDataLen = bufferLen;

    } else {
        CHK_STATUS(
            turnConnectionHandleChannelDataTcpMode(pTurnConnection, pBuffer, bufferLen, pChannelData, &turnChannelDataCount, pProcessedDataLen));
    }

    *pChannelDataCount = turnChannelDataCount;

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (hexStr != NULL) {
        SAFE_MEMFREE(hexStr);
    }
    // 解锁
    if (locked) {
        MUTEX_UNLOCK(pTurnConnection->lock);
    }

    LEAVES();
    return retStatus;
}


/*
 * turnConnectionHandleChannelDataTcpMode will process a single turn channel data item from pBuffer then return.
 * If there is a complete channel data item in buffer, upon return *pTurnChannelDataCount will be 1, *pTurnChannelData
 * will data details about the parsed channel data. *pProcessedDataLen will be the length of data processed.
 */
// turnConnection tcp ChannelData 处理器
STATUS turnConnectionHandleChannelDataTcpMode(PTurnConnection pTurnConnection, PBYTE pBuffer, UINT32 bufferLen, PTurnChannelData pChannelData,
                                              PUINT32 pTurnChannelDataCount, PUINT32 pProcessedDataLen)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 bytesToCopy = 0, remainingMsgSize = 0, paddedChannelDataLen = 0, remainingBufLen = 0, channelDataCount = 0;
    PBYTE pCurPos = NULL;
    UINT16 channelNumber = 0;
    PTurnPeer pTurnPeer = NULL;

    CHK(pTurnConnection != NULL && pChannelData != NULL && pTurnChannelDataCount != NULL && pProcessedDataLen != NULL, STATUS_NULL_ARG);
    CHK(pBuffer != NULL && bufferLen > 0, STATUS_INVALID_ARG);

    pCurPos = pBuffer;
    remainingBufLen = bufferLen;
    /* process only one channel data and return. Because channel data can be intermixed with STUN packet.
     * need to check remainingBufLen too because channel data could be incomplete. */
    
    // 只处理一个通道数据并返回。因为通道数据可能与STUN数据包混合在一起。
    // 也需要检查剩余的BufLen，因为通道数据可能是不完整的。
    while (remainingBufLen != 0 && channelDataCount == 0) {
        DLOGV("currRecvDataLen: %d", pTurnConnection->currRecvDataLen);
        // 接受buffer 已有数据
        if (pTurnConnection->currRecvDataLen != 0) {
            // 已经含有头4字节
            if (pTurnConnection->currRecvDataLen >= TURN_DATA_CHANNEL_SEND_OVERHEAD) {
                /* pTurnConnection->recvDataBuffer always has channel data start */
                paddedChannelDataLen = ROUND_UP((UINT32) getInt16(*(PINT16) (pTurnConnection->recvDataBuffer + SIZEOF(channelNumber))), 4);
                remainingMsgSize = paddedChannelDataLen - (pTurnConnection->currRecvDataLen - TURN_DATA_CHANNEL_SEND_OVERHEAD);
                bytesToCopy = MIN(remainingMsgSize, remainingBufLen);
                remainingBufLen -= bytesToCopy;

                if (bytesToCopy > (pTurnConnection->recvDataBufferSize - pTurnConnection->currRecvDataLen)) {
                    /* drop current message if it is longer than buffer size. */
                    pTurnConnection->currRecvDataLen = 0;
                    CHK(FALSE, STATUS_BUFFER_TOO_SMALL);
                }

                MEMCPY(pTurnConnection->recvDataBuffer + pTurnConnection->currRecvDataLen, pCurPos, bytesToCopy);
                pTurnConnection->currRecvDataLen += bytesToCopy;
                pCurPos += bytesToCopy;

                CHECK_EXT(pTurnConnection->currRecvDataLen <= paddedChannelDataLen + TURN_DATA_CHANNEL_SEND_OVERHEAD,
                          "Should not store more than one channel data message in recvDataBuffer");

                /*
                 * once assembled a complete channel data in recvDataBuffer, copy over to completeChannelDataBuffer to
                 * make room for subsequent partial channel data.
                 */
                if (pTurnConnection->currRecvDataLen == (paddedChannelDataLen + TURN_DATA_CHANNEL_SEND_OVERHEAD)) {
                    channelNumber = (UINT16) getInt16(*(PINT16) pTurnConnection->recvDataBuffer);
                    if ((pTurnPeer = turnConnectionGetPeerWithChannelNumber(pTurnConnection, channelNumber)) != NULL) {
                        MEMCPY(pTurnConnection->completeChannelDataBuffer, pTurnConnection->recvDataBuffer, pTurnConnection->currRecvDataLen);
                        pChannelData->data = pTurnConnection->completeChannelDataBuffer + TURN_DATA_CHANNEL_SEND_OVERHEAD;
                        pChannelData->size = GET_STUN_PACKET_SIZE(pTurnConnection->completeChannelDataBuffer);
                        pChannelData->senderAddr = pTurnPeer->address;
                        channelDataCount++;
                    }

                    pTurnConnection->currRecvDataLen = 0;
                }
            } else {
                /* copy just enough to make a complete channel data header */
                // 拷贝Data Channel 头缺失的部分
                bytesToCopy = MIN(remainingMsgSize, TURN_DATA_CHANNEL_SEND_OVERHEAD - pTurnConnection->currRecvDataLen);
                MEMCPY(pTurnConnection->recvDataBuffer + pTurnConnection->currRecvDataLen, pCurPos, bytesToCopy);
                pTurnConnection->currRecvDataLen += bytesToCopy;
                pCurPos += bytesToCopy;
            }
        }
        // 接受Buffer 无数据
        else {
            /* new channel message start */
            CHK(*pCurPos == TURN_DATA_CHANNEL_MSG_FIRST_BYTE, STATUS_TURN_MISSING_CHANNEL_DATA_HEADER);

            // 4字节对齐
            paddedChannelDataLen = ROUND_UP((UINT32) getInt16(*(PINT16) (pCurPos + SIZEOF(UINT16))), 4);
            // buffer 剩余数据大于一个Data
            if (remainingBufLen >= (paddedChannelDataLen + TURN_DATA_CHANNEL_SEND_OVERHEAD)) {
                channelNumber = (UINT16) getInt16(*(PINT16) pCurPos);
                // 获取对应channel number的TurnPeer
                if ((pTurnPeer = turnConnectionGetPeerWithChannelNumber(pTurnConnection, channelNumber)) != NULL) {
                    // 跳过4字节头
                    pChannelData->data = pCurPos + TURN_DATA_CHANNEL_SEND_OVERHEAD;
                    pChannelData->size = GET_STUN_PACKET_SIZE(pCurPos);
                    pChannelData->senderAddr = pTurnPeer->address;
                    channelDataCount++;
                }


                remainingBufLen -= (paddedChannelDataLen + TURN_DATA_CHANNEL_SEND_OVERHEAD);
                // 移动指针
                pCurPos += (paddedChannelDataLen + TURN_DATA_CHANNEL_SEND_OVERHEAD);

            }
            // Buffer 剩余数据小于一个Data， Data不完整channelDataCount保持不变
            else {
                CHK(pTurnConnection->currRecvDataLen == 0, STATUS_TURN_NEW_DATA_CHANNEL_MSG_HEADER_BEFORE_PREVIOUS_MSG_FINISH);
                CHK(remainingBufLen <= (pTurnConnection->recvDataBufferSize), STATUS_BUFFER_TOO_SMALL);

                MEMCPY(pTurnConnection->recvDataBuffer, pCurPos, remainingBufLen);

                pTurnConnection->currRecvDataLen += remainingBufLen;
                // 移动指针
                pCurPos += remainingBufLen;
                remainingBufLen = 0;
            }
        }
    }

    /* return actual channel data count */
    *pTurnChannelDataCount = channelDataCount;
    *pProcessedDataLen = bufferLen - remainingBufLen;

CleanUp:

    CHK_LOG_ERR(retStatus);

    LEAVES();
    return retStatus;
}

// turnConnection 增加TurnPeer
STATUS turnConnectionAddPeer(PTurnConnection pTurnConnection, PKvsIpAddress pPeerAddress)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PTurnPeer pTurnPeer = NULL;
    BOOL locked = FALSE;

    CHK(pTurnConnection != NULL && pPeerAddress != NULL, STATUS_NULL_ARG);
    CHK(pTurnConnection->turnServer.ipAddress.family == pPeerAddress->family, STATUS_INVALID_ARG);
    CHK_WARN(IS_IPV4_ADDR(pPeerAddress), retStatus, "Drop IPv6 turn peer because only IPv4 turn peer is supported right now");

    // 加锁
    MUTEX_LOCK(pTurnConnection->lock);
    locked = TRUE;

    /* check for duplicate */
    // 判断TurnPeer是否存在
    CHK(turnConnectionGetPeerWithIp(pTurnConnection, pPeerAddress) == NULL, retStatus);
    CHK_WARN(pTurnConnection->turnPeerCount < DEFAULT_TURN_MAX_PEER_COUNT, STATUS_INVALID_OPERATION, "Add peer failed. Max peer count reached");

    pTurnPeer = &pTurnConnection->turnPeerList[pTurnConnection->turnPeerCount++];

    pTurnPeer->connectionState = TURN_PEER_CONN_STATE_CREATE_PERMISSION;
    pTurnPeer->address = *pPeerAddress;
    pTurnPeer->xorAddress = *pPeerAddress;
    /* safe to down cast because DEFAULT_TURN_MAX_PEER_COUNT is enforced */
    pTurnPeer->channelNumber = (UINT16) pTurnConnection->turnPeerCount + TURN_CHANNEL_BIND_CHANNEL_NUMBER_BASE;
    pTurnPeer->permissionExpirationTime = INVALID_TIMESTAMP_VALUE;
    pTurnPeer->ready = FALSE;

    // 异或ip
    CHK_STATUS(xorIpAddress(&pTurnPeer->xorAddress, NULL)); /* only work for IPv4 for now */
    // 创建事务ID Store
    CHK_STATUS(createTransactionIdStore(DEFAULT_MAX_STORED_TRANSACTION_ID_COUNT, &pTurnPeer->pTransactionIdStore));
    pTurnPeer = NULL;

CleanUp:

    if (STATUS_FAILED(retStatus) && pTurnPeer != NULL) {
        freeTransactionIdStore(&pTurnPeer->pTransactionIdStore);
        pTurnConnection->turnPeerCount--;
    }

    // 解锁
    if (locked) {
        MUTEX_UNLOCK(pTurnConnection->lock);
    }

    LEAVES();
    return retStatus;
}

// turnConnection 发送数据
STATUS turnConnectionSendData(PTurnConnection pTurnConnection, PBYTE pBuf, UINT32 bufLen, PKvsIpAddress pDestIp)
{
    STATUS retStatus = STATUS_SUCCESS;
    PTurnPeer pSendPeer = NULL;
    UINT32 paddedDataLen = 0;
    CHAR ipAddrStr[KVS_IP_ADDRESS_STRING_BUFFER_LEN];
    BOOL locked = FALSE;
    BOOL sendLocked = FALSE;

    CHK(pTurnConnection != NULL && pDestIp != NULL, STATUS_NULL_ARG);
    CHK(pBuf != NULL && bufLen > 0, STATUS_INVALID_ARG);

    // 加锁
    MUTEX_LOCK(pTurnConnection->lock);
    locked = TRUE;

    if (!(pTurnConnection->state == TURN_STATE_CREATE_PERMISSION || pTurnConnection->state == TURN_STATE_BIND_CHANNEL ||
          pTurnConnection->state == TURN_STATE_READY)) {
        DLOGV("TurnConnection not ready to send data");

        // If turn is not ready yet. Drop the send since ice will retry.
        CHK(FALSE, retStatus);
    }

    // 根据IP获取TurnPeer
    pSendPeer = turnConnectionGetPeerWithIp(pTurnConnection, pDestIp);

    // 获取IP 字符串
    CHK_STATUS(getIpAddrStr(pDestIp, ipAddrStr, ARRAY_SIZE(ipAddrStr)));
    // TurnPeer 不可用
    if (pSendPeer == NULL) {
        DLOGV("Unable to send data through turn because peer with address %s:%u is not found", ipAddrStr, KVS_GET_IP_ADDRESS_PORT(pDestIp));
        CHK(FALSE, retStatus);
    } else if (pSendPeer->connectionState == TURN_PEER_CONN_STATE_FAILED) {
        CHK(FALSE, STATUS_TURN_CONNECTION_PEER_NOT_USABLE);
    } else if (!pSendPeer->ready) {
        DLOGV("Unable to send data through turn because turn channel is not established with peer with address %s:%u", ipAddrStr,
              KVS_GET_IP_ADDRESS_PORT(pDestIp));
        CHK(FALSE, retStatus);
    }

    // 解锁
    MUTEX_UNLOCK(pTurnConnection->lock);
    locked = FALSE;

    /* need to serialize send because every send load data into the same buffer pTurnConnection->sendDataBuffer */
    // 加锁
    MUTEX_LOCK(pTurnConnection->sendLock);
    sendLocked = TRUE;

    CHK(pTurnConnection->dataBufferSize - TURN_DATA_CHANNEL_SEND_OVERHEAD >= bufLen, STATUS_BUFFER_TOO_SMALL);

    paddedDataLen = (UINT32) ROUND_UP(TURN_DATA_CHANNEL_SEND_OVERHEAD + bufLen, 4);

    /* generate data channel TURN message */
    putInt16((PINT16) (pTurnConnection->sendDataBuffer), pSendPeer->channelNumber);
    putInt16((PINT16) (pTurnConnection->sendDataBuffer + 2), (UINT16) bufLen);
    MEMCPY(pTurnConnection->sendDataBuffer + TURN_DATA_CHANNEL_SEND_OVERHEAD, pBuf, bufLen);

    // 发送数据
    retStatus = iceUtilsSendData(pTurnConnection->sendDataBuffer, paddedDataLen, &pTurnConnection->turnServer.ipAddress,
                                 pTurnConnection->pControlChannel, NULL, FALSE);

    if (STATUS_FAILED(retStatus)) {
        DLOGW("iceUtilsSendData failed with 0x%08x", retStatus);
        if (retStatus != STATUS_SOCKET_CONNECTION_CLOSED_ALREADY) {
            retStatus = STATUS_SUCCESS;
        }
    }

CleanUp:

    CHK_LOG_ERR(retStatus);

    // 解锁
    if (sendLocked) {
        MUTEX_UNLOCK(pTurnConnection->sendLock);
    }

    // 解锁
    if (locked) {
        MUTEX_UNLOCK(pTurnConnection->lock);
    }

    return retStatus;
}

// 启动turnConnection
STATUS turnConnectionStart(PTurnConnection pTurnConnection)
{
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;
    SIZE_T timerCallbackId;

    CHK(pTurnConnection != NULL, STATUS_NULL_ARG);

    // 加锁
    MUTEX_LOCK(pTurnConnection->lock);
    locked = TRUE;

    /* only execute when turnConnection is in TURN_STATE_NEW */
    CHK(pTurnConnection->state == TURN_STATE_NEW, retStatus);

    // 解锁
    MUTEX_UNLOCK(pTurnConnection->lock);
    locked = FALSE;

    timerCallbackId = ATOMIC_EXCHANGE(&pTurnConnection->timerCallbackId, MAX_UINT32);
    if (timerCallbackId != MAX_UINT32) {
        // 取消定时器
        CHK_STATUS(timerQueueCancelTimer(pTurnConnection->timerQueueHandle, (UINT32) timerCallbackId, (UINT64) pTurnConnection));
    }

    /* schedule the timer, which will drive the state machine. */
    // 添加定时器
    CHK_STATUS(timerQueueAddTimer(pTurnConnection->timerQueueHandle, KVS_ICE_DEFAULT_TIMER_START_DELAY, pTurnConnection->currentTimerCallingPeriod,
                                  turnConnectionTimerCallback, (UINT64) pTurnConnection, (PUINT32) &timerCallbackId));

    ATOMIC_STORE(&pTurnConnection->timerCallbackId, timerCallbackId);

CleanUp:

    CHK_LOG_ERR(retStatus);

    // 解锁
    if (locked) {
        MUTEX_UNLOCK(pTurnConnection->lock);
    }

    return retStatus;
}

// turnConnection 刷新Allocation生命周期
STATUS turnConnectionRefreshAllocation(PTurnConnection pTurnConnection)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT64 currTime = 0;
    PStunAttributeLifetime pStunAttributeLifetime = NULL;

    CHK(pTurnConnection != NULL, STATUS_NULL_ARG);

    // 获取当前时间
    currTime = GETTIME();
    // return early if we are not in grace period yet or if we just sent refresh earlier
    // 检查是否过期
    CHK(IS_VALID_TIMESTAMP(pTurnConnection->allocationExpirationTime) &&
            currTime + DEFAULT_TURN_ALLOCATION_REFRESH_GRACE_PERIOD >= pTurnConnection->allocationExpirationTime &&
            currTime >= pTurnConnection->nextAllocationRefreshTime,
        retStatus);

    DLOGD("Refresh turn allocation");

    // 获取allocation 生命周期
    CHK_STATUS(getStunAttribute(pTurnConnection->pTurnAllocationRefreshPacket, STUN_ATTRIBUTE_TYPE_LIFETIME,
                                (PStunAttributeHeader*) &pStunAttributeLifetime));
    CHK(pStunAttributeLifetime != NULL, STATUS_INTERNAL_ERROR);

    // 默认600s
    pStunAttributeLifetime->lifetime = DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS;

    // 发送刷新allocation STUN Packet
    CHK_STATUS(iceUtilsSendStunPacket(pTurnConnection->pTurnAllocationRefreshPacket, pTurnConnection->longTermKey,
                                      ARRAY_SIZE(pTurnConnection->longTermKey), &pTurnConnection->turnServer.ipAddress,
                                      pTurnConnection->pControlChannel, NULL, FALSE));

    // 设置下次刷新时间 1s
    pTurnConnection->nextAllocationRefreshTime = currTime + DEFAULT_TURN_SEND_REFRESH_INVERVAL;

CleanUp:

    CHK_LOG_ERR(retStatus);

    return retStatus;
}

// turnConnection 刷新许可生命周期
STATUS turnConnectionRefreshPermission(PTurnConnection pTurnConnection, PBOOL pNeedRefresh)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT64 currTime = 0;
    PTurnPeer pTurnPeer = NULL;
    BOOL needRefresh = FALSE;
    UINT32 i;

    CHK(pTurnConnection != NULL && pNeedRefresh != NULL, STATUS_NULL_ARG);

    // 获取当前时间
    currTime = GETTIME();

    // refresh all peers whenever one of them expire is close to expiration
    // 提前30s 刷新
    for (i = 0; i < pTurnConnection->turnPeerCount; ++i) {
        pTurnPeer = &pTurnConnection->turnPeerList[i];
        if (IS_VALID_TIMESTAMP(pTurnPeer->permissionExpirationTime) &&
            currTime + DEFAULT_TURN_PERMISSION_REFRESH_GRACE_PERIOD >= pTurnPeer->permissionExpirationTime) {
            DLOGD("Refreshing turn permission");
            needRefresh = TRUE;
        }
    }

CleanUp:

    if (pNeedRefresh != NULL) {
        *pNeedRefresh = needRefresh;
    }

    CHK_LOG_ERR(retStatus);
    return retStatus;
}

// 回收turnConnection  预分配的STUN Packet
STATUS turnConnectionFreePreAllocatedPackets(PTurnConnection pTurnConnection)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pTurnConnection != NULL, STATUS_NULL_ARG);

    if (pTurnConnection->pTurnPacket != NULL) {
        CHK_STATUS(freeStunPacket(&pTurnConnection->pTurnPacket));
    }

    if (pTurnConnection->pTurnChannelBindPacket != NULL) {
        CHK_STATUS(freeStunPacket(&pTurnConnection->pTurnChannelBindPacket));
    }

    if (pTurnConnection->pTurnCreatePermissionPacket != NULL) {
        CHK_STATUS(freeStunPacket(&pTurnConnection->pTurnCreatePermissionPacket));
    }

    if (pTurnConnection->pTurnAllocationRefreshPacket != NULL) {
        CHK_STATUS(freeStunPacket(&pTurnConnection->pTurnAllocationRefreshPacket));
    }

CleanUp:

    CHK_LOG_ERR(retStatus);
    return retStatus;
}

// turnConnection 状态转换
STATUS turnConnectionStepState(PTurnConnection pTurnConnection)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 readyPeerCount = 0, channelWithPermissionCount = 0;
    UINT64 currentTime = GETTIME();
    CHAR ipAddrStr[KVS_IP_ADDRESS_STRING_BUFFER_LEN];
    TURN_CONNECTION_STATE previousState = TURN_STATE_NEW;
    BOOL refreshPeerPermission = FALSE;
    UINT32 i = 0;

    CHK(pTurnConnection != NULL, STATUS_NULL_ARG);

    previousState = pTurnConnection->state;

    switch (pTurnConnection->state) {
        // 新建
        case TURN_STATE_NEW:
            // create empty turn allocation request
            // 创建空的allocation STUN Packet 
            CHK_STATUS(turnConnectionPackageTurnAllocationRequest(NULL, NULL, NULL, 0, DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS,
                                                                  &pTurnConnection->pTurnPacket));

            pTurnConnection->state = TURN_STATE_CHECK_SOCKET_CONNECTION;
            pTurnConnection->stateTimeoutTime = currentTime + DEFAULT_TURN_SOCKET_CONNECT_TIMEOUT;
            break;

        // 检查socket 连接
        case TURN_STATE_CHECK_SOCKET_CONNECTION:
            // socketConnection 连接状态为Connected
            if (socketConnectionIsConnected(pTurnConnection->pControlChannel)) {
                /* initialize TLS once tcp connection is established */
                /* Start receiving data for TLS handshake */
                ATOMIC_STORE_BOOL(&pTurnConnection->pControlChannel->receiveData, TRUE);

                /* We dont support DTLS and TCP, so only options are TCP/TLS and UDP. */
                /* TODO: add plain TCP once it becomes available. */
                // 当传输协议为tcp 初始化安全连接
                if (pTurnConnection->protocol == KVS_SOCKET_PROTOCOL_TCP && pTurnConnection->pControlChannel->pTlsSession == NULL) {
                    CHK_STATUS(socketConnectionInitSecureConnection(pTurnConnection->pControlChannel, FALSE));
                }

                pTurnConnection->state = TURN_STATE_GET_CREDENTIALS;
                pTurnConnection->stateTimeoutTime = currentTime + DEFAULT_TURN_GET_CREDENTIAL_TIMEOUT;
            }
            // socketConnection 连接状态不是Connected
            else {
                CHK(currentTime < pTurnConnection->stateTimeoutTime, STATUS_TURN_CONNECTION_STATE_TRANSITION_TIMEOUT);
            }


        // 获取凭证
        case TURN_STATE_GET_CREDENTIALS:

            // 已获取凭证
            if (pTurnConnection->credentialObtained) {
                DLOGV("Updated turn allocation request credential after receiving 401");

                // update turn allocation packet with credentials
                // 回收StunPacket资源
                CHK_STATUS(freeStunPacket(&pTurnConnection->pTurnPacket));
                // 生成long-term key
                CHK_STATUS(turnConnectionGetLongTermKey(pTurnConnection->turnServer.username, pTurnConnection->turnRealm,
                                                        pTurnConnection->turnServer.credential, pTurnConnection->longTermKey,
                                                        SIZEOF(pTurnConnection->longTermKey)));
                // 构建allocation 请求STUN Packet
                CHK_STATUS(turnConnectionPackageTurnAllocationRequest(pTurnConnection->turnServer.username, pTurnConnection->turnRealm,
                                                                      pTurnConnection->turnNonce, pTurnConnection->nonceLen,
                                                                      DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS, &pTurnConnection->pTurnPacket));

                pTurnConnection->state = TURN_STATE_ALLOCATION;
                pTurnConnection->stateTimeoutTime = currentTime + DEFAULT_TURN_ALLOCATION_TIMEOUT;
            }
            // 未获取凭证
            else {
                CHK(currentTime < pTurnConnection->stateTimeoutTime, STATUS_TURN_CONNECTION_STATE_TRANSITION_TIMEOUT);
            }
            break;

        // allocation
        case TURN_STATE_ALLOCATION:

            // 已创建allocation
            if (ATOMIC_LOAD_BOOL(&pTurnConnection->hasAllocation)) {
                // 获取IP 字符串
                CHK_STATUS(getIpAddrStr(&pTurnConnection->relayAddress, ipAddrStr, ARRAY_SIZE(ipAddrStr)));
                DLOGD("Relay address received: %s, port: %u", ipAddrStr, (UINT16) getInt16(pTurnConnection->relayAddress.port));

                // 回收已存在pTurnCreatePermissionPacket
                if (pTurnConnection->pTurnCreatePermissionPacket != NULL) {
                    CHK_STATUS(freeStunPacket(&pTurnConnection->pTurnCreatePermissionPacket));
                }
                // 第二参数为NULL 事务ID随机生成
                CHK_STATUS(createStunPacket(STUN_PACKET_TYPE_CREATE_PERMISSION, NULL, &pTurnConnection->pTurnCreatePermissionPacket));
                // use host address as placeholder. hostAddress should have the same family as peer address
                // 添加peer 地址属性
                CHK_STATUS(appendStunAddressAttribute(pTurnConnection->pTurnCreatePermissionPacket, STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS,
                                                      &pTurnConnection->hostAddress));
                // 添加username属性
                CHK_STATUS(appendStunUsernameAttribute(pTurnConnection->pTurnCreatePermissionPacket, pTurnConnection->turnServer.username));
                
                // 添加realm属性
                CHK_STATUS(appendStunRealmAttribute(pTurnConnection->pTurnCreatePermissionPacket, pTurnConnection->turnRealm));
                
                // 添加nonce属性
                CHK_STATUS(
                    appendStunNonceAttribute(pTurnConnection->pTurnCreatePermissionPacket, pTurnConnection->turnNonce, pTurnConnection->nonceLen));

                // create channel bind packet here too so for each peer as soon as permission is created, it can start
                // sending chaneel bind request
                if (pTurnConnection->pTurnChannelBindPacket != NULL) {
                    CHK_STATUS(freeStunPacket(&pTurnConnection->pTurnChannelBindPacket));
                }

                // 第二个参数为NULL 事务ID随机生成
                CHK_STATUS(createStunPacket(STUN_PACKET_TYPE_CHANNEL_BIND_REQUEST, NULL, &pTurnConnection->pTurnChannelBindPacket));
                // use host address as placeholder
                
                // 添加peer 地址属性
                CHK_STATUS(appendStunAddressAttribute(pTurnConnection->pTurnChannelBindPacket, STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS,
                                                      &pTurnConnection->hostAddress));
                
                // 添加channel number属性
                CHK_STATUS(appendStunChannelNumberAttribute(pTurnConnection->pTurnChannelBindPacket, 0));
                
                // 添加username属性
                CHK_STATUS(appendStunUsernameAttribute(pTurnConnection->pTurnChannelBindPacket, pTurnConnection->turnServer.username));
                
                // 添加realm 属性
                CHK_STATUS(appendStunRealmAttribute(pTurnConnection->pTurnChannelBindPacket, pTurnConnection->turnRealm));
                
                // 添加nonce属性
                CHK_STATUS(appendStunNonceAttribute(pTurnConnection->pTurnChannelBindPacket, pTurnConnection->turnNonce, pTurnConnection->nonceLen));

                if (pTurnConnection->pTurnAllocationRefreshPacket != NULL) {
                    CHK_STATUS(freeStunPacket(&pTurnConnection->pTurnAllocationRefreshPacket));
                }
                // 事务ID随机生成(NULL)
                CHK_STATUS(createStunPacket(STUN_PACKET_TYPE_REFRESH, NULL, &pTurnConnection->pTurnAllocationRefreshPacket));
                
                // 添加allocation 生命周期
                CHK_STATUS(appendStunLifetimeAttribute(pTurnConnection->pTurnAllocationRefreshPacket, DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS));
                
                // 添加username 属性
                CHK_STATUS(appendStunUsernameAttribute(pTurnConnection->pTurnAllocationRefreshPacket, pTurnConnection->turnServer.username));
                
                // 添加realm属性
                CHK_STATUS(appendStunRealmAttribute(pTurnConnection->pTurnAllocationRefreshPacket, pTurnConnection->turnRealm));
                
                // 添加nonce属性
                CHK_STATUS(
                    appendStunNonceAttribute(pTurnConnection->pTurnAllocationRefreshPacket, pTurnConnection->turnNonce, pTurnConnection->nonceLen));

                pTurnConnection->state = TURN_STATE_CREATE_PERMISSION;
                pTurnConnection->stateTimeoutTime = currentTime + DEFAULT_TURN_CREATE_PERMISSION_TIMEOUT;

            } else {
                CHK(currentTime < pTurnConnection->stateTimeoutTime, STATUS_TURN_CONNECTION_STATE_TRANSITION_TIMEOUT);
            }
            break;

        // 创建许可
        case TURN_STATE_CREATE_PERMISSION:

            for (i = 0; i < pTurnConnection->turnPeerCount; ++i) {
                // As soon as create permission succeeded, we start sending channel bind message.
                // So connectionState could've already advanced to ready state.
                if (pTurnConnection->turnPeerList[i].connectionState == TURN_PEER_CONN_STATE_BIND_CHANNEL ||
                    pTurnConnection->turnPeerList[i].connectionState == TURN_PEER_CONN_STATE_READY) {
                    channelWithPermissionCount++;
                }
            }

            // push back timeout if no peer is available yet
            if (pTurnConnection->turnPeerCount == 0) {
                pTurnConnection->stateTimeoutTime = currentTime + DEFAULT_TURN_CREATE_PERMISSION_TIMEOUT;
                CHK(FALSE, retStatus);
            }

            if (currentTime >= pTurnConnection->stateTimeoutTime) {
                CHK(channelWithPermissionCount > 0, STATUS_TURN_CONNECTION_FAILED_TO_CREATE_PERMISSION);

                // go to next state if we have at least one ready peer
                pTurnConnection->state = TURN_STATE_BIND_CHANNEL;
                pTurnConnection->stateTimeoutTime = currentTime + DEFAULT_TURN_BIND_CHANNEL_TIMEOUT;
            }
            break;

        // 绑定channel
        case TURN_STATE_BIND_CHANNEL:

            for (i = 0; i < pTurnConnection->turnPeerCount; ++i) {
                if (pTurnConnection->turnPeerList[i].connectionState == TURN_PEER_CONN_STATE_READY) {
                    readyPeerCount++;
                }
            }

            if (currentTime >= pTurnConnection->stateTimeoutTime || readyPeerCount == pTurnConnection->turnPeerCount) {
                CHK(readyPeerCount > 0, STATUS_TURN_CONNECTION_FAILED_TO_BIND_CHANNEL);
                // go to next state if we have at least one ready peer
                pTurnConnection->state = TURN_STATE_READY;
            }
            break;

        // 就绪
        case TURN_STATE_READY:

            // 检测是否需要刷新
            CHK_STATUS(turnConnectionRefreshPermission(pTurnConnection, &refreshPeerPermission));
            // 需要刷新
            if (refreshPeerPermission) {
                // reset pTurnPeer->connectionState to make them go through create permission and channel bind again
                for (i = 0; i < pTurnConnection->turnPeerCount; ++i) {
                    pTurnConnection->turnPeerList[i].connectionState = TURN_PEER_CONN_STATE_CREATE_PERMISSION;
                }

                pTurnConnection->currentTimerCallingPeriod = DEFAULT_TURN_TIMER_INTERVAL_BEFORE_READY;
                CHK_STATUS(timerQueueUpdateTimerPeriod(pTurnConnection->timerQueueHandle, (UINT64) pTurnConnection,
                                                       (UINT32) ATOMIC_LOAD(&pTurnConnection->timerCallbackId),
                                                       pTurnConnection->currentTimerCallingPeriod));
                pTurnConnection->state = TURN_STATE_CREATE_PERMISSION;
                pTurnConnection->stateTimeoutTime = currentTime + DEFAULT_TURN_CREATE_PERMISSION_TIMEOUT;
            } else if (pTurnConnection->currentTimerCallingPeriod != DEFAULT_TURN_TIMER_INTERVAL_AFTER_READY) {
                // use longer timer interval as now it just needs to check disconnection and permission expiration.
                pTurnConnection->currentTimerCallingPeriod = DEFAULT_TURN_TIMER_INTERVAL_AFTER_READY;
                CHK_STATUS(timerQueueUpdateTimerPeriod(pTurnConnection->timerQueueHandle, (UINT64) pTurnConnection,
                                                       (UINT32) ATOMIC_LOAD(&pTurnConnection->timerCallbackId),
                                                       pTurnConnection->currentTimerCallingPeriod));
            }

            break;

        // 清理
        case TURN_STATE_CLEAN_UP:
            /* start cleanning up even if we dont receive allocation freed response in time, or if connection is already closed,
             * since we already sent multiple STUN refresh packets with 0 lifetime. */
            // socketConnection 转态为Closed
            // 没有allocation
            // 超时
            if (socketConnectionIsClosed(pTurnConnection->pControlChannel) || !ATOMIC_LOAD_BOOL(&pTurnConnection->hasAllocation) ||
                currentTime >= pTurnConnection->stateTimeoutTime) {
                // clean transactionId store for each turn peer, preserving the peers
                // 清理 所有TurnPeer 的事务ID Store
                for (i = 0; i < pTurnConnection->turnPeerCount; ++i) {
                    transactionIdStoreClear(pTurnConnection->turnPeerList[i].pTransactionIdStore);
                }
                // 回收预先创建的STUN Packet
                CHK_STATUS(turnConnectionFreePreAllocatedPackets(pTurnConnection));
                // 关闭socket Connection
                CHK_STATUS(socketConnectionClosed(pTurnConnection->pControlChannel));
                pTurnConnection->state = STATUS_SUCCEEDED(pTurnConnection->errorStatus) ? TURN_STATE_NEW : TURN_STATE_FAILED;
                ATOMIC_STORE_BOOL(&pTurnConnection->shutdownComplete, TRUE);
            }

            break;

        // 错误
        case TURN_STATE_FAILED:
            DLOGW("TurnConnection in TURN_STATE_FAILED due to 0x%08x. Aborting TurnConnection", pTurnConnection->errorStatus);
            /* Since we are aborting, not gonna do cleanup */
            ATOMIC_STORE_BOOL(&pTurnConnection->hasAllocation, FALSE);
            /* If we haven't done cleanup, go to cleanup state which will do the cleanup then go to failed state again. */
            // 关闭未完成，转状态-->清理
            if (!ATOMIC_LOAD_BOOL(&pTurnConnection->shutdownComplete)) {
                pTurnConnection->state = TURN_STATE_CLEAN_UP;
                pTurnConnection->stateTimeoutTime = currentTime + DEFAULT_TURN_CLEAN_UP_TIMEOUT;
            }

            break;

        default:
            break;
    }

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (STATUS_SUCCEEDED(retStatus) && ATOMIC_LOAD_BOOL(&pTurnConnection->stopTurnConnection) && pTurnConnection->state != TURN_STATE_CLEAN_UP &&
        pTurnConnection->state != TURN_STATE_NEW) {
        pTurnConnection->state = TURN_STATE_CLEAN_UP;
        pTurnConnection->stateTimeoutTime = currentTime + DEFAULT_TURN_CLEAN_UP_TIMEOUT;
    }

    /* move to failed state if retStatus is failed status and state is not yet TURN_STATE_FAILED */
    if (STATUS_FAILED(retStatus) && pTurnConnection->state != TURN_STATE_FAILED) {
        pTurnConnection->errorStatus = retStatus;
        pTurnConnection->state = TURN_STATE_FAILED;
        /* fix up state to trigger transition into TURN_STATE_FAILED  */
        retStatus = STATUS_SUCCESS;
    }

    if (pTurnConnection != NULL && previousState != pTurnConnection->state) {
        DLOGD("TurnConnection state changed from %s to %s", turnConnectionGetStateStr(previousState),
              turnConnectionGetStateStr(pTurnConnection->state));
    }

    LEAVES();
    return retStatus;
}

// turnConnection 更新nonce
STATUS turnConnectionUpdateNonce(PTurnConnection pTurnConnection)
{
    STATUS retStatus = STATUS_SUCCESS;

    // assume holding pTurnConnection->lock

    // update nonce for pre-created packets

    // 更新nonce属性
    if (pTurnConnection->pTurnPacket != NULL) {
        CHK_STATUS(updateStunNonceAttribute(pTurnConnection->pTurnPacket, pTurnConnection->turnNonce, pTurnConnection->nonceLen));
    }

    if (pTurnConnection->pTurnAllocationRefreshPacket != NULL) {
        CHK_STATUS(updateStunNonceAttribute(pTurnConnection->pTurnAllocationRefreshPacket, pTurnConnection->turnNonce, pTurnConnection->nonceLen));
    }

    if (pTurnConnection->pTurnChannelBindPacket != NULL) {
        CHK_STATUS(updateStunNonceAttribute(pTurnConnection->pTurnChannelBindPacket, pTurnConnection->turnNonce, pTurnConnection->nonceLen));
    }

    if (pTurnConnection->pTurnCreatePermissionPacket != NULL) {
        CHK_STATUS(updateStunNonceAttribute(pTurnConnection->pTurnCreatePermissionPacket, pTurnConnection->turnNonce, pTurnConnection->nonceLen));
    }

CleanUp:

    CHK_LOG_ERR(retStatus);
    return retStatus;
}

// 关闭turnConnection
STATUS turnConnectionShutdown(PTurnConnection pTurnConnection, UINT64 waitUntilAllocationFreedTimeout)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT64 currentTime = 0, timeoutTime = 0;
    BOOL locked = FALSE;
    CHK(pTurnConnection != NULL, STATUS_NULL_ARG);

    // 设置stopTurnConnection 标志
    ATOMIC_STORE(&pTurnConnection->stopTurnConnection, TRUE);

    // 加锁
    MUTEX_LOCK(pTurnConnection->lock);
    locked = TRUE;

    CHK(ATOMIC_LOAD_BOOL(&pTurnConnection->hasAllocation), retStatus);

    if (waitUntilAllocationFreedTimeout > 0) {
        // 获取当前时间
        currentTime = GETTIME();
        timeoutTime = currentTime + waitUntilAllocationFreedTimeout;

        while (ATOMIC_LOAD_BOOL(&pTurnConnection->hasAllocation) && currentTime < timeoutTime) {
            CVAR_WAIT(pTurnConnection->freeAllocationCvar, pTurnConnection->lock, waitUntilAllocationFreedTimeout);
            currentTime = GETTIME();
        }

        // 超时
        if (ATOMIC_LOAD_BOOL(&pTurnConnection->hasAllocation)) {
            DLOGD("Failed to free turn allocation within timeout of %" PRIu64 " milliseconds",
                  waitUntilAllocationFreedTimeout / HUNDREDS_OF_NANOS_IN_A_MILLISECOND);
        }
    }

CleanUp:

    CHK_LOG_ERR(retStatus);

    // 解锁
    if (locked) {
        MUTEX_UNLOCK(pTurnConnection->lock);
    }

    return retStatus;
}

// 判断TurnConnection 是否关闭完成
BOOL turnConnectionIsShutdownComplete(PTurnConnection pTurnConnection)
{
    if (pTurnConnection == NULL) {
        return TRUE;
    } else {
        return ATOMIC_LOAD_BOOL(&pTurnConnection->shutdownComplete);
    }
}

// 获取中继地址
BOOL turnConnectionGetRelayAddress(PTurnConnection pTurnConnection, PKvsIpAddress pKvsIpAddress)
{
    // turn connection 无allocation
    if (pTurnConnection == NULL || !ATOMIC_LOAD_BOOL(&pTurnConnection->hasAllocation)) {
        return FALSE;
    }
    // turn connectin 有allocation
    else if (pKvsIpAddress != NULL) {
        // 加锁
        MUTEX_LOCK(pTurnConnection->lock);
        *pKvsIpAddress = pTurnConnection->relayAddress;
        // 解锁
        MUTEX_UNLOCK(pTurnConnection->lock);
        return TRUE;
    }

    return FALSE;
}


STATUS turnConnectionTimerCallback(UINT32 timerId, UINT64 currentTime, UINT64 customData)
{
    UNUSED_PARAM(timerId);
    UNUSED_PARAM(currentTime);
    STATUS retStatus = STATUS_SUCCESS, sendStatus = STATUS_SUCCESS;
    PTurnConnection pTurnConnection = (PTurnConnection) customData;
    BOOL locked = FALSE, stopScheduling = FALSE;
    PTurnPeer pTurnPeer = NULL;
    PStunAttributeAddress pStunAttributeAddress = NULL;
    PStunAttributeChannelNumber pStunAttributeChannelNumber = NULL;
    PStunAttributeLifetime pStunAttributeLifetime = NULL;
    UINT32 i = 0;

    CHK(pTurnConnection != NULL, STATUS_NULL_ARG);

    MUTEX_LOCK(pTurnConnection->lock);
    locked = TRUE;

    switch (pTurnConnection->state) {
        case TURN_STATE_GET_CREDENTIALS:
            sendStatus = iceUtilsSendStunPacket(pTurnConnection->pTurnPacket, NULL, 0, &pTurnConnection->turnServer.ipAddress,
                                                pTurnConnection->pControlChannel, NULL, FALSE);
            break;

        case TURN_STATE_ALLOCATION:
            sendStatus = iceUtilsSendStunPacket(pTurnConnection->pTurnPacket, pTurnConnection->longTermKey, ARRAY_SIZE(pTurnConnection->longTermKey),
                                                &pTurnConnection->turnServer.ipAddress, pTurnConnection->pControlChannel, NULL, FALSE);
            break;

        case TURN_STATE_CREATE_PERMISSION:
            // explicit fall-through
        case TURN_STATE_BIND_CHANNEL:
            // explicit fall-through
        case TURN_STATE_READY:
            for (i = 0; i < pTurnConnection->turnPeerCount; ++i) {
                pTurnPeer = &pTurnConnection->turnPeerList[i];

                if (pTurnPeer->connectionState == TURN_PEER_CONN_STATE_CREATE_PERMISSION) {
                    // update peer address;
                    CHK_STATUS(getStunAttribute(pTurnConnection->pTurnCreatePermissionPacket, STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS,
                                                (PStunAttributeHeader*) &pStunAttributeAddress));
                    CHK_WARN(pStunAttributeAddress != NULL, STATUS_INTERNAL_ERROR, "xor peer address attribute not found");
                    pStunAttributeAddress->address = pTurnPeer->address;

                    CHK_STATUS(iceUtilsGenerateTransactionId(pTurnConnection->pTurnCreatePermissionPacket->header.transactionId,
                                                             ARRAY_SIZE(pTurnConnection->pTurnCreatePermissionPacket->header.transactionId)));

                    CHK(pTurnPeer->pTransactionIdStore != NULL, STATUS_INVALID_OPERATION);
                    transactionIdStoreInsert(pTurnPeer->pTransactionIdStore, pTurnConnection->pTurnCreatePermissionPacket->header.transactionId);
                    sendStatus = iceUtilsSendStunPacket(pTurnConnection->pTurnCreatePermissionPacket, pTurnConnection->longTermKey,
                                                        ARRAY_SIZE(pTurnConnection->longTermKey), &pTurnConnection->turnServer.ipAddress,
                                                        pTurnConnection->pControlChannel, NULL, FALSE);

                } else if (pTurnPeer->connectionState == TURN_PEER_CONN_STATE_BIND_CHANNEL) {
                    // update peer address;
                    CHK_STATUS(getStunAttribute(pTurnConnection->pTurnChannelBindPacket, STUN_ATTRIBUTE_TYPE_XOR_PEER_ADDRESS,
                                                (PStunAttributeHeader*) &pStunAttributeAddress));
                    CHK_WARN(pStunAttributeAddress != NULL, STATUS_INTERNAL_ERROR, "xor peer address attribute not found");
                    pStunAttributeAddress->address = pTurnPeer->address;

                    // update channel number
                    CHK_STATUS(getStunAttribute(pTurnConnection->pTurnChannelBindPacket, STUN_ATTRIBUTE_TYPE_CHANNEL_NUMBER,
                                                (PStunAttributeHeader*) &pStunAttributeChannelNumber));
                    CHK_WARN(pStunAttributeChannelNumber != NULL, STATUS_INTERNAL_ERROR, "channel number attribute not found");
                    pStunAttributeChannelNumber->channelNumber = pTurnPeer->channelNumber;

                    CHK_STATUS(iceUtilsGenerateTransactionId(pTurnConnection->pTurnChannelBindPacket->header.transactionId,
                                                             ARRAY_SIZE(pTurnConnection->pTurnChannelBindPacket->header.transactionId)));

                    CHK(pTurnPeer->pTransactionIdStore != NULL, STATUS_INVALID_OPERATION);
                    transactionIdStoreInsert(pTurnPeer->pTransactionIdStore, pTurnConnection->pTurnChannelBindPacket->header.transactionId);
                    sendStatus = iceUtilsSendStunPacket(pTurnConnection->pTurnChannelBindPacket, pTurnConnection->longTermKey,
                                                        ARRAY_SIZE(pTurnConnection->longTermKey), &pTurnConnection->turnServer.ipAddress,
                                                        pTurnConnection->pControlChannel, NULL, FALSE);
                }
            }

            CHK_STATUS(turnConnectionRefreshAllocation(pTurnConnection));
            break;

        case TURN_STATE_CLEAN_UP:
            if (ATOMIC_LOAD_BOOL(&pTurnConnection->hasAllocation)) {
                CHK_STATUS(getStunAttribute(pTurnConnection->pTurnAllocationRefreshPacket, STUN_ATTRIBUTE_TYPE_LIFETIME,
                                            (PStunAttributeHeader*) &pStunAttributeLifetime));
                CHK(pStunAttributeLifetime != NULL, STATUS_INTERNAL_ERROR);
                pStunAttributeLifetime->lifetime = 0;
                sendStatus = iceUtilsSendStunPacket(pTurnConnection->pTurnAllocationRefreshPacket, pTurnConnection->longTermKey,
                                                    ARRAY_SIZE(pTurnConnection->longTermKey), &pTurnConnection->turnServer.ipAddress,
                                                    pTurnConnection->pControlChannel, NULL, FALSE);
                pTurnConnection->deallocatePacketSent = TRUE;
            }

            break;

        case TURN_STATE_FAILED:
            stopScheduling = ATOMIC_LOAD_BOOL(&pTurnConnection->shutdownComplete);
            break;

        default:
            break;
    }

    if (sendStatus == STATUS_SOCKET_CONNECTION_CLOSED_ALREADY) {
        DLOGE("TurnConnection socket %d closed unexpectedly", pTurnConnection->pControlChannel->localSocket);
        turnConnectionFatalError(pTurnConnection, sendStatus);
    }

    /* drive the state machine. */
    CHK_STATUS(turnConnectionStepState(pTurnConnection));

    /* after turnConnectionStepState(), turn state is TURN_STATE_NEW only if TURN_STATE_CLEAN_UP is completed. Thus
     * we can stop the timer. */
    if (pTurnConnection->state == TURN_STATE_NEW) {
        stopScheduling = TRUE;
    }

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (locked) {
        MUTEX_UNLOCK(pTurnConnection->lock);
    }

    if (stopScheduling) {
        retStatus = STATUS_TIMER_QUEUE_STOP_SCHEDULING;
        if (pTurnConnection != NULL) {
            ATOMIC_STORE(&pTurnConnection->timerCallbackId, MAX_UINT32);
        }
    }

    return retStatus;
}

// username:realm:password
// 生成long-term key
STATUS turnConnectionGetLongTermKey(PCHAR username, PCHAR realm, PCHAR password, PBYTE pBuffer, UINT32 bufferLen)
{
    STATUS retStatus = STATUS_SUCCESS;
    CHAR stringBuffer[STUN_MAX_USERNAME_LEN + MAX_ICE_CONFIG_CREDENTIAL_LEN + STUN_MAX_REALM_LEN + 2]; // 2 for two ":" between each value

    CHK(username != NULL && realm != NULL && password != NULL && pBuffer != NULL, STATUS_NULL_ARG);
    CHK(username[0] != '\0' && realm[0] != '\0' && password[0] != '\0' && bufferLen >= KVS_MD5_DIGEST_LENGTH, STATUS_INVALID_ARG);
    CHK((STRLEN(username) + STRLEN(realm) + STRLEN(password)) <= ARRAY_SIZE(stringBuffer) - 2, STATUS_INVALID_ARG);

    SPRINTF(stringBuffer, "%s:%s:%s", username, realm, password);

    // TODO: Return back the error check
    KVS_MD5_DIGEST((PBYTE) stringBuffer, STRLEN(stringBuffer), pBuffer);

CleanUp:

    return retStatus;
}

// 构建TurnConnection allocation Request 包
STATUS turnConnectionPackageTurnAllocationRequest(PCHAR username, PCHAR realm, PBYTE nonce, UINT16 nonceLen, UINT32 lifetime,
                                                  PStunPacket* ppStunPacket)
{
    STATUS retStatus = STATUS_SUCCESS;
    PStunPacket pTurnAllocateRequest = NULL;

    CHK(ppStunPacket != NULL, STATUS_NULL_ARG);
    CHK((username == NULL && realm == NULL && nonce == NULL) || (username != NULL && realm != NULL && nonce != NULL && nonceLen > 0),
        STATUS_INVALID_ARG);

    // 创建STUN Packet
    CHK_STATUS(createStunPacket(STUN_PACKET_TYPE_ALLOCATE, NULL, &pTurnAllocateRequest));
    // 追加allocation 生命周期属性
    CHK_STATUS(appendStunLifetimeAttribute(pTurnAllocateRequest, lifetime));
    // 追加通信协议属性
    CHK_STATUS(appendStunRequestedTransportAttribute(pTurnAllocateRequest, (UINT8) TURN_REQUEST_TRANSPORT_UDP));

    // either username, realm and nonce are all null or all not null
    if (username != NULL) {
        // 追加username 属性
        CHK_STATUS(appendStunUsernameAttribute(pTurnAllocateRequest, username));
        // 追加realm 属性
        CHK_STATUS(appendStunRealmAttribute(pTurnAllocateRequest, realm));
        // 追加nonce 属性
        CHK_STATUS(appendStunNonceAttribute(pTurnAllocateRequest, nonce, nonceLen));
    }

CleanUp:

    // 回收StunPacket 资源
    if (STATUS_FAILED(retStatus) && pTurnAllocateRequest != NULL) {
        freeStunPacket(&pTurnAllocateRequest);
        pTurnAllocateRequest = NULL;
    }

    if (pTurnAllocateRequest != NULL && ppStunPacket != NULL) {
        *ppStunPacket = pTurnAllocateRequest;
    }

    return retStatus;
}

// 获取TurnConnection 状态字符串
PCHAR turnConnectionGetStateStr(TURN_CONNECTION_STATE state)
{
    switch (state) {
        case TURN_STATE_NEW:
            return TURN_STATE_NEW_STR;
        case TURN_STATE_CHECK_SOCKET_CONNECTION:
            return TURN_STATE_CHECK_SOCKET_CONNECTION_STR;
        case TURN_STATE_GET_CREDENTIALS:
            return TURN_STATE_GET_CREDENTIALS_STR;
        case TURN_STATE_ALLOCATION:
            return TURN_STATE_ALLOCATION_STR;
        case TURN_STATE_CREATE_PERMISSION:
            return TURN_STATE_CREATE_PERMISSION_STR;
        case TURN_STATE_BIND_CHANNEL:
            return TURN_STATE_BIND_CHANNEL_STR;
        case TURN_STATE_READY:
            return TURN_STATE_READY_STR;
        case TURN_STATE_CLEAN_UP:
            return TURN_STATE_CLEAN_UP_STR;
        case TURN_STATE_FAILED:
            return TURN_STATE_FAILED_STR;
    }
    return TURN_STATE_UNKNOWN_STR;
}

// 根据channel number 获取TurnPeer
PTurnPeer turnConnectionGetPeerWithChannelNumber(PTurnConnection pTurnConnection, UINT16 channelNumber)
{
    PTurnPeer pTurnPeer = NULL;
    UINT32 i = 0;

    for (; i < pTurnConnection->turnPeerCount; ++i) {
        if (pTurnConnection->turnPeerList[i].channelNumber == channelNumber) {
            pTurnPeer = &pTurnConnection->turnPeerList[i];
        }
    }

    return pTurnPeer;
}

// 根据IP 获取TurnPeer
PTurnPeer turnConnectionGetPeerWithIp(PTurnConnection pTurnConnection, PKvsIpAddress pKvsIpAddress)
{
    PTurnPeer pTurnPeer = NULL;
    UINT32 i = 0;

    for (; i < pTurnConnection->turnPeerCount; ++i) {
        if (isSameIpAddress(&pTurnConnection->turnPeerList[i].address, pKvsIpAddress, TRUE)) {
            pTurnPeer = &pTurnConnection->turnPeerList[i];
        }
    }

    return pTurnPeer;
}

// 设置TurnConnection错误状态
VOID turnConnectionFatalError(PTurnConnection pTurnConnection, STATUS errorStatus)
{
    if (pTurnConnection == NULL) {
        return;
    }

    /* Assume holding pTurnConnection->lock */
    pTurnConnection->errorStatus = errorStatus;
    pTurnConnection->state = TURN_STATE_FAILED;
}
