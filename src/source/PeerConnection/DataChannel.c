#define LOG_CLASS "DataChannel"

#include "../Include_i.h"

// 连接本地DataChannel
STATUS connectLocalDataChannel()
{
    return STATUS_SUCCESS;
}

// 创建DataChannel
STATUS createDataChannel(PRtcPeerConnection pPeerConnection, PCHAR pDataChannelName, PRtcDataChannelInit pRtcDataChannelInit,
                         PRtcDataChannel* ppRtcDataChannel)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PKvsPeerConnection pKvsPeerConnection = (PKvsPeerConnection) pPeerConnection;
    UINT32 channelId = 0;
    PKvsDataChannel pKvsDataChannel = NULL;

    CHK(pKvsPeerConnection != NULL && pDataChannelName != NULL && ppRtcDataChannel != NULL, STATUS_NULL_ARG);

    // Only support creating DataChannels before signaling for now
    CHK(pKvsPeerConnection->pSctpSession == NULL, STATUS_INTERNAL_ERROR);

    // 分配内存
    CHK((pKvsDataChannel = (PKvsDataChannel) MEMCALLOC(1, SIZEOF(KvsDataChannel))) != NULL, STATUS_NOT_ENOUGH_MEMORY);
    
    // 设置信令通道名
    STRNCPY(pKvsDataChannel->dataChannel.name, pDataChannelName, MAX_DATA_CHANNEL_NAME_LEN);
    pKvsDataChannel->pRtcPeerConnection = (PRtcPeerConnection) pKvsPeerConnection;
    if (pRtcDataChannelInit != NULL) {
        // Setting negotiated to false. Not supporting at the moment
        pRtcDataChannelInit->negotiated = FALSE;
        pKvsDataChannel->rtcDataChannelInit = *pRtcDataChannelInit;
    } else {
        // If nothing is set, set default to ordered mode
        pKvsDataChannel->rtcDataChannelInit.ordered = FALSE; // 不按顺序发送
        NULLABLE_SET_EMPTY(pKvsDataChannel->rtcDataChannelInit.maxPacketLifeTime); // 限制时间
        NULLABLE_SET_EMPTY(pKvsDataChannel->rtcDataChannelInit.maxRetransmits); // 重传次数
    }
    STRNCPY(pKvsDataChannel->rtcDataChannelDiagnostics.label, pKvsDataChannel->dataChannel.name, STRLEN(pKvsDataChannel->dataChannel.name));
    // 设置DataChannel 状态
    // RTC_DATA_CHANNEL_STATE_CONNECTING, 
    // RTC_DATA_CHANNEL_STATE_OPEN,  可发数据，触发onOpen回调 
    // RTC_DATA_CHANNEL_STATE_CLOSING,    
    // RTC_DATA_CHANNEL_STATE_CLOSED
    pKvsDataChannel->rtcDataChannelDiagnostics.state = RTC_DATA_CHANNEL_STATE_CONNECTING;
    CHK_STATUS(hashTableGetCount(pKvsPeerConnection->pDataChannels, &channelId));
    // 设置DataChannel ID
    pKvsDataChannel->rtcDataChannelDiagnostics.dataChannelIdentifier = channelId;
    pKvsDataChannel->dataChannel.id = channelId;
    // 设置协议
    STRNCPY(pKvsDataChannel->rtcDataChannelDiagnostics.protocol, DATA_CHANNEL_PROTOCOL_STR,
            ARRAY_SIZE(pKvsDataChannel->rtcDataChannelDiagnostics.protocol));
    CHK_STATUS(hashTablePut(pKvsPeerConnection->pDataChannels, channelId, (UINT64) pKvsDataChannel));

CleanUp:
    if (STATUS_SUCCEEDED(retStatus)) {
        *ppRtcDataChannel = (PRtcDataChannel) pKvsDataChannel;
    } else {
        SAFE_MEMFREE(pKvsDataChannel);
    }

    LEAVES();
    return retStatus;
}

// 发送数据
STATUS dataChannelSend(PRtcDataChannel pRtcDataChannel, BOOL isBinary, PBYTE pMessage, UINT32 pMessageLen)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSctpSession pSctpSession = NULL;
    PKvsDataChannel pKvsDataChannel = (PKvsDataChannel) pRtcDataChannel;

    CHK(pKvsDataChannel != NULL && pMessage != NULL, STATUS_NULL_ARG);

    pSctpSession = ((PKvsPeerConnection) pKvsDataChannel->pRtcPeerConnection)->pSctpSession;

    // 使用Sctp 发送消息
    CHK_STATUS(sctpSessionWriteMessage(pSctpSession, pKvsDataChannel->channelId, isBinary, pMessage, pMessageLen));
    // 发送统计
    pKvsDataChannel->rtcDataChannelDiagnostics.messagesSent++;
    pKvsDataChannel->rtcDataChannelDiagnostics.bytesSent += pMessageLen;
CleanUp:

    return retStatus;
}

// 设置onMessage回调、数据
STATUS dataChannelOnMessage(PRtcDataChannel pRtcDataChannel, UINT64 customData, RtcOnMessage rtcOnMessage)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PKvsDataChannel pKvsDataChannel = (PKvsDataChannel) pRtcDataChannel;

    CHK(pKvsDataChannel != NULL && rtcOnMessage != NULL, STATUS_NULL_ARG);

    pKvsDataChannel->onMessage = rtcOnMessage; // 设置收到message回调函数
    pKvsDataChannel->onMessageCustomData = customData; // 数据

CleanUp:

    LEAVES();
    return retStatus;
}

// 设置onOpen回调、数据
STATUS dataChannelOnOpen(PRtcDataChannel pRtcDataChannel, UINT64 customData, RtcOnOpen rtcOnOpen)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PKvsDataChannel pKvsDataChannel = (PKvsDataChannel) pRtcDataChannel;

    CHK(pKvsDataChannel != NULL && rtcOnOpen != NULL, STATUS_NULL_ARG);

    pKvsDataChannel->onOpen = rtcOnOpen; // 设置onOpen回调函数
    pKvsDataChannel->onOpenCustomData = customData; // 数据

CleanUp:

    LEAVES();
    return retStatus;
}
