#define LOG_CLASS "RtcpPacket"

#include "../Include_i.h"

// 使用字节序列设置RtcpPacket
STATUS setRtcpPacketFromBytes(PBYTE pRawPacket, UINT32 pRawPacketsLen, PRtcpPacket pRtcpPacket)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT16 packetLen = 0;

    CHK(pRtcpPacket != NULL, STATUS_NULL_ARG);
    CHK(pRawPacketsLen >= RTCP_PACKET_HEADER_LEN, STATUS_RTCP_INPUT_PACKET_TOO_SMALL);

    // RTCP packet len is length of packet in 32 bit words - 1
    // We don't assert exact length since this may be a compound packet, it
    // is the callers responsibility to parse subsequent entries
    // 3-4 字节 length字段
    packetLen = getInt16(*(PUINT16) (pRawPacket + RTCP_PACKET_LEN_OFFSET));
    CHK((packetLen + 1) * RTCP_PACKET_LEN_WORD_SIZE <= pRawPacketsLen, STATUS_RTCP_INPUT_PARTIAL_PACKET);

    // 版本 第1字节 高2bits 固定2
    pRtcpPacket->header.version = (pRawPacket[0] >> VERSION_SHIFT) & VERSION_MASK;
    CHK(pRtcpPacket->header.version == RTCP_PACKET_VERSION_VAL, STATUS_RTCP_INPUT_PACKET_INVALID_VERSION);

    // 第1字节 低5bits
    pRtcpPacket->header.receptionReportCount = pRawPacket[0] & RTCP_PACKET_RRC_BITMASK;
    // PayloadType 第2字节 
    pRtcpPacket->header.packetType = pRawPacket[RTCP_PACKET_TYPE_OFFSET];
    pRtcpPacket->header.packetLength = packetLen;

    // 设置长度 length * 4
    pRtcpPacket->payloadLength = packetLen * RTCP_PACKET_LEN_WORD_SIZE;
    // 设置payload 不包含头4字节
    pRtcpPacket->payload = pRawPacket + RTCP_PACKET_LEN_WORD_SIZE;

CleanUp:
    LEAVES();
    return retStatus;
}

// 获取rtcp Nack List
// Given a RTCP Packet list extract the list of SSRCes, since the list of SSRCes may not be know ahead of time (because of BLP)
// we need to allocate the list dynamically
STATUS rtcpNackListGet(PBYTE pPayload, UINT32 payloadLen, PUINT32 pSenderSsrc, PUINT32 pReceiverSsrc, PUINT16 pSequenceNumberList,
                       PUINT32 pSequenceNumberListLen)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    INT32 j;
    UINT16 currentSequenceNumber;
    UINT16 sequenceNumberCount = 0, BLP;
    UINT32 i = RTCP_NACK_LIST_LEN;

    CHK(pPayload != NULL && pSequenceNumberListLen != NULL && pSenderSsrc != NULL && pReceiverSsrc != NULL, STATUS_NULL_ARG);
    CHK(payloadLen >= RTCP_NACK_LIST_LEN && (payloadLen % 4 == 0), STATUS_RTCP_INPUT_NACK_LIST_INVALID);

    // 
    *pSenderSsrc = getInt32(*(PUINT32) pPayload);
    // 
    *pReceiverSsrc = getInt32(*(PUINT32) (pPayload + 4));


    // PID 16bits 丢失RTP包的ID
    // BID 16bits 从 PID 开始接下来 16 个 RTP 数据包的丢失情况
    // 一个 NACK 报文可以携带多个 RTP 序列号，NACK 接收端对这些序列号逐个处理。
    for (; i < payloadLen; i += 4) {
        // 1-2字节PID
        currentSequenceNumber = getInt16(*(PUINT16) (pPayload + i));
        // 3-4字节BLP
        BLP = getInt16(*(PUINT16) (pPayload + i + 2));

        // If pSsrcList is not NULL and we have space push and increment
        if (pSequenceNumberList != NULL && sequenceNumberCount <= *pSequenceNumberListLen) {
            pSequenceNumberList[sequenceNumberCount] = currentSequenceNumber;
        }
        sequenceNumberCount++;

        // 检查BLP 16bits 值为1
        for (j = 0; j < 16; j++) {
            if ((BLP & (1 << j)) >> j) {
                if (pSequenceNumberList != NULL && sequenceNumberCount <= *pSequenceNumberListLen) {
                    pSequenceNumberList[sequenceNumberCount] = (currentSequenceNumber + j + 1);
                }
                sequenceNumberCount++;
            }
        }
    }

CleanUp:
    if (STATUS_SUCCEEDED(retStatus)) {
        *pSequenceNumberListLen = sequenceNumberCount;
    }

    LEAVES();
    return retStatus;
}

// 断言是否是REMB包
// Assert that Application Layer Feedback payload is REMB
STATUS isRembPacket(PBYTE pPayload, UINT32 payloadLen)
{
    STATUS retStatus = STATUS_SUCCESS;
    // R E M B
    const BYTE rembUniqueIdentifier[] = {0x52, 0x45, 0x4d, 0x42};

    CHK(pPayload != NULL, STATUS_NULL_ARG);
    CHK(payloadLen >= RTCP_PACKET_REMB_MIN_SIZE, STATUS_RTCP_INPUT_REMB_TOO_SMALL);
    // 标记是否为REMB
    CHK(MEMCMP(rembUniqueIdentifier, pPayload + RTCP_PACKET_REMB_IDENTIFIER_OFFSET, SIZEOF(rembUniqueIdentifier)) == 0,
        STATUS_RTCP_INPUT_REMB_INVALID);

CleanUp:

    LEAVES();
    return retStatus;
}

// 从RTCP payload提取值
/**
 * Get values from RTCP Payload
 *
 * Parameters:
 *     pPayload         - REMB Payload
 *     payloadLen       - Total length of payload
 *     pMaximumBitRate  - REMB Value
 *     pSsrcList        - buffer to write list of SSRCes into.
 *     pSsrcListLen     - destination PUINT32 to store the count of SSRCes from the incoming REMB.
 */
STATUS rembValueGet(PBYTE pPayload, UINT32 payloadLen, PDOUBLE pMaximumBitRate, PUINT32 pSsrcList, PUINT8 pSsrcListLen)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT8 ssrcListLen = 0, exponent = 0;
    UINT32 mantissa = 0, i;
    DOUBLE maximumBitRate = 0;

    // Unique identifier --> REMB 32bits
    // Num SSRC 8bits 同步源数量；BR Exp 6bits Mantissa的指数
    // BR Mantissa 18bits REMB发送者估计的最大总媒体比特率（忽略所有数据包开销）的尾数
    CHK(pPayload != NULL && pMaximumBitRate != NULL && pSsrcListLen != NULL, STATUS_NULL_ARG);
    CHK(payloadLen >= RTCP_PACKET_REMB_MIN_SIZE, STATUS_RTCP_INPUT_REMB_TOO_SMALL);

    // Unique identifier后的4个字节
    MEMCPY(&mantissa, pPayload + RTCP_PACKET_REMB_IDENTIFIER_OFFSET + SIZEOF(UINT32), SIZEOF(UINT32));
    // 小端转大端
    mantissa = htonl(mantissa);

    // 0000 0000 0000 0011 1111 1111 1111 1111
    mantissa &= RTCP_PACKET_REMB_MANTISSA_BITMASK;

    // 指数，6bits
    exponent = pPayload[RTCP_PACKET_REMB_IDENTIFIER_OFFSET + SIZEOF(UINT32) + SIZEOF(BYTE)] >> 2;
    // mantissa * (2 ^ exponent)
    maximumBitRate = mantissa << exponent;

    // 同步源数量8bits
    // Only populate SSRC list if caller requests
    ssrcListLen = pPayload[RTCP_PACKET_REMB_IDENTIFIER_OFFSET + SIZEOF(UINT32)];
    CHK(payloadLen >= RTCP_PACKET_REMB_MIN_SIZE + (ssrcListLen * SIZEOF(UINT32)), STATUS_RTCP_INPUT_REMB_INVALID);

    // 提取所有SSRC
    for (i = 0; i < ssrcListLen; i++) {
        pSsrcList[i] = getInt32(*(PUINT32) (pPayload + RTCP_PACKET_REMB_IDENTIFIER_OFFSET + 8 + (i * SIZEOF(UINT32))));
    }

CleanUp:
    if (STATUS_SUCCEEDED(retStatus)) {
        *pSsrcListLen = ssrcListLen;
        *pMaximumBitRate = maximumBitRate;
    }

    LEAVES();
    return retStatus;
}

// 将time100ns转换为秒，64bits表示(高32bits-->整数，低32bits--->小数)
// converts 100ns precision time to ntp time
UINT64 convertTimestampToNTP(UINT64 time100ns)
{
    // 转换为秒
    UINT64 sec = time100ns / HUNDREDS_OF_NANOS_IN_A_SECOND;
    // 余数
    UINT64 _100ns = time100ns % HUNDREDS_OF_NANOS_IN_A_SECOND;

    UINT64 ntp_sec = sec + NTP_OFFSET;
    // 低32bits表示小数秒
    // _100ns * (2 ^ 32) / (10 * 1000 * 1000)
    UINT64 ntp_frac = KVS_CONVERT_TIMESCALE(_100ns, HUNDREDS_OF_NANOS_IN_A_SECOND, NTP_TIMESCALE);
    // 高32bits 表示整数秒， 低32bits表示小数秒
    return (ntp_sec << 32U | ntp_frac);
}
