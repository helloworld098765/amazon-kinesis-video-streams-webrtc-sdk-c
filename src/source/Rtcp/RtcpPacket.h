/*******************************************
RTCP Packet include file
*******************************************/
#ifndef __KINESIS_VIDEO_WEBRTC_CLIENT_RTCP_RTCPPACKET_H
#define __KINESIS_VIDEO_WEBRTC_CLIENT_RTCP_RTCPPACKET_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define RTCP_PACKET_LEN_OFFSET  2
#define RTCP_PACKET_TYPE_OFFSET 1

#define RTCP_PACKET_RRC_BITMASK 0x1F

// RTCP 头4字节
#define RTCP_PACKET_HEADER_LEN 4
#define RTCP_NACK_LIST_LEN     8

// RTCP 版本，固定2
#define RTCP_PACKET_VERSION_VAL 2

#define RTCP_PACKET_LEN_WORD_SIZE 4

// RTCP REMB最小大小
#define RTCP_PACKET_REMB_MIN_SIZE          16
//  V = 2bits    P = 1bit    FMT = 5bits     PT = 8bits  length = 16bits
//  SSRC of packet sender = 32bits
//  SSRC of media source = 32bits
#define RTCP_PACKET_REMB_IDENTIFIER_OFFSET 8
#define RTCP_PACKET_REMB_MANTISSA_BITMASK  0x3FFFF

#define RTCP_PACKET_SENDER_REPORT_MINLEN      24
#define RTCP_PACKET_RECEIVER_REPORT_BLOCK_LEN 24
#define RTCP_PACKET_RECEIVER_REPORT_MINLEN    4 + RTCP_PACKET_RECEIVER_REPORT_BLOCK_LEN

// https://tools.ietf.org/html/rfc3550#section-4
// If the participant has not yet sent an RTCP packet (the variable
// initial is true), the constant Tmin is set to 2.5 seconds, else it
// is set to 5 seconds.
#define RTCP_FIRST_REPORT_DELAY (3 * HUNDREDS_OF_NANOS_IN_A_SECOND)

#define RTCP_PACKET_SENDER_REPORT_MINLEN      24
#define RTCP_PACKET_RECEIVER_REPORT_BLOCK_LEN 24
#define RTCP_PACKET_RECEIVER_REPORT_MINLEN    4 + RTCP_PACKET_RECEIVER_REPORT_BLOCK_LEN

// https://tools.ietf.org/html/rfc3550#section-4
// If the participant has not yet sent an RTCP packet (the variable
// initial is true), the constant Tmin is set to 2.5 seconds, else it
// is set to 5 seconds.
#define RTCP_FIRST_REPORT_DELAY (3 * HUNDREDS_OF_NANOS_IN_A_SECOND)

typedef enum {
    // 关键帧请求
    RTCP_PACKET_TYPE_FIR = 192, // https://tools.ietf.org/html/rfc2032#section-5.2.1
    // 发送者报告
    RTCP_PACKET_TYPE_SENDER_REPORT = 200,
    // 接受者报告
    RTCP_PACKET_TYPE_RECEIVER_REPORT = 201, // https://tools.ietf.org/html/rfc3550#section-6.4.2
    // 源描述项
    RTCP_PACKET_TYPE_SOURCE_DESCRIPTION = 202,
    // 传输层反馈 RTPFB
    RTCP_PACKET_TYPE_GENERIC_RTP_FEEDBACK = 205,
    // payload反馈 PSFB
    RTCP_PACKET_TYPE_PAYLOAD_SPECIFIC_FEEDBACK = 206,
} RTCP_PACKET_TYPE;

typedef enum {
    // 丢包请求
    RTCP_FEEDBACK_MESSAGE_TYPE_NACK = 1,
    // 图像丢失
    RTCP_PSFB_PLI = 1, // https://tools.ietf.org/html/rfc4585#section-6.3
    // 片丢失
    RTCP_PSFB_SLI = 2, // https://tools.ietf.org/html/rfc4585#section-6.3.2
    // 应用层消息
    RTCP_FEEDBACK_MESSAGE_TYPE_APPLICATION_LAYER_FEEDBACK = 15,
} RTCP_FEEDBACK_MESSAGE_TYPE;

/*
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |V=2|P|    Count   |       PT      |             length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

// RTCP 头
typedef struct {
    UINT8 version;
    UINT8 receptionReportCount;
    RTCP_PACKET_TYPE packetType;

    UINT32 packetLength;
} RtcpPacketHeader, *PRtcpPacketHeader;

// RTCP 包
typedef struct {
    RtcpPacketHeader header;

    PBYTE payload;
    UINT32 payloadLength;
} RtcpPacket, *PRtcpPacket;

STATUS setRtcpPacketFromBytes(PBYTE, UINT32, PRtcpPacket);
STATUS rtcpNackListGet(PBYTE, UINT32, PUINT32, PUINT32, PUINT16, PUINT32);
STATUS rembValueGet(PBYTE, UINT32, PDOUBLE, PUINT32, PUINT8);
STATUS isRembPacket(PBYTE, UINT32);

// 一个是两个时期之间的偏移量。
// Unix 使用位于 1/1/1970-00:00h (UTC) 的纪元，NTP 使用 1/1/1900-00:00h。
// 这导致偏移量相当于 70 年（以秒为单位）（两个日期之间有 17 个闰年，因此偏移量为
// (70*365 + 17)*86400 = 2208988800
#define NTP_OFFSET    2208988800ULL
// 0xffff ffff + 1 = 2 ^ 32
#define NTP_TIMESCALE 4294967296ULL

// converts 100ns precision time to ntp time
UINT64 convertTimestampToNTP(UINT64 time100ns);

#define DLSR_TIMESCALE 65536

// https://tools.ietf.org/html/rfc3550#section-4
// In some fields where a more compact representation is
//   appropriate, only the middle 32 bits are used; that is, the low 16
//   bits of the integer part and the high 16 bits of the fractional part.
#define MID_NTP(ntp_time) (UINT32)((currentTimeNTP >> 16U) & 0xffffffffULL)

#ifdef __cplusplus
}
#endif

#endif //__KINESIS_VIDEO_WEBRTC_CLIENT_RTCP_RTCPPACKET_H
