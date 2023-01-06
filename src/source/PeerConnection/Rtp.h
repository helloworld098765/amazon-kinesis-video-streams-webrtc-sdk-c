#ifndef __KINESIS_VIDEO_WEBRTC_CLIENT_PEERCONNECTION_RTP__
#define __KINESIS_VIDEO_WEBRTC_CLIENT_PEERCONNECTION_RTP__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Default MTU comes from libwebrtc
// https://groups.google.com/forum/#!topic/discuss-webrtc/gH5ysR3SoZI
#define DEFAULT_MTU_SIZE                           1200
#define DEFAULT_ROLLING_BUFFER_DURATION_IN_SECONDS 3
#define HIGHEST_EXPECTED_BIT_RATE                  (10 * 1024 * 1024)
#define DEFAULT_SEQ_NUM_BUFFER_SIZE                1000
#define DEFAULT_VALID_INDEX_BUFFER_SIZE            1000
#define DEFAULT_PEER_FRAME_BUFFER_SIZE             (5 * 1024)
#define SRTP_AUTH_TAG_OVERHEAD                     10

// https://www.w3.org/TR/webrtc-stats/#dom-rtcoutboundrtpstreamstats-huge
// Huge frames, by definition, are frames that have an encoded size at least 2.5 times the average size of the frames.
#define HUGE_FRAME_MULTIPLIER 2.5

typedef struct {
    UINT8 payloadType;
    UINT8 rtxPayloadType;           // 重发payloadType
    UINT16 sequenceNumber;          // 序列号
    UINT16 rtxSequenceNumber;       // 重发序列号
    UINT32 ssrc;                    // SSRC
    UINT32 rtxSsrc;                 // 重发SSRC
    PayloadArray payloadArray;      // RTP 负载

    RtcMediaStreamTrack track;      // 媒体轨道
    PRtpRollingBuffer packetBuffer; // 
    PRetransmitter retransmitter;   // 重发器

    UINT64 rtpTimeOffset;
    UINT64 firstFrameWallClockTime; // 100ns precision

    // used for fps calculation
    UINT64 lastKnownFrameCount;
    UINT64 lastKnownFrameCountTime; // 100ns precision

} RtcRtpSender, *PRtcRtpSender;

typedef struct {
    RtcRtpTransceiver transceiver;                  //
    RtcRtpSender sender;                            //发送器

    PKvsPeerConnection pKvsPeerConnection;          //

    UINT32 jitterBufferSsrc;                        // 抖动Buffer SSRC
    PJitterBuffer pJitterBuffer;                    // 抖动Buffer

    UINT64 onFrameCustomData;                       // 数据
    RtcOnFrame onFrame;                             // onFrame回调函数

    UINT64 onBandwidthEstimationCustomData;         //
    RtcOnBandwidthEstimation onBandwidthEstimation; //
    UINT64 onPictureLossCustomData;
    RtcOnPictureLoss onPictureLoss;                 //

    PBYTE peerFrameBuffer;
    UINT32 peerFrameBufferSize;

    UINT32 rtcpReportsTimerId;

    MUTEX statsLock;
    RtcOutboundRtpStreamStats outboundStats;
    RtcRemoteInboundRtpStreamStats remoteInboundStats;
    RtcInboundRtpStreamStats inboundStats;
} KvsRtpTransceiver, *PKvsRtpTransceiver;

STATUS createKvsRtpTransceiver(RTC_RTP_TRANSCEIVER_DIRECTION, PKvsPeerConnection, UINT32, UINT32, PRtcMediaStreamTrack, PJitterBuffer, RTC_CODEC,
                               PKvsRtpTransceiver*);
STATUS freeKvsRtpTransceiver(PKvsRtpTransceiver*);

STATUS kvsRtpTransceiverSetJitterBuffer(PKvsRtpTransceiver, PJitterBuffer);

#define CONVERT_TIMESTAMP_TO_RTP(clockRate, pts) ((UINT64) ((DOUBLE) (pts) * ((DOUBLE) (clockRate) / HUNDREDS_OF_NANOS_IN_A_SECOND)))

STATUS writeRtpPacket(PKvsPeerConnection pKvsPeerConnection, PRtpPacket pRtpPacket);

STATUS hasTransceiverWithSsrc(PKvsPeerConnection pKvsPeerConnection, UINT32 ssrc);
STATUS findTransceiverBySsrc(PKvsPeerConnection pKvsPeerConnection, PKvsRtpTransceiver* ppTransceiver, UINT32 ssrc);

#ifdef __cplusplus
}
#endif
#endif /* __KINESIS_VIDEO_WEBRTC_CLIENT_PEERCONNECTION_RTP__ */
