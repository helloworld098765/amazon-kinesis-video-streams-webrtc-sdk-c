#define LOG_CLASS "DTLS"
#include "../Include_i.h"

// 设置dtls Session OutBoundData回调
STATUS dtlsSessionOnOutBoundData(PDtlsSession pDtlsSession, UINT64 customData, DtlsSessionOutboundPacketFunc callbackFn)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pDtlsSession != NULL && callbackFn != NULL, STATUS_NULL_ARG);

    // 加锁
    MUTEX_LOCK(pDtlsSession->sslLock);
    // 设置回调
    pDtlsSession->dtlsSessionCallbacks.outboundPacketFn = callbackFn;
    // 设置数据
    pDtlsSession->dtlsSessionCallbacks.outBoundPacketFnCustomData = customData;
    // 解锁
    MUTEX_UNLOCK(pDtlsSession->sslLock);

CleanUp:
    return retStatus;
}

// 设置dtls Session StateChange回调
STATUS dtlsSessionOnStateChange(PDtlsSession pDtlsSession, UINT64 customData, DtlsSessionOnStateChange callbackFn)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pDtlsSession != NULL && callbackFn != NULL, STATUS_NULL_ARG);

    // 加锁
    MUTEX_LOCK(pDtlsSession->sslLock);
    // 设置回调函数
    pDtlsSession->dtlsSessionCallbacks.stateChangeFn = callbackFn;
    // 设置数据
    pDtlsSession->dtlsSessionCallbacks.stateChangeFnCustomData = customData;
    // 解锁
    MUTEX_UNLOCK(pDtlsSession->sslLock);

CleanUp:
    LEAVES();
    return retStatus;
}

// dtls 验证证书
STATUS dtlsValidateRtcCertificates(PRtcCertificate pRtcCertificates, PUINT32 pCount)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 i = 0;

    CHK(pCount != NULL, STATUS_NULL_ARG);

    // No certs have been specified
    CHK(pRtcCertificates != NULL, retStatus);

    for (i = 0, *pCount = 0; pRtcCertificates[i].pCertificate != NULL && i < MAX_RTCCONFIGURATION_CERTIFICATES; i++) {
        CHK(pRtcCertificates[i].privateKeySize == 0 || pRtcCertificates[i].pPrivateKey != NULL, STATUS_SSL_INVALID_CERTIFICATE_BITS);
    }

CleanUp:

    // If pRtcCertificates is NULL, default pCount to 0
    if (pCount != NULL) {
        *pCount = i;
    }

    LEAVES();
    return retStatus;
}

// dtls Session 改变状态
STATUS dtlsSessionChangeState(PDtlsSession pDtlsSession, RTC_DTLS_TRANSPORT_STATE newState)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pDtlsSession != NULL, STATUS_NULL_ARG);
    CHK(pDtlsSession->state != newState, retStatus);

    // connecting ---> connected
    if (pDtlsSession->state == RTC_DTLS_TRANSPORT_STATE_CONNECTING && newState == RTC_DTLS_TRANSPORT_STATE_CONNECTED) {
        DLOGD("DTLS init completed. Time taken %" PRIu64 " ms",
              (GETTIME() - pDtlsSession->dtlsSessionStartTime) / HUNDREDS_OF_NANOS_IN_A_MILLISECOND);
    }
    pDtlsSession->state = newState;
    // 调用回调
    if (pDtlsSession->dtlsSessionCallbacks.stateChangeFn != NULL) {
        pDtlsSession->dtlsSessionCallbacks.stateChangeFn(pDtlsSession->dtlsSessionCallbacks.stateChangeFnCustomData, newState);
    }

CleanUp:

    LEAVES();
    return retStatus;
}

// 填充随机伪装位
STATUS dtlsFillPseudoRandomBits(PBYTE pBuf, UINT32 bufSize)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 i;

    CHK(pBuf != NULL, STATUS_NULL_ARG);
    CHK(bufSize >= DTLS_CERT_MIN_SERIAL_NUM_SIZE && bufSize <= DTLS_CERT_MAX_SERIAL_NUM_SIZE, retStatus);

    // 填充
    for (i = 0; i < bufSize; i++) {
        *pBuf++ = (BYTE) (RAND() & 0xFF);
    }

CleanUp:

    LEAVES();
    return retStatus;
}
