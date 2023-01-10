#define LOG_CLASS "IOBuffer"
#include "../Include_i.h"

// 创建IOBuffer
STATUS createIOBuffer(UINT32 initialCap, PIOBuffer* ppBuffer)
{
    STATUS retStatus = STATUS_SUCCESS;
    PIOBuffer pBuffer = NULL;

    // 分配内存
    pBuffer = (PIOBuffer) MEMCALLOC(SIZEOF(IOBuffer), 1);
    CHK(pBuffer != NULL, STATUS_NOT_ENOUGH_MEMORY);


    if (initialCap != 0) {
        pBuffer->raw = (PBYTE) MEMALLOC(initialCap);
        CHK(pBuffer->raw != NULL, STATUS_NOT_ENOUGH_MEMORY);
        pBuffer->cap = initialCap;
    }

    *ppBuffer = pBuffer;

CleanUp:

    if (STATUS_FAILED(retStatus) && pBuffer != NULL) {
        freeIOBuffer(&pBuffer);
    }

    return retStatus;
}

// 回收IOBuffer资源
STATUS freeIOBuffer(PIOBuffer* ppBuffer)
{
    STATUS retStatus = STATUS_SUCCESS;
    PIOBuffer pBuffer;

    CHK(ppBuffer != NULL, STATUS_NULL_ARG);

    pBuffer = *ppBuffer;
    CHK(pBuffer != NULL, retStatus);

    MEMFREE(pBuffer->raw);
    SAFE_MEMFREE(*ppBuffer);

CleanUp:

    return retStatus;
}

// 重置IOBuffer
STATUS ioBufferReset(PIOBuffer pBuffer)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pBuffer != NULL, STATUS_NULL_ARG);

    pBuffer->len = 0;
    pBuffer->off = 0;

CleanUp:

    return retStatus;
}

STATUS ioBufferWrite(PIOBuffer pBuffer, PBYTE pData, UINT32 dataLen)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 freeSpace;
    UINT32 newCap;

    CHK(pBuffer != NULL && pData != NULL, STATUS_NULL_ARG);

    freeSpace = pBuffer->cap - pBuffer->len;
    // 空间不足，调整buffer大小
    if (freeSpace < dataLen) {
        newCap = pBuffer->len + dataLen;
        pBuffer->raw = MEMREALLOC(pBuffer->raw, newCap);
        CHK(pBuffer->raw != NULL, STATUS_NOT_ENOUGH_MEMORY);
        pBuffer->cap = newCap;
    }

    MEMCPY(pBuffer->raw + pBuffer->len, pData, dataLen);
    pBuffer->len += dataLen;

CleanUp:

    return retStatus;
}

// 读取IOBuffer
STATUS ioBufferRead(PIOBuffer pBuffer, PBYTE pData, UINT32 bufferLen, PUINT32 pDataLen)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 dataLen;

    CHK(pBuffer != NULL && pDataLen != NULL, STATUS_NULL_ARG);

    dataLen = MIN(bufferLen, pBuffer->len - pBuffer->off);

    MEMCPY(pData, pBuffer->raw + pBuffer->off, dataLen);
    pBuffer->off += dataLen;

    // buffer数据已读完，len = 0,off = 0
    if (pBuffer->off == pBuffer->len) {
        ioBufferReset(pBuffer);
    }

    *pDataLen = dataLen;

CleanUp:

    return retStatus;
}
