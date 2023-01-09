#define LOG_CLASS "RollingBuffer"

#include "../Include_i.h"

// 创建RollingBuffer
STATUS createRollingBuffer(UINT32 capacity, FreeDataFunc freeDataFunc, PRollingBuffer* ppRollingBuffer)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PRollingBuffer pRollingBuffer = NULL;
    CHK(capacity != 0, STATUS_INVALID_ARG);

    CHK(ppRollingBuffer != NULL, STATUS_NULL_ARG);
    // 分配内存
    pRollingBuffer = (PRollingBuffer) MEMALLOC(SIZEOF(RollingBuffer) + SIZEOF(UINT64) * capacity);
    CHK(pRollingBuffer != NULL, STATUS_NOT_ENOUGH_MEMORY);
    // 设置容量
    pRollingBuffer->capacity = capacity;
    // 设置头节点
    pRollingBuffer->headIndex = 0;
    // 设置尾节点
    pRollingBuffer->tailIndex = 0;
    pRollingBuffer->freeDataFn = freeDataFunc;
    // 创建锁
    pRollingBuffer->lock = MUTEX_CREATE(FALSE);
    // 设置dataBuffer地址
    pRollingBuffer->dataBuffer = (PUINT64) (pRollingBuffer + 1);
    // 置0
    MEMSET(pRollingBuffer->dataBuffer, 0, SIZEOF(UINT64) * pRollingBuffer->capacity);

CleanUp:
    if (STATUS_FAILED(retStatus) && pRollingBuffer != NULL) {
        freeRollingBuffer(&pRollingBuffer);
        pRollingBuffer = NULL;
    }

    if (ppRollingBuffer != NULL) {
        *ppRollingBuffer = pRollingBuffer;
    }
    LEAVES();
    return retStatus;
}

// 回收RollingBuffer内存
STATUS freeRollingBuffer(PRollingBuffer* ppRollingBuffer)
{
    ENTERS();
    PRollingBuffer pRollingBuffer = NULL;
    PUINT64 pCurData;

    STATUS retStatus = STATUS_SUCCESS;

    CHK(ppRollingBuffer != NULL, STATUS_NULL_ARG);

    pRollingBuffer = *ppRollingBuffer;
    // freeRollingBuffer is idempotent
    CHK(pRollingBuffer != NULL, retStatus);

    // 加锁
    MUTEX_LOCK(pRollingBuffer->lock);
    // 释放节点资源
    while (pRollingBuffer->tailIndex < pRollingBuffer->headIndex) {
        pCurData = pRollingBuffer->dataBuffer + ROLLING_BUFFER_MAP_INDEX(pRollingBuffer, pRollingBuffer->tailIndex);
        if (pRollingBuffer->freeDataFn != NULL) {
            pRollingBuffer->freeDataFn(pCurData);
            *pCurData = (UINT64) NULL;
        }
        pRollingBuffer->tailIndex++;
    }
    // 解锁
    MUTEX_UNLOCK(pRollingBuffer->lock);
    // 回收锁资源
    MUTEX_FREE(pRollingBuffer->lock);
    // 回收RollingBuffer资源
    SAFE_MEMFREE(*ppRollingBuffer);
CleanUp:
    CHK_LOG_ERR(retStatus);

    LEAVES();
    return retStatus;
}

// RollingBuffer 追加数据
STATUS rollingBufferAppendData(PRollingBuffer pRollingBuffer, UINT64 data, PUINT64 pIndex)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL isLocked = FALSE;

    CHK(pRollingBuffer != NULL, STATUS_NULL_ARG);

    // 加锁
    MUTEX_LOCK(pRollingBuffer->lock);
    isLocked = TRUE;

    // 空
    if (pRollingBuffer->headIndex == pRollingBuffer->tailIndex) {
        // Empty buffer
        pRollingBuffer->dataBuffer[ROLLING_BUFFER_MAP_INDEX(pRollingBuffer, pRollingBuffer->tailIndex)] = data;
        pRollingBuffer->headIndex = pRollingBuffer->tailIndex + 1;
    }
    else {
        // buffer 已满，
        if (pRollingBuffer->headIndex == pRollingBuffer->tailIndex + pRollingBuffer->capacity) {
            if (pRollingBuffer->freeDataFn != NULL) {
                CHK_STATUS(
                    pRollingBuffer->freeDataFn(pRollingBuffer->dataBuffer + ROLLING_BUFFER_MAP_INDEX(pRollingBuffer, pRollingBuffer->tailIndex)));
            }
            pRollingBuffer->tailIndex++;
        }
        pRollingBuffer->dataBuffer[ROLLING_BUFFER_MAP_INDEX(pRollingBuffer, pRollingBuffer->headIndex)] = data;
        pRollingBuffer->headIndex++;
    }
    if (pIndex != NULL) {
        *pIndex = pRollingBuffer->headIndex - 1;
    }
CleanUp:
    // 解锁
    if (isLocked) {
        MUTEX_UNLOCK(pRollingBuffer->lock);
    }

    CHK_LOG_ERR(retStatus);

    LEAVES();
    return retStatus;
}

// RollingBuffer 插入数据(覆盖指定索引处的数据)
STATUS rollingBufferInsertData(PRollingBuffer pRollingBuffer, UINT64 index, UINT64 data)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL isLocked = FALSE;
    PUINT64 pData;
    CHK(pRollingBuffer != NULL, STATUS_NULL_ARG);

    // 加锁
    MUTEX_LOCK(pRollingBuffer->lock);
    isLocked = TRUE;

    CHK(pRollingBuffer->headIndex > index && pRollingBuffer->tailIndex <= index, STATUS_ROLLING_BUFFER_NOT_IN_RANGE);

    pData = pRollingBuffer->dataBuffer + ROLLING_BUFFER_MAP_INDEX(pRollingBuffer, index);
    // 覆盖指定索引的数据
    if (*pData != (UINT64) NULL && pRollingBuffer->freeDataFn != NULL) {
        pRollingBuffer->freeDataFn(pData);
    }
    *pData = data;

CleanUp:
    // 解锁
    if (isLocked) {
        MUTEX_UNLOCK(pRollingBuffer->lock);
    }

    LEAVES();
    return retStatus;
}

// 提取指定索引的数据(提取后将index位置设置为NULL)
STATUS rollingBufferExtractData(PRollingBuffer pRollingBuffer, UINT64 index, PUINT64 pData)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL isLocked = FALSE;
    CHK(pRollingBuffer != NULL && pData != NULL, STATUS_NULL_ARG);

    // 加锁
    MUTEX_LOCK(pRollingBuffer->lock);
    isLocked = TRUE;
    // 检测index在有效范围
    if (pRollingBuffer->headIndex > index && pRollingBuffer->tailIndex <= index) {
        *pData = pRollingBuffer->dataBuffer[ROLLING_BUFFER_MAP_INDEX(pRollingBuffer, index)];
        // 将index位置的数据置为NULL
        if (*pData != (UINT64) NULL) {
            pRollingBuffer->dataBuffer[ROLLING_BUFFER_MAP_INDEX(pRollingBuffer, index)] = (UINT64) NULL;
        }
    } else {
        *pData = (UINT64) NULL;
    }
CleanUp:
    // 解锁
    if (isLocked) {
        MUTEX_UNLOCK(pRollingBuffer->lock);
    }
    CHK_LOG_ERR(retStatus);

    LEAVES();
    return retStatus;
}

// 获取RollingVBuffer大小
STATUS rollingBufferGetSize(PRollingBuffer pRollingBuffer, PUINT32 pSize)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pRollingBuffer != NULL && pSize != NULL, STATUS_NULL_ARG);
    *pSize = pRollingBuffer->headIndex - pRollingBuffer->tailIndex;
CleanUp:
    CHK_LOG_ERR(retStatus);

    LEAVES();
    return retStatus;
}

// 检测RollingBuffer是否为空
// headIndex == tailIndex
STATUS rollingBufferIsEmpty(PRollingBuffer pRollingBuffer, PBOOL pIsEmpty)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    CHK(pRollingBuffer != NULL && pIsEmpty != NULL, STATUS_NULL_ARG);
    *pIsEmpty = (pRollingBuffer->headIndex == pRollingBuffer->tailIndex);

CleanUp:
    CHK_LOG_ERR(retStatus);

    LEAVES();
    return retStatus;
}
