/**
 * Kinesis Video Producer ConnectionListener
 */
#define LOG_CLASS "ConnectionListener"
#include "../Include_i.h"

// 创建connectionListener
STATUS createConnectionListener(PConnectionListener* ppConnectionListener)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 allocationSize = SIZEOF(ConnectionListener) + MAX_UDP_PACKET_SIZE;
    PConnectionListener pConnectionListener = NULL;

    CHK(ppConnectionListener != NULL, STATUS_NULL_ARG);

    // 分配内存
    pConnectionListener = (PConnectionListener) MEMCALLOC(1, allocationSize);
    CHK(pConnectionListener != NULL, STATUS_NOT_ENOUGH_MEMORY);

    // 设置终止标志
    ATOMIC_STORE_BOOL(&pConnectionListener->terminate, FALSE);
    // 初始化接受数据线程tid
    pConnectionListener->receiveDataRoutine = INVALID_TID_VALUE;

    // 创建锁
    pConnectionListener->lock = MUTEX_CREATE(FALSE);

    // No sockets are present
    pConnectionListener->socketCount = 0;

    // pConnectionListener->pBuffer starts at the end of ConnectionListener struct
    pConnectionListener->pBuffer = (PBYTE) (pConnectionListener + 1);
    pConnectionListener->bufferLen = MAX_UDP_PACKET_SIZE;

CleanUp:

    if (STATUS_FAILED(retStatus) && pConnectionListener != NULL) {
        freeConnectionListener(&pConnectionListener);
        pConnectionListener = NULL;
    }

    if (ppConnectionListener != NULL) {
        *ppConnectionListener = pConnectionListener;
    }

    return retStatus;
}

// 回收ConnectionListener资源
STATUS freeConnectionListener(PConnectionListener* ppConnectionListener)
{
    STATUS retStatus = STATUS_SUCCESS;
    PConnectionListener pConnectionListener = NULL;
    UINT64 timeToWait;
    TID threadId;
    BOOL threadTerminated = FALSE;

    CHK(ppConnectionListener != NULL, STATUS_NULL_ARG);
    CHK(*ppConnectionListener != NULL, retStatus);

    pConnectionListener = *ppConnectionListener;

    // 设置终止标志
    ATOMIC_STORE_BOOL(&pConnectionListener->terminate, TRUE);

    if (IS_VALID_MUTEX_VALUE(pConnectionListener->lock)) {
        // Try to await for the thread to finish up
        // NOTE: As TID is not atomic we need to wrap the read in locks
        timeToWait = GETTIME() + CONNECTION_LISTENER_SHUTDOWN_TIMEOUT;

        do {
            // 加锁
            MUTEX_LOCK(pConnectionListener->lock);
            threadId = pConnectionListener->receiveDataRoutine;
            // 解锁
            MUTEX_UNLOCK(pConnectionListener->lock);
            if (!IS_VALID_TID_VALUE(threadId)) {
                threadTerminated = TRUE;
            }

            // Allow the thread to finish and exit
            if (!threadTerminated) {
                THREAD_SLEEP(KVS_ICE_SHORT_CHECK_DELAY);
            }
        } while (!threadTerminated && GETTIME() < timeToWait);

        if (!threadTerminated) {
            DLOGW("Connection listener handler thread shutdown timed out");
        }

        // 回收锁资源
        MUTEX_FREE(pConnectionListener->lock);
    }

    // 回收connectionListener资源
    MEMFREE(pConnectionListener);

    *ppConnectionListener = NULL;

CleanUp:

    CHK_LOG_ERR(retStatus);

    return retStatus;
}

// connectionListener 增加socketConnection
STATUS connectionListenerAddConnection(PConnectionListener pConnectionListener, PSocketConnection pSocketConnection)
{
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE, iterate = TRUE;
    UINT32 i;

    CHK(pConnectionListener != NULL && pSocketConnection != NULL, STATUS_NULL_ARG);
    CHK(!ATOMIC_LOAD_BOOL(&pConnectionListener->terminate), retStatus);

    // 加锁
    MUTEX_LOCK(pConnectionListener->lock);
    locked = TRUE;

    // Check for space
    CHK(pConnectionListener->socketCount < CONNECTION_LISTENER_DEFAULT_MAX_LISTENING_CONNECTION, STATUS_NOT_ENOUGH_MEMORY);

    // Find an empty slot by checking whether connected
    // 找到第一个空位置，插入
    for (i = 0; iterate && i < CONNECTION_LISTENER_DEFAULT_MAX_LISTENING_CONNECTION; i++) {
        if (pConnectionListener->sockets[i] == NULL) {
            pConnectionListener->sockets[i] = pSocketConnection;
            pConnectionListener->socketCount++;
            iterate = FALSE;
        }
    }

    // 解锁
    MUTEX_UNLOCK(pConnectionListener->lock);
    locked = FALSE;

CleanUp:

    // 解锁
    if (locked) {
        MUTEX_UNLOCK(pConnectionListener->lock);
    }

    return retStatus;
}


// 删除socketConnection
STATUS connectionListenerRemoveConnection(PConnectionListener pConnectionListener, PSocketConnection pSocketConnection)
{
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE, iterate = TRUE;
    UINT32 i;

    CHK(pConnectionListener != NULL && pSocketConnection != NULL, STATUS_NULL_ARG);
    CHK(!ATOMIC_LOAD_BOOL(&pConnectionListener->terminate), retStatus);

    // 加锁
    MUTEX_LOCK(pConnectionListener->lock);
    locked = TRUE;

    // Mark socket as closed
    // 关闭socketConnection
    CHK_STATUS(socketConnectionClosed(pSocketConnection));

    // Remove from the list of sockets
    // 删除socketConnection
    for (i = 0; iterate && i < CONNECTION_LISTENER_DEFAULT_MAX_LISTENING_CONNECTION; i++) {
        if (pConnectionListener->sockets[i] == pSocketConnection) {
            iterate = FALSE;

            // Mark the slot as empty and decrement the count
            pConnectionListener->sockets[i] = NULL;
            pConnectionListener->socketCount--;
        }
    }

CleanUp:

    // 解锁
    if (locked) {
        MUTEX_UNLOCK(pConnectionListener->lock);
    }

    return retStatus;
}

// 删除connectionListener所有socketConnection
STATUS connectionListenerRemoveAllConnection(PConnectionListener pConnectionListener)
{
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;
    UINT32 i;

    CHK(pConnectionListener != NULL, STATUS_NULL_ARG);
    CHK(!ATOMIC_LOAD_BOOL(&pConnectionListener->terminate), retStatus);

    // 加锁
    MUTEX_LOCK(pConnectionListener->lock);
    locked = TRUE;

    // 删除所有socketConnection
    for (i = 0; i < CONNECTION_LISTENER_DEFAULT_MAX_LISTENING_CONNECTION; i++) {
        if (pConnectionListener->sockets[i] != NULL) {
            // 关闭 socketConnection
            CHK_STATUS(socketConnectionClosed(pConnectionListener->sockets[i]));
            pConnectionListener->sockets[i] = NULL;
            pConnectionListener->socketCount--;
        }
    }

CleanUp:

    // 解锁
    if (locked) {
        MUTEX_UNLOCK(pConnectionListener->lock);
    }

    return retStatus;
}

// 启动connectionListener
STATUS connectionListenerStart(PConnectionListener pConnectionListener)
{
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;

    CHK(pConnectionListener != NULL, STATUS_NULL_ARG);
    CHK(!ATOMIC_LOAD_BOOL(&pConnectionListener->terminate), retStatus);

    // 加锁
    MUTEX_LOCK(pConnectionListener->lock);
    locked = TRUE;

    CHK(!IS_VALID_TID_VALUE(pConnectionListener->receiveDataRoutine), retStatus);
    // 启动接受数据线程
    CHK_STATUS(THREAD_CREATE(&pConnectionListener->receiveDataRoutine, connectionListenerReceiveDataRoutine, (PVOID) pConnectionListener));
    // 线程结束，自动回收资源
    CHK_STATUS(THREAD_DETACH(pConnectionListener->receiveDataRoutine));

CleanUp:

    // 解锁
    if (locked) {
        MUTEX_UNLOCK(pConnectionListener->lock);
    }

    return retStatus;
}

// 可以读到fd
BOOL canReadFd(INT32 fd, struct pollfd* fds, INT32 nfds)
{
    INT32 i;
    for (i = 0; i < nfds; i++) {
        // POLLIN 有数据要读
        if (fds[i].fd == fd && (fds[i].revents & POLLIN) != 0) {
            return TRUE;
        }
    }
    return FALSE;
}

// connectionListener 接收数据函数
PVOID connectionListenerReceiveDataRoutine(PVOID arg)
{
    STATUS retStatus = STATUS_SUCCESS;
    PConnectionListener pConnectionListener = (PConnectionListener) arg;
    PSocketConnection pSocketConnection;
    BOOL iterate = TRUE;
    PSocketConnection sockets[CONNECTION_LISTENER_DEFAULT_MAX_LISTENING_CONNECTION];
    UINT32 i, socketCount;

    INT32 nfds = 0;
    struct pollfd rfds[CONNECTION_LISTENER_DEFAULT_MAX_LISTENING_CONNECTION];
    INT32 retval, localSocket;
    INT64 readLen;
    // the source address is put here. sockaddr_storage can hold either sockaddr_in or sockaddr_in6
    struct sockaddr_storage srcAddrBuff;
    socklen_t srcAddrBuffLen = SIZEOF(srcAddrBuff);
    struct sockaddr_in* pIpv4Addr;
    struct sockaddr_in6* pIpv6Addr;
    KvsIpAddress srcAddr;
    PKvsIpAddress pSrcAddr = NULL;

    CHK(pConnectionListener != NULL, STATUS_NULL_ARG);

    /* Ensure that memory sanitizers consider
     * rfds initialized even if FD_ZERO is
     * implemented in assembly. */
    MEMSET(&rfds, 0x00, SIZEOF(rfds));

    srcAddr.isPointToPoint = FALSE;

    // 终止标志为FALSE
    while (!ATOMIC_LOAD_BOOL(&pConnectionListener->terminate)) {
        nfds = 0;

        // Perform the socket connection gathering under the lock
        // NOTE: There is no cleanup jump from the lock/unlock block
        // so we don't need to use a boolean indicator whether locked
        // 加锁
        MUTEX_LOCK(pConnectionListener->lock);
        for (i = 0, socketCount = 0; i < CONNECTION_LISTENER_DEFAULT_MAX_LISTENING_CONNECTION; i++) {
            pSocketConnection = pConnectionListener->sockets[i];
            // pSocketConnection存在
            if (pSocketConnection != NULL) {
                // 当socketConnection不为Closed
                if (!socketConnectionIsClosed(pSocketConnection)) {
                    // 加锁
                    MUTEX_LOCK(pSocketConnection->lock);
                    localSocket = pSocketConnection->localSocket;
                    // 解锁
                    MUTEX_UNLOCK(pSocketConnection->lock);
                    rfds[nfds].fd = localSocket;
                    // POLLIN 有数据要读
                    // POLLPRI 有紧急数据要读
                    // POLLOUT 现在写入不会阻塞
                    rfds[nfds].events = POLLIN | POLLPRI;
                    rfds[nfds].revents = 0;
                    nfds++;

                    // Store the sockets locally while in use and mark it as in use
                    sockets[socketCount++] = pSocketConnection;
                    // 设置socketConnection 使用状态为TRUE
                    ATOMIC_STORE_BOOL(&pSocketConnection->inUse, TRUE);
                }
                // 当socketConnection 状态为closed
                else {
                    // Remove the connection
                    pConnectionListener->sockets[i] = NULL;
                    pConnectionListener->socketCount--;
                }
            }
        }

        // Need to unlock the mutex to ensure other racing threads unblock
        // 解锁
        MUTEX_UNLOCK(pConnectionListener->lock);

        // blocking call until resolves as a timeout, an error, a signal or data received
        retval = POLL(rfds, nfds, CONNECTION_LISTENER_SOCKET_WAIT_FOR_DATA_TIMEOUT / HUNDREDS_OF_NANOS_IN_A_MILLISECOND);

        // In case of 0 we have a timeout and should re-lock to allow for other
        // interlocking operations to proceed. A positive return means we received data
        if (retval == -1) {
            DLOGW("poll() failed with errno %s", getErrorString(getErrorCode()));
        } else if (retval > 0) {
            for (i = 0; i < socketCount; i++) {
                pSocketConnection = sockets[i];
                //socketConnection 状态不为Closed
                if (!socketConnectionIsClosed(pSocketConnection)) {
                    // 加锁
                    MUTEX_LOCK(pSocketConnection->lock);
                    localSocket = pSocketConnection->localSocket;
                    // 解锁
                    MUTEX_UNLOCK(pSocketConnection->lock);

                    // localSocket存在， 并且有数据要读
                    if (canReadFd(localSocket, rfds, nfds)) {
                        iterate = TRUE;
                        while (iterate) {
                            // 接收一个数据报并保存源地址
                            readLen = recvfrom(localSocket, pConnectionListener->pBuffer, pConnectionListener->bufferLen, 0,
                                               (struct sockaddr*) &srcAddrBuff, &srcAddrBuffLen);
                            // 接受数据出错
                            if (readLen < 0) {
                                switch (getErrorCode()) {
                                    case EWOULDBLOCK:
                                        break;
                                    default:
                                        /* on any other error, close connection */
                                        CHK_STATUS(socketConnectionClosed(pSocketConnection));
                                        DLOGD("recvfrom() failed with errno %s for socket %d", getErrorString(getErrorCode()), localSocket);
                                        break;
                                }

                                iterate = FALSE;
                            }
                            // 连接终止
                            else if (readLen == 0) {
                                // 关闭socketConnection
                                CHK_STATUS(socketConnectionClosed(pSocketConnection));
                                iterate = FALSE;
                            }
                            // 
                            else if (/* readLen > 0 */
                                       ATOMIC_LOAD_BOOL(&pSocketConnection->receiveData) && pSocketConnection->dataAvailableCallbackFn != NULL &&
                                       /* data could be encrypted so they need to be decrypted through socketConnectionReadData
                                        * and get the decrypted data length. */
                                       // 从socketConnection读取数据
                                       STATUS_SUCCEEDED(socketConnectionReadData(pSocketConnection, pConnectionListener->pBuffer,
                                                                                 pConnectionListener->bufferLen, (PUINT32) &readLen))) {
                                // udp
                                if (pSocketConnection->protocol == KVS_SOCKET_PROTOCOL_UDP) {
                                    // ipv4
                                    if (srcAddrBuff.ss_family == AF_INET) {
                                        srcAddr.family = KVS_IP_FAMILY_TYPE_IPV4;
                                        pIpv4Addr = (struct sockaddr_in*) &srcAddrBuff;
                                        MEMCPY(srcAddr.address, (PBYTE) &pIpv4Addr->sin_addr, IPV4_ADDRESS_LENGTH);
                                        srcAddr.port = pIpv4Addr->sin_port;
                                    }
                                    // ipv6
                                    else if (srcAddrBuff.ss_family == AF_INET6) {
                                        srcAddr.family = KVS_IP_FAMILY_TYPE_IPV6;
                                        pIpv6Addr = (struct sockaddr_in6*) &srcAddrBuff;
                                        MEMCPY(srcAddr.address, (PBYTE) &pIpv6Addr->sin6_addr, IPV6_ADDRESS_LENGTH);
                                        srcAddr.port = pIpv6Addr->sin6_port;
                                    }
                                    pSrcAddr = &srcAddr;
                                }
                                // tcp
                                else {
                                    // srcAddr is ignored in TCP callback handlers
                                    pSrcAddr = NULL;
                                }

                                // readLen may be 0 if SSL does not emit any application data.
                                // in that case, no need to call dataAvailable callback
                                if (readLen > 0) {
                                    pSocketConnection->dataAvailableCallbackFn(pSocketConnection->dataAvailableCallbackCustomData, pSocketConnection,
                                                                               pConnectionListener->pBuffer, (UINT32) readLen, pSrcAddr,
                                                                               NULL); // no dest information available right now.
                                }
                            }

                            // reset srcAddrBuffLen to actual size
                            srcAddrBuffLen = SIZEOF(srcAddrBuff);
                        }
                    }
                }
            }
        }

        // Mark as unused
        // 设置socketConnection 使用状态为FALSE
        for (i = 0; i < socketCount; i++) {
            ATOMIC_STORE_BOOL(&sockets[i]->inUse, FALSE);
        }
    }

CleanUp:

    // The check for valid mutex is necessary because when we're in freeConnectionListener
    // we may free the mutex in another thread so by the time we get here accessing the lock
    // will result in accessing a resource after it has been freed
    if (pConnectionListener != NULL && IS_VALID_MUTEX_VALUE(pConnectionListener->lock)) {
        // As TID is 64 bit we can't atomically update it and need to do it under the lock
        MUTEX_LOCK(pConnectionListener->lock);
        pConnectionListener->receiveDataRoutine = INVALID_TID_VALUE;
        MUTEX_UNLOCK(pConnectionListener->lock);
    }

    CHK_LOG_ERR(retStatus);

    return (PVOID) (ULONG_PTR) retStatus;
}
