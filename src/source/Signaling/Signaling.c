#define LOG_CLASS "Signaling"
#include "../Include_i.h"

extern StateMachineState SIGNALING_STATE_MACHINE_STATES[];
extern UINT32 SIGNALING_STATE_MACHINE_STATE_COUNT;

// 创建信令(同步)
STATUS createSignalingSync(PSignalingClientInfoInternal pClientInfo, PChannelInfo pChannelInfo, PSignalingClientCallbacks pCallbacks,
                           PAwsCredentialProvider pCredentialProvider, PSignalingClient* ppSignalingClient)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = NULL;
    PCHAR userLogLevelStr = NULL;
    UINT32 userLogLevel;
    struct lws_context_creation_info creationInfo;
    const lws_retry_bo_t retryPolicy = {
        .secs_since_valid_ping = SIGNALING_SERVICE_WSS_PING_PONG_INTERVAL_IN_SECONDS,
        .secs_since_valid_hangup = SIGNALING_SERVICE_WSS_HANGUP_IN_SECONDS,
    };
    PStateMachineState pStateMachineState;
    BOOL cacheFound = FALSE;
    PSignalingFileCacheEntry pFileCacheEntry = NULL;

    CHK(pClientInfo != NULL && pChannelInfo != NULL && pCallbacks != NULL && pCredentialProvider != NULL && ppSignalingClient != NULL,
        STATUS_NULL_ARG);
    // 检查版本
    CHK(pChannelInfo->version <= CHANNEL_INFO_CURRENT_VERSION, STATUS_SIGNALING_INVALID_CHANNEL_INFO_VERSION);
    // 信令条目文件缓存，分配内存
    CHK(NULL != (pFileCacheEntry = (PSignalingFileCacheEntry) MEMALLOC(SIZEOF(SignalingFileCacheEntry))), STATUS_NOT_ENOUGH_MEMORY);

    // Allocate enough storage
    // signalingClient 分配内存
    CHK(NULL != (pSignalingClient = (PSignalingClient) MEMCALLOC(1, SIZEOF(SignalingClient))), STATUS_NOT_ENOUGH_MEMORY);

    // Initialize the listener and restart thread trackers
    // 初始化线程跟踪器
    CHK_STATUS(initializeThreadTracker(&pSignalingClient->listenerTracker));
    CHK_STATUS(initializeThreadTracker(&pSignalingClient->reconnecterTracker));

    // Validate and store the input
    // 创建ChannelInfo
    CHK_STATUS(createValidateChannelInfo(pChannelInfo, &pSignalingClient->pChannelInfo));
    // 设置callbacks
    CHK_STATUS(validateSignalingCallbacks(pSignalingClient, pCallbacks));
    // 设置ClientInfo
    CHK_STATUS(validateSignalingClientInfo(pSignalingClient, pClientInfo));

    // 设置版本
    pSignalingClient->version = SIGNALING_CLIENT_CURRENT_VERSION;

    // Set invalid call times
    // 设置无效的调用时间
    pSignalingClient->describeTime = INVALID_TIMESTAMP_VALUE;
    pSignalingClient->createTime = INVALID_TIMESTAMP_VALUE;
    pSignalingClient->getEndpointTime = INVALID_TIMESTAMP_VALUE;
    pSignalingClient->getIceConfigTime = INVALID_TIMESTAMP_VALUE;
    pSignalingClient->deleteTime = INVALID_TIMESTAMP_VALUE;
    pSignalingClient->connectTime = INVALID_TIMESTAMP_VALUE;

    if (pSignalingClient->pChannelInfo->cachingPolicy == SIGNALING_API_CALL_CACHE_TYPE_FILE) {
        // Signaling channel name can be NULL in case of pre-created channels in which case we use ARN as the name
        if (STATUS_FAILED(signalingCacheLoadFromFile(pChannelInfo->pChannelName != NULL ? pChannelInfo->pChannelName : pChannelInfo->pChannelArn,
                                                     pChannelInfo->pRegion, pChannelInfo->channelRoleType, pFileCacheEntry, &cacheFound,
                                                     pSignalingClient->clientInfo.cacheFilePath))) {
            DLOGW("Failed to load signaling cache from file");
        }
        // cache命中
        else if (cacheFound) {
            STRCPY(pSignalingClient->channelDescription.channelArn, pFileCacheEntry->channelArn);
            STRCPY(pSignalingClient->channelEndpointHttps, pFileCacheEntry->httpsEndpoint);
            STRCPY(pSignalingClient->channelEndpointWss, pFileCacheEntry->wssEndpoint);
            pSignalingClient->describeTime = pFileCacheEntry->creationTsEpochSeconds * HUNDREDS_OF_NANOS_IN_A_SECOND;
            pSignalingClient->getEndpointTime = pFileCacheEntry->creationTsEpochSeconds * HUNDREDS_OF_NANOS_IN_A_SECOND;
        }
    }

    // Attempting to get the logging level from the env var and if it fails then set it from the client info
    // 设置日志级别
    if ((userLogLevelStr = GETENV(DEBUG_LOG_LEVEL_ENV_VAR)) != NULL && STATUS_SUCCEEDED(STRTOUI32(userLogLevelStr, NULL, 10, &userLogLevel))) {
        userLogLevel = userLogLevel > LOG_LEVEL_SILENT ? LOG_LEVEL_SILENT : userLogLevel < LOG_LEVEL_VERBOSE ? LOG_LEVEL_VERBOSE : userLogLevel;
    } else {
        userLogLevel = pClientInfo->signalingClientInfo.loggingLevel;
    }

    SET_LOGGER_LOG_LEVEL(userLogLevel);

    // Store the credential provider
    // 设置凭证提供者
    pSignalingClient->pCredentialProvider = pCredentialProvider;

    // 配置信令状态机重试策略
    CHK_STATUS(configureRetryStrategyForSignalingStateMachine(pSignalingClient));

    // Create the state machine
    // 创建状态机
    CHK_STATUS(createStateMachine(SIGNALING_STATE_MACHINE_STATES, SIGNALING_STATE_MACHINE_STATE_COUNT,
                                  CUSTOM_DATA_FROM_SIGNALING_CLIENT(pSignalingClient), signalingGetCurrentTime,
                                  CUSTOM_DATA_FROM_SIGNALING_CLIENT(pSignalingClient), &pSignalingClient->pStateMachine));

    // Prepare the signaling channel protocols array
    // 设置协议、回调函数
    pSignalingClient->signalingProtocols[PROTOCOL_INDEX_HTTPS].name = HTTPS_SCHEME_NAME;
    pSignalingClient->signalingProtocols[PROTOCOL_INDEX_HTTPS].callback = lwsHttpCallbackRoutine;
    pSignalingClient->signalingProtocols[PROTOCOL_INDEX_WSS].name = WSS_SCHEME_NAME;
    pSignalingClient->signalingProtocols[PROTOCOL_INDEX_WSS].callback = lwsWssCallbackRoutine;

    pSignalingClient->currentWsi[PROTOCOL_INDEX_HTTPS] = NULL;
    pSignalingClient->currentWsi[PROTOCOL_INDEX_WSS] = NULL;

    // 设置creationInfo
    MEMSET(&creationInfo, 0x00, SIZEOF(struct lws_context_creation_info));
    creationInfo.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    creationInfo.port = CONTEXT_PORT_NO_LISTEN;
    creationInfo.protocols = pSignalingClient->signalingProtocols;
    creationInfo.timeout_secs = SIGNALING_SERVICE_API_CALL_TIMEOUT_IN_SECONDS;
    creationInfo.gid = -1;
    creationInfo.uid = -1;
    creationInfo.client_ssl_ca_filepath = pChannelInfo->pCertPath;
    creationInfo.client_ssl_cipher_list = "HIGH:!PSK:!RSP:!eNULL:!aNULL:!RC4:!MD5:!DES:!3DES:!aDH:!kDH:!DSS";
    creationInfo.ka_time = SIGNALING_SERVICE_TCP_KEEPALIVE_IN_SECONDS;
    creationInfo.ka_probes = SIGNALING_SERVICE_TCP_KEEPALIVE_PROBE_COUNT;
    creationInfo.ka_interval = SIGNALING_SERVICE_TCP_KEEPALIVE_PROBE_INTERVAL_IN_SECONDS;
    creationInfo.retry_and_idle_policy = &retryPolicy;

    // 初始化标志
    ATOMIC_STORE_BOOL(&pSignalingClient->clientReady, FALSE);
    ATOMIC_STORE_BOOL(&pSignalingClient->shutdown, FALSE);
    ATOMIC_STORE_BOOL(&pSignalingClient->connected, FALSE);
    ATOMIC_STORE_BOOL(&pSignalingClient->deleting, FALSE);
    ATOMIC_STORE_BOOL(&pSignalingClient->deleted, FALSE);
    ATOMIC_STORE_BOOL(&pSignalingClient->serviceLockContention, FALSE);

    // Add to the signal handler
    // signal(SIGINT, lwsSignalHandler);

    // Create the sync primitives
    // 创建锁、条件变量
    pSignalingClient->connectedCvar = CVAR_CREATE();
    CHK(IS_VALID_CVAR_VALUE(pSignalingClient->connectedCvar), STATUS_INVALID_OPERATION);
    pSignalingClient->connectedLock = MUTEX_CREATE(FALSE);
    CHK(IS_VALID_MUTEX_VALUE(pSignalingClient->connectedLock), STATUS_INVALID_OPERATION);
    pSignalingClient->sendCvar = CVAR_CREATE();
    CHK(IS_VALID_CVAR_VALUE(pSignalingClient->sendCvar), STATUS_INVALID_OPERATION);
    pSignalingClient->sendLock = MUTEX_CREATE(FALSE);
    CHK(IS_VALID_MUTEX_VALUE(pSignalingClient->sendLock), STATUS_INVALID_OPERATION);
    pSignalingClient->receiveCvar = CVAR_CREATE();
    CHK(IS_VALID_CVAR_VALUE(pSignalingClient->receiveCvar), STATUS_INVALID_OPERATION);
    pSignalingClient->receiveLock = MUTEX_CREATE(FALSE);
    CHK(IS_VALID_MUTEX_VALUE(pSignalingClient->receiveLock), STATUS_INVALID_OPERATION);

    pSignalingClient->stateLock = MUTEX_CREATE(TRUE);
    CHK(IS_VALID_MUTEX_VALUE(pSignalingClient->stateLock), STATUS_INVALID_OPERATION);

    pSignalingClient->messageQueueLock = MUTEX_CREATE(TRUE);
    CHK(IS_VALID_MUTEX_VALUE(pSignalingClient->messageQueueLock), STATUS_INVALID_OPERATION);

    pSignalingClient->lwsServiceLock = MUTEX_CREATE(TRUE);
    CHK(IS_VALID_MUTEX_VALUE(pSignalingClient->lwsServiceLock), STATUS_INVALID_OPERATION);

    pSignalingClient->lwsSerializerLock = MUTEX_CREATE(TRUE);
    CHK(IS_VALID_MUTEX_VALUE(pSignalingClient->lwsSerializerLock), STATUS_INVALID_OPERATION);

    pSignalingClient->diagnosticsLock = MUTEX_CREATE(TRUE);
    CHK(IS_VALID_MUTEX_VALUE(pSignalingClient->diagnosticsLock), STATUS_INVALID_OPERATION);

    // Create the ongoing message list
    // 创建消息队列
    CHK_STATUS(stackQueueCreate(&pSignalingClient->pMessageQueue));

    // 创建websocket 上下文
    pSignalingClient->pLwsContext = lws_create_context(&creationInfo);
    CHK(pSignalingClient->pLwsContext != NULL, STATUS_SIGNALING_LWS_CREATE_CONTEXT_FAILED);

    // Initializing the diagnostics mostly is taken care of by zero-mem in MEMCALLOC
    // 设置diagnostics 创建时间
    pSignalingClient->diagnostics.createTime = SIGNALING_GET_CURRENT_TIME(pSignalingClient);
    CHK_STATUS(hashTableCreateWithParams(SIGNALING_CLOCKSKEW_HASH_TABLE_BUCKET_COUNT, SIGNALING_CLOCKSKEW_HASH_TABLE_BUCKET_LENGTH,
                                         &pSignalingClient->diagnostics.pEndpointToClockSkewHashMap));

    // At this point we have constructed the main object and we can assign to the returned pointer
    *ppSignalingClient = pSignalingClient;

    // Notify of the state change initially as the state machinery is already in the NEW state
    if (pSignalingClient->signalingClientCallbacks.stateChangeFn != NULL) {
        // 获取状态机当前状态
        CHK_STATUS(getStateMachineCurrentState(pSignalingClient->pStateMachine, &pStateMachineState));
        CHK_STATUS(pSignalingClient->signalingClientCallbacks.stateChangeFn(pSignalingClient->signalingClientCallbacks.customData,
                                                                            getSignalingStateFromStateMachineState(pStateMachineState->state)));
    }

    // Do not force ice config state
    ATOMIC_STORE_BOOL(&pSignalingClient->refreshIceConfig, FALSE);

    // We do not cache token in file system, so we will always have to retrieve one after creating the client.
    // 信令状态迭代
    CHK_STATUS(signalingStateMachineIterator(pSignalingClient, pSignalingClient->diagnostics.createTime + SIGNALING_CONNECT_STATE_TIMEOUT,
                                             SIGNALING_STATE_GET_TOKEN));

CleanUp:
    if (pClientInfo != NULL && pSignalingClient != NULL) {
        pClientInfo->signalingClientInfo.stateMachineRetryCountReadOnly = pSignalingClient->diagnostics.stateMachineRetryCount;
    }
    CHK_LOG_ERR(retStatus);

    // 回收信令资源
    if (STATUS_FAILED(retStatus)) {
        freeSignaling(&pSignalingClient);
    }

    if (ppSignalingClient != NULL) {
        *ppSignalingClient = pSignalingClient;
    }
    // 回收文件缓存资源
    SAFE_MEMFREE(pFileCacheEntry);
    LEAVES();
    return retStatus;
}

// 回收信令
STATUS freeSignaling(PSignalingClient* ppSignalingClient)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient;

    CHK(ppSignalingClient != NULL, STATUS_NULL_ARG);

    pSignalingClient = *ppSignalingClient;
    CHK(pSignalingClient != NULL, retStatus);

    ATOMIC_STORE_BOOL(&pSignalingClient->shutdown, TRUE);

    // 终止正在进行的操作
    terminateOngoingOperations(pSignalingClient);

    if (pSignalingClient->pLwsContext != NULL) {
        // 加锁
        MUTEX_LOCK(pSignalingClient->lwsServiceLock);
        // 销毁websocket 上下文
        lws_context_destroy(pSignalingClient->pLwsContext);
        pSignalingClient->pLwsContext = NULL;
        // 解锁
        MUTEX_UNLOCK(pSignalingClient->lwsServiceLock);
    }

    // 回收状态机资源
    freeStateMachine(pSignalingClient->pStateMachine);

    // 回收客户端重试策略资源
    freeClientRetryStrategy(pSignalingClient);

    // 回收ChannelInfo资源
    freeChannelInfo(&pSignalingClient->pChannelInfo);

    // 回收消息队列资源
    stackQueueFree(pSignalingClient->pMessageQueue);

    // 回收哈希表
    hashTableFree(pSignalingClient->diagnostics.pEndpointToClockSkewHashMap);

    // 回收锁、条件变量资源
    if (IS_VALID_MUTEX_VALUE(pSignalingClient->connectedLock)) {
        MUTEX_FREE(pSignalingClient->connectedLock);
    }

    if (IS_VALID_CVAR_VALUE(pSignalingClient->connectedCvar)) {
        CVAR_FREE(pSignalingClient->connectedCvar);
    }

    if (IS_VALID_MUTEX_VALUE(pSignalingClient->sendLock)) {
        MUTEX_FREE(pSignalingClient->sendLock);
    }

    if (IS_VALID_CVAR_VALUE(pSignalingClient->sendCvar)) {
        CVAR_FREE(pSignalingClient->sendCvar);
    }

    if (IS_VALID_MUTEX_VALUE(pSignalingClient->receiveLock)) {
        MUTEX_FREE(pSignalingClient->receiveLock);
    }

    if (IS_VALID_CVAR_VALUE(pSignalingClient->receiveCvar)) {
        CVAR_FREE(pSignalingClient->receiveCvar);
    }

    if (IS_VALID_MUTEX_VALUE(pSignalingClient->stateLock)) {
        MUTEX_FREE(pSignalingClient->stateLock);
    }

    if (IS_VALID_MUTEX_VALUE(pSignalingClient->messageQueueLock)) {
        MUTEX_FREE(pSignalingClient->messageQueueLock);
    }

    if (IS_VALID_MUTEX_VALUE(pSignalingClient->lwsServiceLock)) {
        MUTEX_FREE(pSignalingClient->lwsServiceLock);
    }

    if (IS_VALID_MUTEX_VALUE(pSignalingClient->lwsSerializerLock)) {
        MUTEX_FREE(pSignalingClient->lwsSerializerLock);
    }

    if (IS_VALID_MUTEX_VALUE(pSignalingClient->diagnosticsLock)) {
        MUTEX_FREE(pSignalingClient->diagnosticsLock);
    }

    // 回收线程跟踪者
    uninitializeThreadTracker(&pSignalingClient->reconnecterTracker);
    uninitializeThreadTracker(&pSignalingClient->listenerTracker);

    MEMFREE(pSignalingClient);

    *ppSignalingClient = NULL;

CleanUp:

    LEAVES();
    return retStatus;
}

// 为信令状态机，设置默认重试策略
STATUS setupDefaultRetryStrategyForSignalingStateMachine(PSignalingClient pSignalingClient)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PKvsRetryStrategyCallbacks pKvsRetryStrategyCallbacks = &(pSignalingClient->clientInfo.signalingStateMachineRetryStrategyCallbacks);

    // Use default as exponential backoff wait
    // 设置回调
    pKvsRetryStrategyCallbacks->createRetryStrategyFn = exponentialBackoffRetryStrategyCreate;
    pKvsRetryStrategyCallbacks->freeRetryStrategyFn = exponentialBackoffRetryStrategyFree;
    pKvsRetryStrategyCallbacks->executeRetryStrategyFn = getExponentialBackoffRetryStrategyWaitTime;
    pKvsRetryStrategyCallbacks->getCurrentRetryAttemptNumberFn = getExponentialBackoffRetryCount;

    // Use a default exponential backoff config for state machine level retries
    pSignalingClient->clientInfo.signalingStateMachineRetryStrategy.pRetryStrategyConfig =
        (PRetryStrategyConfig) &DEFAULT_SIGNALING_STATE_MACHINE_EXPONENTIAL_BACKOFF_RETRY_CONFIGURATION;

    LEAVES();
    return retStatus;
}

// 为信令状态机配置重试策略
STATUS configureRetryStrategyForSignalingStateMachine(PSignalingClient pSignalingClient)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PKvsRetryStrategyCallbacks pKvsRetryStrategyCallbacks = NULL;

    CHK(pSignalingClient != NULL, STATUS_NULL_ARG);
    pKvsRetryStrategyCallbacks = &(pSignalingClient->clientInfo.signalingStateMachineRetryStrategyCallbacks);

    // If the callbacks for retry strategy are already set, then use that otherwise
    // build the client with a default retry strategy.
    if (pKvsRetryStrategyCallbacks->createRetryStrategyFn == NULL || pKvsRetryStrategyCallbacks->freeRetryStrategyFn == NULL ||
        pKvsRetryStrategyCallbacks->executeRetryStrategyFn == NULL || pKvsRetryStrategyCallbacks->getCurrentRetryAttemptNumberFn == NULL) {
        CHK_STATUS(setupDefaultRetryStrategyForSignalingStateMachine(pSignalingClient));
    }

    CHK_STATUS(pKvsRetryStrategyCallbacks->createRetryStrategyFn(&(pSignalingClient->clientInfo.signalingStateMachineRetryStrategy)));

CleanUp:

    LEAVES();
    return retStatus;
}

// 回收信令客户端重试策略资源
STATUS freeClientRetryStrategy(PSignalingClient pSignalingClient)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PKvsRetryStrategyCallbacks pKvsRetryStrategyCallbacks = NULL;

    CHK(pSignalingClient != NULL, STATUS_NULL_ARG);

    pKvsRetryStrategyCallbacks = &(pSignalingClient->clientInfo.signalingStateMachineRetryStrategyCallbacks);
    CHK(pKvsRetryStrategyCallbacks->freeRetryStrategyFn != NULL, STATUS_SUCCESS);

    CHK_STATUS(pKvsRetryStrategyCallbacks->freeRetryStrategyFn(&(pSignalingClient->clientInfo.signalingStateMachineRetryStrategy)));

CleanUp:

    LEAVES();
    return retStatus;
}

// 终止正在进行的操作
STATUS terminateOngoingOperations(PSignalingClient pSignalingClient)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pSignalingClient != NULL, STATUS_NULL_ARG);

    // Terminate the listener thread if alive
    terminateLwsListenerLoop(pSignalingClient);

    // Await for the reconnect thread to exit
    awaitForThreadTermination(&pSignalingClient->reconnecterTracker, SIGNALING_CLIENT_SHUTDOWN_TIMEOUT);

CleanUp:

    CHK_LOG_ERR(retStatus);

    LEAVES();
    return retStatus;
}

// 发送信令消息(同步)
STATUS signalingSendMessageSync(PSignalingClient pSignalingClient, PSignalingMessage pSignalingMessage)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL removeFromList = FALSE;

    CHK(pSignalingClient != NULL && pSignalingMessage != NULL, STATUS_NULL_ARG);
    CHK(pSignalingMessage->peerClientId != NULL && pSignalingMessage->payload != NULL, STATUS_INVALID_ARG);
    CHK(pSignalingMessage->version <= SIGNALING_MESSAGE_CURRENT_VERSION, STATUS_SIGNALING_INVALID_SIGNALING_MESSAGE_VERSION);

    // Store the signaling message
    // 储存信令消息
    CHK_STATUS(signalingStoreOngoingMessage(pSignalingClient, pSignalingMessage));
    removeFromList = TRUE;

    // Perform the call
    // 发送websocket 消息
    CHK_STATUS(sendLwsMessage(pSignalingClient, pSignalingMessage->messageType, pSignalingMessage->peerClientId, pSignalingMessage->payload,
                              pSignalingMessage->payloadLen, pSignalingMessage->correlationId, 0));

    // Update the internal diagnostics only after successfully sending
    // 发生消息数加1
    ATOMIC_INCREMENT(&pSignalingClient->diagnostics.numberOfMessagesSent);

CleanUp:

    CHK_LOG_ERR(retStatus);

    // Remove from the list if previously added
    // 删除信令消息
    if (removeFromList) {
        signalingRemoveOngoingMessage(pSignalingClient, pSignalingMessage->correlationId);
    }

    LEAVES();
    return retStatus;
}

// 信令获取IceConfigInfo数量
STATUS signalingGetIceConfigInfoCount(PSignalingClient pSignalingClient, PUINT32 pIceConfigCount)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pSignalingClient != NULL && pIceConfigCount != NULL, STATUS_NULL_ARG);

    CHK_STATUS(refreshIceConfiguration(pSignalingClient));

    *pIceConfigCount = pSignalingClient->iceConfigCount;

CleanUp:

    CHK_LOG_ERR(retStatus);

    LEAVES();
    return retStatus;
}

// 信令获取IceConfigInfo(根据index)
STATUS signalingGetIceConfigInfo(PSignalingClient pSignalingClient, UINT32 index, PIceConfigInfo* ppIceConfigInfo)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pSignalingClient != NULL && ppIceConfigInfo != NULL, STATUS_NULL_ARG);

    // Refresh the ICE configuration first
    CHK_STATUS(refreshIceConfiguration(pSignalingClient));

    CHK(index < pSignalingClient->iceConfigCount, STATUS_INVALID_ARG);

    *ppIceConfigInfo = &pSignalingClient->iceConfigs[index];

CleanUp:

    CHK_LOG_ERR(retStatus);

    LEAVES();
    return retStatus;
}

// 信令Fetch(同步)
STATUS signalingFetchSync(PSignalingClient pSignalingClient)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    SIZE_T result;

    CHK(pSignalingClient != NULL, STATUS_NULL_ARG);

    // Check if we are already not connected
    if (ATOMIC_LOAD_BOOL(&pSignalingClient->connected)) {
        CHK_STATUS(terminateOngoingOperations(pSignalingClient));
    }

    // move to the fromGetToken() so we can move to the necessary step
    // We start from get token to keep the design consistent with how it was when the constructor (create)
    // would bring you to the READY state, but this is a two-way door and can be redone later.
    // 设置状态机当前状态
    setStateMachineCurrentState(pSignalingClient->pStateMachine, SIGNALING_STATE_GET_TOKEN);

    // if we're not failing from a bad token, set the result to OK to that fromGetToken will move
    // to getEndpoint, describe, or create. If it is bad, keep reiterating on token.
    result = ATOMIC_LOAD(&pSignalingClient->result);
    if (result != SERVICE_CALL_NOT_AUTHORIZED) {
        ATOMIC_STORE(&pSignalingClient->result, (SIZE_T) SERVICE_CALL_RESULT_OK);
    }
    // 信令状态机迭代
    CHK_STATUS(signalingStateMachineIterator(pSignalingClient, SIGNALING_GET_CURRENT_TIME(pSignalingClient) + SIGNALING_CONNECT_STATE_TIMEOUT,
                                             SIGNALING_STATE_READY));

CleanUp:

    // 重置状态机重试次数
    if (STATUS_FAILED(retStatus)) {
        resetStateMachineRetryCount(pSignalingClient->pStateMachine);
    }
    CHK_LOG_ERR(retStatus);
    LEAVES();
    return retStatus;
}

// 信令连接(同步)
STATUS signalingConnectSync(PSignalingClient pSignalingClient)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PStateMachineState pState = NULL;

    CHK(pSignalingClient != NULL, STATUS_NULL_ARG);

    // Validate the state
    // 设置状态机状态
    CHK_STATUS(acceptSignalingStateMachineState(
        pSignalingClient, SIGNALING_STATE_READY | SIGNALING_STATE_CONNECT | SIGNALING_STATE_DISCONNECTED | SIGNALING_STATE_CONNECTED));

    // Check if we are already connected
    CHK(!ATOMIC_LOAD_BOOL(&pSignalingClient->connected), retStatus);

    // Store the signaling state in case we error/timeout so we can re-set it on exit
    // 获取状态机当前状态
    CHK_STATUS(getStateMachineCurrentState(pSignalingClient->pStateMachine, &pState));

    // 信令状态机迭代
    CHK_STATUS(signalingStateMachineIterator(pSignalingClient, SIGNALING_GET_CURRENT_TIME(pSignalingClient) + SIGNALING_CONNECT_STATE_TIMEOUT,
                                             SIGNALING_STATE_CONNECTED));

CleanUp:

    CHK_LOG_ERR(retStatus);

    // Re-set the state if we failed
    if (STATUS_FAILED(retStatus) && (pState != NULL)) {
        resetStateMachineRetryCount(pSignalingClient->pStateMachine);
        setStateMachineCurrentState(pSignalingClient->pStateMachine, pState->state);
    }

    LEAVES();
    return retStatus;
}

// 信令断开连接(同步)
STATUS signalingDisconnectSync(PSignalingClient pSignalingClient)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pSignalingClient != NULL, STATUS_NULL_ARG);

    // Check if we are already not connected
    CHK(ATOMIC_LOAD_BOOL(&pSignalingClient->connected), retStatus);

    // 终止正在进行的操作
    CHK_STATUS(terminateOngoingOperations(pSignalingClient));

    ATOMIC_STORE(&pSignalingClient->result, (SIZE_T) SERVICE_CALL_RESULT_OK);

    // 信令状态机迭代器
    CHK_STATUS(signalingStateMachineIterator(pSignalingClient, SIGNALING_GET_CURRENT_TIME(pSignalingClient) + SIGNALING_DISCONNECT_STATE_TIMEOUT,
                                             SIGNALING_STATE_READY));

CleanUp:

    CHK_LOG_ERR(retStatus);

    LEAVES();
    return retStatus;
}

// 信令删除(同步)
STATUS signalingDeleteSync(PSignalingClient pSignalingClient)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pSignalingClient != NULL, STATUS_NULL_ARG);

    // Check if we are already deleting
    CHK(!ATOMIC_LOAD_BOOL(&pSignalingClient->deleted), retStatus);

    // Mark as being deleted
    ATOMIC_STORE_BOOL(&pSignalingClient->deleting, TRUE);

    // 终止正在进行的操作
    CHK_STATUS(terminateOngoingOperations(pSignalingClient));

    // Set the state directly
    // 设置状态机状态
    setStateMachineCurrentState(pSignalingClient->pStateMachine, SIGNALING_STATE_DELETE);

    // 信令状态机迭代器
    CHK_STATUS(signalingStateMachineIterator(pSignalingClient, SIGNALING_GET_CURRENT_TIME(pSignalingClient) + SIGNALING_DELETE_TIMEOUT,
                                             SIGNALING_STATE_DELETED));

CleanUp:

    CHK_LOG_ERR(retStatus);

    LEAVES();
    return retStatus;
}

// 设置信令回调
STATUS validateSignalingCallbacks(PSignalingClient pSignalingClient, PSignalingClientCallbacks pCallbacks)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pSignalingClient != NULL && pCallbacks != NULL, STATUS_NULL_ARG);
    CHK(pCallbacks->version <= SIGNALING_CLIENT_CALLBACKS_CURRENT_VERSION, STATUS_SIGNALING_INVALID_SIGNALING_CALLBACKS_VERSION);

    // Store and validate
    pSignalingClient->signalingClientCallbacks = *pCallbacks;

CleanUp:

    CHK_LOG_ERR(retStatus);

    LEAVES();
    return retStatus;
}

// 设置信令ClientInfo
STATUS validateSignalingClientInfo(PSignalingClient pSignalingClient, PSignalingClientInfoInternal pClientInfo)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pSignalingClient != NULL && pClientInfo != NULL, STATUS_NULL_ARG);
    // 检查版本
    CHK(pClientInfo->signalingClientInfo.version <= SIGNALING_CLIENT_INFO_CURRENT_VERSION, STATUS_SIGNALING_INVALID_CLIENT_INFO_VERSION);
    CHK(STRNLEN(pClientInfo->signalingClientInfo.clientId, MAX_SIGNALING_CLIENT_ID_LEN + 1) <= MAX_SIGNALING_CLIENT_ID_LEN,
        STATUS_SIGNALING_INVALID_CLIENT_INFO_CLIENT_LENGTH);

    // Copy and store internally
    pSignalingClient->clientInfo = *pClientInfo;

    // V1 features
    // 版本差异
    switch (pSignalingClient->clientInfo.signalingClientInfo.version) {
        case 0:
            // Set the default path
            // 设置缓存文件路径
            STRCPY(pSignalingClient->clientInfo.cacheFilePath, DEFAULT_CACHE_FILE_PATH);

            break;

        case 1:
            // If the path is specified and not empty then we validate and copy/store
            if (pSignalingClient->clientInfo.signalingClientInfo.cacheFilePath != NULL &&
                pSignalingClient->clientInfo.signalingClientInfo.cacheFilePath[0] != '\0') {
                CHK(STRNLEN(pSignalingClient->clientInfo.signalingClientInfo.cacheFilePath, MAX_PATH_LEN + 1) <= MAX_PATH_LEN,
                    STATUS_SIGNALING_INVALID_CLIENT_INFO_CACHE_FILE_PATH_LEN);
                STRCPY(pSignalingClient->clientInfo.cacheFilePath, pSignalingClient->clientInfo.signalingClientInfo.cacheFilePath);
            } else {
                // Set the default path
                STRCPY(pSignalingClient->clientInfo.cacheFilePath, DEFAULT_CACHE_FILE_PATH);
            }

            break;

        default:
            CHK_ERR(FALSE, STATUS_INTERNAL_ERROR, "Internal error checking and validating the ClientInfo version");
    }

CleanUp:

    CHK_LOG_ERR(retStatus);
    LEAVES();
    return retStatus;
}

// 设置IceConfiguration
STATUS validateIceConfiguration(PSignalingClient pSignalingClient)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 i;
    UINT64 minTtl = MAX_UINT64;

    CHK(pSignalingClient != NULL, STATUS_NULL_ARG);
    CHK(pSignalingClient->iceConfigCount <= MAX_ICE_CONFIG_COUNT, STATUS_SIGNALING_MAX_ICE_CONFIG_COUNT);
    CHK(pSignalingClient->iceConfigCount > 0, STATUS_SIGNALING_NO_CONFIG_SPECIFIED);

    for (i = 0; i < pSignalingClient->iceConfigCount; i++) {
        CHK(pSignalingClient->iceConfigs[i].version <= SIGNALING_ICE_CONFIG_INFO_CURRENT_VERSION, STATUS_SIGNALING_INVALID_ICE_CONFIG_INFO_VERSION);
        CHK(pSignalingClient->iceConfigs[i].uriCount > 0, STATUS_SIGNALING_NO_CONFIG_URI_SPECIFIED);
        CHK(pSignalingClient->iceConfigs[i].uriCount <= MAX_ICE_CONFIG_URI_COUNT, STATUS_SIGNALING_MAX_ICE_URI_COUNT);

        minTtl = MIN(minTtl, pSignalingClient->iceConfigs[i].ttl);
    }

    CHK(minTtl > ICE_CONFIGURATION_REFRESH_GRACE_PERIOD, STATUS_SIGNALING_ICE_TTL_LESS_THAN_GRACE_PERIOD);

    // 设置iceConfigTime
    pSignalingClient->iceConfigTime = SIGNALING_GET_CURRENT_TIME(pSignalingClient);
    // 设置iceConfig过期时间
    pSignalingClient->iceConfigExpiration = pSignalingClient->iceConfigTime + (minTtl - ICE_CONFIGURATION_REFRESH_GRACE_PERIOD);

CleanUp:

    CHK_LOG_ERR(retStatus);

    LEAVES();
    return retStatus;
}

// 刷新IceConfiguration
STATUS refreshIceConfiguration(PSignalingClient pSignalingClient)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PStateMachineState pStateMachineState = NULL;
    CHAR iceRefreshErrMsg[SIGNALING_MAX_ERROR_MESSAGE_LEN + 1];
    UINT32 iceRefreshErrLen;
    UINT64 curTime;
    BOOL locked = FALSE;

    CHK(pSignalingClient != NULL, STATUS_NULL_ARG);

    DLOGD("Refreshing the ICE Server Configuration");

    // Check whether we have a valid not-yet-expired ICE configuration and if so early exit
    curTime = SIGNALING_GET_CURRENT_TIME(pSignalingClient);
    CHK(pSignalingClient->iceConfigCount == 0 || curTime > pSignalingClient->iceConfigExpiration, retStatus);

    // ICE config can be retrieved in specific states only
    // 设置状态
    CHK_STATUS(acceptSignalingStateMachineState(
        pSignalingClient, SIGNALING_STATE_READY | SIGNALING_STATE_CONNECT | SIGNALING_STATE_CONNECTED | SIGNALING_STATE_DISCONNECTED));

    // 加锁
    MUTEX_LOCK(pSignalingClient->stateLock);
    locked = TRUE;
    // Get and store the current state to re-set to if we fail
    // 获取当前信令状态
    CHK_STATUS(getStateMachineCurrentState(pSignalingClient->pStateMachine, &pStateMachineState));

    // Force the state machine to revert back to get ICE configuration without re-connection
    ATOMIC_STORE(&pSignalingClient->result, (SIZE_T) SERVICE_CALL_RESULT_SIGNALING_RECONNECT_ICE);
    ATOMIC_STORE(&pSignalingClient->refreshIceConfig, TRUE);

    // Iterate the state machinery in steady states only - ready or connected
    if (pStateMachineState->state == SIGNALING_STATE_READY || pStateMachineState->state == SIGNALING_STATE_CONNECTED) {
        // 信令状态机迭代
        CHK_STATUS(signalingStateMachineIterator(pSignalingClient, curTime + SIGNALING_REFRESH_ICE_CONFIG_STATE_TIMEOUT, pStateMachineState->state));
    }

CleanUp:

    // 解锁
    if (locked) {
        MUTEX_UNLOCK(pSignalingClient->stateLock);
    }

    CHK_LOG_ERR(retStatus);

    // Notify the client in case of an error
    if (pSignalingClient != NULL && STATUS_FAILED(retStatus)) {
        // Update the diagnostics info prior calling the error callback
        ATOMIC_INCREMENT(&pSignalingClient->diagnostics.numberOfRuntimeErrors);

        // Reset the stored state as we could have been connected prior to the ICE refresh and we still need to be connected
        if (pStateMachineState != NULL) {
            setStateMachineCurrentState(pSignalingClient->pStateMachine, pStateMachineState->state);
        }

        // Need to invoke the error handler callback
        if (pSignalingClient->signalingClientCallbacks.errorReportFn != NULL) {
            iceRefreshErrLen = SNPRINTF(iceRefreshErrMsg, SIGNALING_MAX_ERROR_MESSAGE_LEN, SIGNALING_ICE_CONFIG_REFRESH_ERROR_MSG, retStatus);
            iceRefreshErrMsg[SIGNALING_MAX_ERROR_MESSAGE_LEN] = '\0';
            pSignalingClient->signalingClientCallbacks.errorReportFn(pSignalingClient->signalingClientCallbacks.customData,
                                                                     STATUS_SIGNALING_ICE_CONFIG_REFRESH_FAILED, iceRefreshErrMsg, iceRefreshErrLen);
        }
    }

    LEAVES();
    return retStatus;
}

// 信令储存正在进行的消息
STATUS signalingStoreOngoingMessage(PSignalingClient pSignalingClient, PSignalingMessage pSignalingMessage)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;
    PSignalingMessage pExistingMessage = NULL;

    CHK(pSignalingClient != NULL && pSignalingMessage != NULL, STATUS_NULL_ARG);
    // 加锁
    MUTEX_LOCK(pSignalingClient->messageQueueLock);
    locked = TRUE;

    // 获取正在进行的消息
    CHK_STATUS(signalingGetOngoingMessage(pSignalingClient, pSignalingMessage->correlationId, pSignalingMessage->peerClientId, &pExistingMessage));
    CHK(pExistingMessage == NULL, STATUS_SIGNALING_DUPLICATE_MESSAGE_BEING_SENT);
    // 消息入队
    CHK_STATUS(stackQueueEnqueue(pSignalingClient->pMessageQueue, (UINT64) pSignalingMessage));

CleanUp:

    // 解锁
    if (locked) {
        MUTEX_UNLOCK(pSignalingClient->messageQueueLock);
    }

    LEAVES();
    return retStatus;
}

// 信令删除正在进行的消息
STATUS signalingRemoveOngoingMessage(PSignalingClient pSignalingClient, PCHAR correlationId)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;
    PSignalingMessage pExistingMessage;
    StackQueueIterator iterator;
    UINT64 data;

    CHK(pSignalingClient != NULL && correlationId != NULL, STATUS_NULL_ARG);
    // 加锁
    MUTEX_LOCK(pSignalingClient->messageQueueLock);
    locked = TRUE;

    // 获得信息队列迭代器
    CHK_STATUS(stackQueueGetIterator(pSignalingClient->pMessageQueue, &iterator));
    while (IS_VALID_ITERATOR(iterator)) {
        // 获取数据
        CHK_STATUS(stackQueueIteratorGetItem(iterator, &data));

        pExistingMessage = (PSignalingMessage) data;
        CHK(pExistingMessage != NULL, STATUS_INTERNAL_ERROR);

        if ((correlationId[0] == '\0' && pExistingMessage->correlationId[0] == '\0') || 0 == STRCMP(pExistingMessage->correlationId, correlationId)) {
            // Remove the match
            // 删除匹配的item
            CHK_STATUS(stackQueueRemoveItem(pSignalingClient->pMessageQueue, data));

            // Early return
            CHK(FALSE, retStatus);
        }
        // 移动指针
        CHK_STATUS(stackQueueIteratorNext(&iterator));
    }

    // Didn't find a match
    CHK(FALSE, STATUS_NOT_FOUND);

CleanUp:

    // 解锁
    if (locked) {
        MUTEX_UNLOCK(pSignalingClient->messageQueueLock);
    }

    LEAVES();
    return retStatus;
}

// 信令获取正在进行的消息(根据correlationId、peerClientId)
STATUS signalingGetOngoingMessage(PSignalingClient pSignalingClient, PCHAR correlationId, PCHAR peerClientId, PSignalingMessage* ppSignalingMessage)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE, checkPeerClientId = TRUE;
    PSignalingMessage pExistingMessage = NULL;
    StackQueueIterator iterator;
    UINT64 data;

    CHK(pSignalingClient != NULL && correlationId != NULL && ppSignalingMessage != NULL, STATUS_NULL_ARG);
    if (peerClientId == NULL || IS_EMPTY_STRING(peerClientId)) {
        checkPeerClientId = FALSE;
    }

    // 加锁
    MUTEX_LOCK(pSignalingClient->messageQueueLock);
    locked = TRUE;

    // 获取迭代器
    CHK_STATUS(stackQueueGetIterator(pSignalingClient->pMessageQueue, &iterator));
    while (IS_VALID_ITERATOR(iterator)) {
        // 获取item
        CHK_STATUS(stackQueueIteratorGetItem(iterator, &data));

        pExistingMessage = (PSignalingMessage) data;
        CHK(pExistingMessage != NULL, STATUS_INTERNAL_ERROR);

        if (((correlationId[0] == '\0' && pExistingMessage->correlationId[0] == '\0') ||
             0 == STRCMP(pExistingMessage->correlationId, correlationId)) &&
            (!checkPeerClientId || 0 == STRCMP(pExistingMessage->peerClientId, peerClientId))) {
            *ppSignalingMessage = pExistingMessage;

            // Early return
            CHK(FALSE, retStatus);
        }

        CHK_STATUS(stackQueueIteratorNext(&iterator));
    }

CleanUp:

    if (ppSignalingMessage != NULL) {
        *ppSignalingMessage = pExistingMessage;
    }

    // 解锁
    if (locked) {
        MUTEX_UNLOCK(pSignalingClient->messageQueueLock);
    }

    LEAVES();
    return retStatus;
}

// 初始化线程跟踪器
STATUS initializeThreadTracker(PThreadTracker pThreadTracker)
{
    STATUS retStatus = STATUS_SUCCESS;
    CHK(pThreadTracker != NULL, STATUS_NULL_ARG);

    pThreadTracker->threadId = INVALID_TID_VALUE;

    // 创建锁
    pThreadTracker->lock = MUTEX_CREATE(FALSE);
    CHK(IS_VALID_MUTEX_VALUE(pThreadTracker->lock), STATUS_INVALID_OPERATION);

    // 创建条件变量
    pThreadTracker->await = CVAR_CREATE();
    CHK(IS_VALID_CVAR_VALUE(pThreadTracker->await), STATUS_INVALID_OPERATION);

    // 设置终止标志
    ATOMIC_STORE_BOOL(&pThreadTracker->terminated, TRUE);

CleanUp:
    return retStatus;
}

// 回收线程跟踪器资源
STATUS uninitializeThreadTracker(PThreadTracker pThreadTracker)
{
    STATUS retStatus = STATUS_SUCCESS;
    CHK(pThreadTracker != NULL, STATUS_NULL_ARG);

    // 回收锁资源
    if (IS_VALID_MUTEX_VALUE(pThreadTracker->lock)) {
        MUTEX_FREE(pThreadTracker->lock);
    }

    // 回收条件变量资源
    if (IS_VALID_CVAR_VALUE(pThreadTracker->await)) {
        CVAR_FREE(pThreadTracker->await);
    }

CleanUp:
    return retStatus;
}

// 等待线程终止
STATUS awaitForThreadTermination(PThreadTracker pThreadTracker, UINT64 timeout)
{
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;

    CHK(pThreadTracker != NULL, STATUS_NULL_ARG);

    // 加锁
    MUTEX_LOCK(pThreadTracker->lock);
    locked = TRUE;
    // Await for the termination
    while (!ATOMIC_LOAD_BOOL(&pThreadTracker->terminated)) {
        CHK_STATUS(CVAR_WAIT(pThreadTracker->await, pThreadTracker->lock, timeout));
    }

    // 解锁
    MUTEX_UNLOCK(pThreadTracker->lock);
    locked = FALSE;

CleanUp:

    // 解锁
    if (locked) {
        MUTEX_UNLOCK(pThreadTracker->lock);
    }

    return retStatus;
}

// 描述通道
STATUS describeChannel(PSignalingClient pSignalingClient, UINT64 time)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL apiCall = TRUE;

    CHK(pSignalingClient != NULL, STATUS_NULL_ARG);

    THREAD_SLEEP_UNTIL(time);
    // Check for the stale credentials
    // 检查凭证是否过期
    CHECK_SIGNALING_CREDENTIALS_EXPIRATION(pSignalingClient);

    ATOMIC_STORE(&pSignalingClient->result, (SIZE_T) SERVICE_CALL_RESULT_NOT_SET);

    // 
    switch (pSignalingClient->pChannelInfo->cachingPolicy) {
        case SIGNALING_API_CALL_CACHE_TYPE_NONE:
            break;

        case SIGNALING_API_CALL_CACHE_TYPE_DESCRIBE_GETENDPOINT:
            /* explicit fall-through */
        case SIGNALING_API_CALL_CACHE_TYPE_FILE:
            if (IS_VALID_TIMESTAMP(pSignalingClient->describeTime) &&
                time <= pSignalingClient->describeTime + pSignalingClient->pChannelInfo->cachingPeriod) {
                apiCall = FALSE;
            }

            break;
    }

    // Call DescribeChannel API
    if (STATUS_SUCCEEDED(retStatus)) {
        if (apiCall) {
            // Call pre hook func
            if (pSignalingClient->clientInfo.describePreHookFn != NULL) {
                retStatus = pSignalingClient->clientInfo.describePreHookFn(pSignalingClient->clientInfo.hookCustomData);
            }

            if (STATUS_SUCCEEDED(retStatus)) {
                retStatus = describeChannelLws(pSignalingClient, time);
                // Store the last call time on success
                if (STATUS_SUCCEEDED(retStatus)) {
                    pSignalingClient->describeTime = time;
                }

                // Calculate the latency whether the call succeeded or not
                SIGNALING_API_LATENCY_CALCULATION(pSignalingClient, time, TRUE);
            }

            // Call post hook func
            if (pSignalingClient->clientInfo.describePostHookFn != NULL) {
                retStatus = pSignalingClient->clientInfo.describePostHookFn(pSignalingClient->clientInfo.hookCustomData);
            }
        } else {
            ATOMIC_STORE(&pSignalingClient->result, (SIZE_T) SERVICE_CALL_RESULT_OK);
        }
    }

CleanUp:

    LEAVES();
    return retStatus;
}

// 创建通道
STATUS createChannel(PSignalingClient pSignalingClient, UINT64 time)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pSignalingClient != NULL, STATUS_NULL_ARG);

    THREAD_SLEEP_UNTIL(time);

    // Check for the stale credentials
    CHECK_SIGNALING_CREDENTIALS_EXPIRATION(pSignalingClient);

    ATOMIC_STORE(&pSignalingClient->result, (SIZE_T) SERVICE_CALL_RESULT_NOT_SET);

    // We are not caching create calls

    if (pSignalingClient->clientInfo.createPreHookFn != NULL) {
        retStatus = pSignalingClient->clientInfo.createPreHookFn(pSignalingClient->clientInfo.hookCustomData);
    }

    if (STATUS_SUCCEEDED(retStatus)) {
        retStatus = createChannelLws(pSignalingClient, time);

        // Store the time of the call on success
        if (STATUS_SUCCEEDED(retStatus)) {
            pSignalingClient->createTime = time;
        }

        // Calculate the latency whether the call succeeded or not
        SIGNALING_API_LATENCY_CALCULATION(pSignalingClient, time, TRUE);
    }

    if (pSignalingClient->clientInfo.createPostHookFn != NULL) {
        retStatus = pSignalingClient->clientInfo.createPostHookFn(pSignalingClient->clientInfo.hookCustomData);
    }

CleanUp:

    LEAVES();
    return retStatus;
}

// 获取ChannelEndpoint
STATUS getChannelEndpoint(PSignalingClient pSignalingClient, UINT64 time)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL apiCall = TRUE;
    SignalingFileCacheEntry signalingFileCacheEntry;

    CHK(pSignalingClient != NULL, STATUS_NULL_ARG);

    THREAD_SLEEP_UNTIL(time);

    // Check for the stale credentials
    CHECK_SIGNALING_CREDENTIALS_EXPIRATION(pSignalingClient);

    ATOMIC_STORE(&pSignalingClient->result, (SIZE_T) SERVICE_CALL_RESULT_NOT_SET);

    switch (pSignalingClient->pChannelInfo->cachingPolicy) {
        case SIGNALING_API_CALL_CACHE_TYPE_NONE:
            break;

        case SIGNALING_API_CALL_CACHE_TYPE_DESCRIBE_GETENDPOINT:
            /* explicit fall-through */
        case SIGNALING_API_CALL_CACHE_TYPE_FILE:
            if (IS_VALID_TIMESTAMP(pSignalingClient->getEndpointTime) &&
                time <= pSignalingClient->getEndpointTime + pSignalingClient->pChannelInfo->cachingPeriod) {
                apiCall = FALSE;
            }

            break;
    }

    if (STATUS_SUCCEEDED(retStatus)) {
        if (apiCall) {
            if (pSignalingClient->clientInfo.getEndpointPreHookFn != NULL) {
                retStatus = pSignalingClient->clientInfo.getEndpointPreHookFn(pSignalingClient->clientInfo.hookCustomData);
            }

            if (STATUS_SUCCEEDED(retStatus)) {
                retStatus = getChannelEndpointLws(pSignalingClient, time);

                if (STATUS_SUCCEEDED(retStatus)) {
                    pSignalingClient->getEndpointTime = time;

                    if (pSignalingClient->pChannelInfo->cachingPolicy == SIGNALING_API_CALL_CACHE_TYPE_FILE) {
                        signalingFileCacheEntry.creationTsEpochSeconds = time / HUNDREDS_OF_NANOS_IN_A_SECOND;
                        signalingFileCacheEntry.role = pSignalingClient->pChannelInfo->channelRoleType;
                        // In case of pre-created channels, the channel name can be NULL in which case we will use ARN.
                        // The validation logic in the channel info validates that both can't be NULL at the same time.
                        STRCPY(signalingFileCacheEntry.channelName,
                               pSignalingClient->pChannelInfo->pChannelName != NULL ? pSignalingClient->pChannelInfo->pChannelName
                                                                                    : pSignalingClient->pChannelInfo->pChannelArn);
                        STRCPY(signalingFileCacheEntry.region, pSignalingClient->pChannelInfo->pRegion);
                        STRCPY(signalingFileCacheEntry.channelArn, pSignalingClient->channelDescription.channelArn);
                        STRCPY(signalingFileCacheEntry.httpsEndpoint, pSignalingClient->channelEndpointHttps);
                        STRCPY(signalingFileCacheEntry.wssEndpoint, pSignalingClient->channelEndpointWss);
                        if (STATUS_FAILED(signalingCacheSaveToFile(&signalingFileCacheEntry, pSignalingClient->clientInfo.cacheFilePath))) {
                            DLOGW("Failed to save signaling cache to file");
                        }
                    }
                }

                // Calculate the latency whether the call succeeded or not
                SIGNALING_API_LATENCY_CALCULATION(pSignalingClient, time, TRUE);
            }

            if (pSignalingClient->clientInfo.getEndpointPostHookFn != NULL) {
                retStatus = pSignalingClient->clientInfo.getEndpointPostHookFn(pSignalingClient->clientInfo.hookCustomData);
            }
        } else {
            ATOMIC_STORE(&pSignalingClient->result, (SIZE_T) SERVICE_CALL_RESULT_OK);
        }
    }

CleanUp:

    LEAVES();
    return retStatus;
}

// 获取IceConfig
STATUS getIceConfig(PSignalingClient pSignalingClient, UINT64 time)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pSignalingClient != NULL, STATUS_NULL_ARG);

    THREAD_SLEEP_UNTIL(time);

    // Check for the stale credentials
    CHECK_SIGNALING_CREDENTIALS_EXPIRATION(pSignalingClient);

    ATOMIC_STORE(&pSignalingClient->result, (SIZE_T) SERVICE_CALL_RESULT_NOT_SET);

    // We are not caching ICE server config calls

    if (pSignalingClient->clientInfo.getIceConfigPreHookFn != NULL) {
        retStatus = pSignalingClient->clientInfo.getIceConfigPreHookFn(pSignalingClient->clientInfo.hookCustomData);
    }

    if (STATUS_SUCCEEDED(retStatus)) {
        retStatus = getIceConfigLws(pSignalingClient, time);

        if (STATUS_SUCCEEDED(retStatus)) {
            pSignalingClient->getIceConfigTime = time;
        }

        // Calculate the latency whether the call succeeded or not
        SIGNALING_API_LATENCY_CALCULATION(pSignalingClient, time, FALSE);
    }

    if (pSignalingClient->clientInfo.getIceConfigPostHookFn != NULL) {
        retStatus = pSignalingClient->clientInfo.getIceConfigPostHookFn(pSignalingClient->clientInfo.hookCustomData);
    }

CleanUp:

    LEAVES();
    return retStatus;
}

// 删除通道
STATUS deleteChannel(PSignalingClient pSignalingClient, UINT64 time)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pSignalingClient != NULL, STATUS_NULL_ARG);

    THREAD_SLEEP_UNTIL(time);

    // Check for the stale credentials
    CHECK_SIGNALING_CREDENTIALS_EXPIRATION(pSignalingClient);

    ATOMIC_STORE(&pSignalingClient->result, (SIZE_T) SERVICE_CALL_RESULT_NOT_SET);

    // We are not caching delete calls

    if (pSignalingClient->clientInfo.deletePreHookFn != NULL) {
        retStatus = pSignalingClient->clientInfo.deletePreHookFn(pSignalingClient->clientInfo.hookCustomData);
    }

    if (STATUS_SUCCEEDED(retStatus)) {
        retStatus = deleteChannelLws(pSignalingClient, time);

        // Store the time of the call on success
        if (STATUS_SUCCEEDED(retStatus)) {
            pSignalingClient->deleteTime = time;
        }

        // Calculate the latency whether the call succeeded or not
        SIGNALING_API_LATENCY_CALCULATION(pSignalingClient, time, TRUE);
    }

    if (pSignalingClient->clientInfo.deletePostHookFn != NULL) {
        retStatus = pSignalingClient->clientInfo.deletePostHookFn(pSignalingClient->clientInfo.hookCustomData);
    }

CleanUp:

    LEAVES();
    return retStatus;
}

// 连接信令通道
STATUS connectSignalingChannel(PSignalingClient pSignalingClient, UINT64 time)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pSignalingClient != NULL, STATUS_NULL_ARG);

    THREAD_SLEEP_UNTIL(time);

    // Check for the stale credentials
    CHECK_SIGNALING_CREDENTIALS_EXPIRATION(pSignalingClient);

    ATOMIC_STORE(&pSignalingClient->result, (SIZE_T) SERVICE_CALL_RESULT_NOT_SET);

    // We are not caching connect calls

    if (pSignalingClient->clientInfo.connectPreHookFn != NULL) {
        retStatus = pSignalingClient->clientInfo.connectPreHookFn(pSignalingClient->clientInfo.hookCustomData);
    }

    if (STATUS_SUCCEEDED(retStatus)) {
        // No need to reconnect again if already connected. This can happen if we get to this state after ice refresh
        if (!ATOMIC_LOAD_BOOL(&pSignalingClient->connected)) {
            ATOMIC_STORE(&pSignalingClient->result, (SIZE_T) SERVICE_CALL_RESULT_NOT_SET);
            retStatus = connectSignalingChannelLws(pSignalingClient, time);

            // Store the time of the call on success
            if (STATUS_SUCCEEDED(retStatus)) {
                pSignalingClient->connectTime = time;
            }
        } else {
            ATOMIC_STORE(&pSignalingClient->result, (SIZE_T) SERVICE_CALL_RESULT_OK);
        }
    }

    if (pSignalingClient->clientInfo.connectPostHookFn != NULL) {
        retStatus = pSignalingClient->clientInfo.connectPostHookFn(pSignalingClient->clientInfo.hookCustomData);
    }

CleanUp:

    LEAVES();
    return retStatus;
}

// 信令获取当前时间
UINT64 signalingGetCurrentTime(UINT64 customData)
{
    UNUSED_PARAM(customData);
    return GETTIME();
}

// 信令获取Metrics
STATUS signalingGetMetrics(PSignalingClient pSignalingClient, PSignalingClientMetrics pSignalingClientMetrics)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT64 curTime;

    curTime = SIGNALING_GET_CURRENT_TIME(pSignalingClient);

    CHK(pSignalingClient != NULL && pSignalingClientMetrics != NULL, STATUS_NULL_ARG);
    CHK(pSignalingClientMetrics->version <= SIGNALING_CLIENT_METRICS_CURRENT_VERSION, STATUS_SIGNALING_INVALID_METRICS_VERSION);

    // Interlock the threading due to data race possibility
    MUTEX_LOCK(pSignalingClient->diagnosticsLock);

    // Fill in the data structures according to the version of the requested structure - currently only v0
    pSignalingClientMetrics->signalingClientStats.signalingClientUptime = curTime - pSignalingClient->diagnostics.createTime;
    pSignalingClientMetrics->signalingClientStats.numberOfMessagesSent = (UINT32) pSignalingClient->diagnostics.numberOfMessagesSent;
    pSignalingClientMetrics->signalingClientStats.numberOfMessagesReceived = (UINT32) pSignalingClient->diagnostics.numberOfMessagesReceived;
    pSignalingClientMetrics->signalingClientStats.iceRefreshCount = (UINT32) pSignalingClient->diagnostics.iceRefreshCount;
    pSignalingClientMetrics->signalingClientStats.numberOfErrors = (UINT32) pSignalingClient->diagnostics.numberOfErrors;
    pSignalingClientMetrics->signalingClientStats.numberOfRuntimeErrors = (UINT32) pSignalingClient->diagnostics.numberOfRuntimeErrors;
    pSignalingClientMetrics->signalingClientStats.numberOfReconnects = (UINT32) pSignalingClient->diagnostics.numberOfReconnects;
    pSignalingClientMetrics->signalingClientStats.cpApiCallLatency = pSignalingClient->diagnostics.cpApiLatency;
    pSignalingClientMetrics->signalingClientStats.dpApiCallLatency = pSignalingClient->diagnostics.dpApiLatency;

    pSignalingClientMetrics->signalingClientStats.connectionDuration =
        ATOMIC_LOAD_BOOL(&pSignalingClient->connected) ? curTime - pSignalingClient->diagnostics.connectTime : 0;
    pSignalingClientMetrics->signalingClientStats.apiCallRetryCount = pSignalingClient->diagnostics.stateMachineRetryCount;

    MUTEX_UNLOCK(pSignalingClient->diagnosticsLock);

CleanUp:

    LEAVES();
    return retStatus;
}
