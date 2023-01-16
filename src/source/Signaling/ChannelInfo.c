#define LOG_CLASS "ChannelInfo"
#include "../Include_i.h"

// 创建验证ChannelInfo
STATUS createValidateChannelInfo(PChannelInfo pOrigChannelInfo, PChannelInfo* ppChannelInfo)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    UINT32 allocSize, nameLen = 0, arnLen = 0, regionLen = 0, cplLen = 0, certLen = 0, postfixLen = 0, agentLen = 0, userAgentLen = 0, kmsLen = 0,
                      tagsSize;
    PCHAR pCurPtr, pRegionPtr;
    PChannelInfo pChannelInfo = NULL;

    CHK(pOrigChannelInfo != NULL && ppChannelInfo != NULL, STATUS_NULL_ARG);

    CHK((pOrigChannelInfo->pChannelName != NULL || pOrigChannelInfo->pChannelArn != NULL) && ppChannelInfo != NULL, STATUS_NULL_ARG);

    // Get and validate the lengths for all strings and store lengths excluding null terminator
    // 校验通道名, 设置nameLen
    if (pOrigChannelInfo->pChannelName != NULL) {
        CHK((nameLen = (UINT32) STRNLEN(pOrigChannelInfo->pChannelName, MAX_CHANNEL_NAME_LEN + 1)) <= MAX_CHANNEL_NAME_LEN,
            STATUS_SIGNALING_INVALID_CHANNEL_NAME_LENGTH);
    }
    // 校验ChannelArn， 设置arnLen
    if (pOrigChannelInfo->pChannelArn != NULL) {
        CHK((arnLen = (UINT32) STRNLEN(pOrigChannelInfo->pChannelArn, MAX_ARN_LEN + 1)) <= MAX_ARN_LEN, STATUS_SIGNALING_INVALID_CHANNEL_ARN_LENGTH);
    }

    // Fix-up the region
    if (pOrigChannelInfo->pRegion != NULL) {
        CHK((regionLen = (UINT32) STRNLEN(pOrigChannelInfo->pRegion, MAX_REGION_NAME_LEN + 1)) <= MAX_REGION_NAME_LEN,
            STATUS_SIGNALING_INVALID_REGION_LENGTH);
        pRegionPtr = pOrigChannelInfo->pRegion;
    }
    // 设置默认地区us-west-2
    else {
        regionLen = ARRAY_SIZE(DEFAULT_AWS_REGION) - 1;
        pRegionPtr = DEFAULT_AWS_REGION;
    }

    // 校验controlPlaneUrl,设置cplLen
    if (pOrigChannelInfo->pControlPlaneUrl != NULL) {
        CHK((cplLen = (UINT32) STRNLEN(pOrigChannelInfo->pControlPlaneUrl, MAX_URI_CHAR_LEN + 1)) <= MAX_URI_CHAR_LEN,
            STATUS_SIGNALING_INVALID_CPL_LENGTH);
    } else {
        cplLen = MAX_CONTROL_PLANE_URI_CHAR_LEN;
    }

    // 校验certPath, 设置certLen
    if (pOrigChannelInfo->pCertPath != NULL) {
        CHK((certLen = (UINT32) STRNLEN(pOrigChannelInfo->pCertPath, MAX_PATH_LEN + 1)) <= MAX_PATH_LEN,
            STATUS_SIGNALING_INVALID_CERTIFICATE_PATH_LENGTH);
    }

    userAgentLen = MAX_USER_AGENT_LEN;

    // 校验UserAgentPostfix, 设置postfixLen
    if (pOrigChannelInfo->pUserAgentPostfix != NULL) {
        CHK((postfixLen = (UINT32) STRNLEN(pOrigChannelInfo->pUserAgentPostfix, MAX_CUSTOM_USER_AGENT_NAME_POSTFIX_LEN + 1)) <=
                MAX_CUSTOM_USER_AGENT_NAME_POSTFIX_LEN,
            STATUS_SIGNALING_INVALID_AGENT_POSTFIX_LENGTH);
    }

    // 校验CustomUserAgent，设置agentLen
    if (pOrigChannelInfo->pCustomUserAgent != NULL) {
        CHK((agentLen = (UINT32) STRNLEN(pOrigChannelInfo->pCustomUserAgent, MAX_CUSTOM_USER_AGENT_LEN + 1)) <= MAX_CUSTOM_USER_AGENT_LEN,
            STATUS_SIGNALING_INVALID_AGENT_LENGTH);
    }

    // 校验KmsKeyId,设置kmsLen
    if (pOrigChannelInfo->pKmsKeyId != NULL) {
        CHK((kmsLen = (UINT32) STRNLEN(pOrigChannelInfo->pKmsKeyId, MAX_ARN_LEN + 1)) <= MAX_ARN_LEN, STATUS_SIGNALING_INVALID_KMS_KEY_LENGTH);
    }

    // 设置messageTtl
    if (pOrigChannelInfo->messageTtl == 0) {
        pOrigChannelInfo->messageTtl = SIGNALING_DEFAULT_MESSAGE_TTL_VALUE;
    } else {
        CHK(pOrigChannelInfo->messageTtl >= MIN_SIGNALING_MESSAGE_TTL_VALUE && pOrigChannelInfo->messageTtl <= MAX_SIGNALING_MESSAGE_TTL_VALUE,
            STATUS_SIGNALING_INVALID_MESSAGE_TTL_VALUE);
    }

    // If tags count is not zero then pTags shouldn't be NULL
    CHK_STATUS(validateTags(pOrigChannelInfo->tagCount, pOrigChannelInfo->pTags));

    // Account for the tags
    CHK_STATUS(packageTags(pOrigChannelInfo->tagCount, pOrigChannelInfo->pTags, 0, NULL, &tagsSize));

    // Allocate enough storage to hold the data with aligned strings size and set the pointers and NULL terminators
    allocSize = SIZEOF(ChannelInfo) + ALIGN_UP_TO_MACHINE_WORD(1 + nameLen) + ALIGN_UP_TO_MACHINE_WORD(1 + arnLen) +
        ALIGN_UP_TO_MACHINE_WORD(1 + regionLen) + ALIGN_UP_TO_MACHINE_WORD(1 + cplLen) + ALIGN_UP_TO_MACHINE_WORD(1 + certLen) +
        ALIGN_UP_TO_MACHINE_WORD(1 + postfixLen) + ALIGN_UP_TO_MACHINE_WORD(1 + agentLen) + ALIGN_UP_TO_MACHINE_WORD(1 + userAgentLen) +
        ALIGN_UP_TO_MACHINE_WORD(1 + kmsLen) + tagsSize;
    // 分配内存
    CHK(NULL != (pChannelInfo = (PChannelInfo) MEMCALLOC(1, allocSize)), STATUS_NOT_ENOUGH_MEMORY);

    // 设值channelInfo
    pChannelInfo->version = CHANNEL_INFO_CURRENT_VERSION;
    pChannelInfo->channelType = pOrigChannelInfo->channelType;
    pChannelInfo->channelRoleType = pOrigChannelInfo->channelRoleType;
    pChannelInfo->cachingPeriod = pOrigChannelInfo->cachingPeriod;
    pChannelInfo->retry = pOrigChannelInfo->retry;
    pChannelInfo->reconnect = pOrigChannelInfo->reconnect;
    pChannelInfo->messageTtl = pOrigChannelInfo->messageTtl;
    pChannelInfo->tagCount = pOrigChannelInfo->tagCount;

    // V1 handling
    // 设置缓存策略
    if (pOrigChannelInfo->version > 0) {
        pChannelInfo->cachingPolicy = pOrigChannelInfo->cachingPolicy;
    } else {
        pChannelInfo->cachingPolicy = SIGNALING_API_CALL_CACHE_TYPE_NONE;
    }

    // Set the current pointer to the end
    pCurPtr = (PCHAR) (pChannelInfo + 1);

    // Set the pointers to the end and copy the data.
    // NOTE: the structure is calloc-ed so the strings will be NULL terminated
    // 设置channelName
    if (nameLen != 0) {
        STRCPY(pCurPtr, pOrigChannelInfo->pChannelName);
        pChannelInfo->pChannelName = pCurPtr;
        pCurPtr += ALIGN_UP_TO_MACHINE_WORD(nameLen + 1); // For the NULL terminator
    }

    // 设置ChannelArn
    if (arnLen != 0) {
        STRCPY(pCurPtr, pOrigChannelInfo->pChannelArn);
        pChannelInfo->pChannelArn = pCurPtr;
        pCurPtr += ALIGN_UP_TO_MACHINE_WORD(arnLen + 1);
    }

    // 设置Region
    STRCPY(pCurPtr, pRegionPtr);
    pChannelInfo->pRegion = pCurPtr;
    pCurPtr += ALIGN_UP_TO_MACHINE_WORD(regionLen + 1);

    // 设置ControlPlaneUrl
    if (pOrigChannelInfo->pControlPlaneUrl != NULL && *pOrigChannelInfo->pControlPlaneUrl != '\0') {
        STRCPY(pCurPtr, pOrigChannelInfo->pControlPlaneUrl);
    } else {
        // Create a fully qualified URI
        SNPRINTF(pCurPtr, MAX_CONTROL_PLANE_URI_CHAR_LEN, "%s%s.%s%s", CONTROL_PLANE_URI_PREFIX, KINESIS_VIDEO_SERVICE_NAME, pChannelInfo->pRegion,
                 CONTROL_PLANE_URI_POSTFIX);
    }

    pChannelInfo->pControlPlaneUrl = pCurPtr;
    pCurPtr += ALIGN_UP_TO_MACHINE_WORD(cplLen + 1);

    // 设置certPath
    if (certLen != 0) {
        STRCPY(pCurPtr, pOrigChannelInfo->pCertPath);
        pChannelInfo->pCertPath = pCurPtr;
        pCurPtr += ALIGN_UP_TO_MACHINE_WORD(certLen + 1);
    }

    // 设置UserAgentPostfix
    if (postfixLen != 0) {
        STRCPY(pCurPtr, pOrigChannelInfo->pUserAgentPostfix);
        pChannelInfo->pUserAgentPostfix = pCurPtr;
        pCurPtr += ALIGN_UP_TO_MACHINE_WORD(postfixLen + 1);
    }

    // 设置CustomUserAgent
    if (agentLen != 0) {
        STRCPY(pCurPtr, pOrigChannelInfo->pCustomUserAgent);
        pChannelInfo->pCustomUserAgent = pCurPtr;
        pCurPtr += ALIGN_UP_TO_MACHINE_WORD(agentLen + 1);
    }

    // 设置UserAgent
    getUserAgentString(pOrigChannelInfo->pUserAgentPostfix, pOrigChannelInfo->pCustomUserAgent, MAX_USER_AGENT_LEN, pCurPtr);
    pChannelInfo->pUserAgent = pCurPtr;
    pChannelInfo->pUserAgent[MAX_USER_AGENT_LEN] = '\0';
    pCurPtr += ALIGN_UP_TO_MACHINE_WORD(userAgentLen + 1);

    // 设置KvmKeyId
    if (kmsLen != 0) {
        STRCPY(pCurPtr, pOrigChannelInfo->pCustomUserAgent);
        pChannelInfo->pKmsKeyId = pCurPtr;
        pCurPtr += ALIGN_UP_TO_MACHINE_WORD(kmsLen + 1);
    }

    // Fix-up the caching period
    // 设置缓存周期
    if (pChannelInfo->cachingPeriod == SIGNALING_API_CALL_CACHE_TTL_SENTINEL_VALUE) {
        pChannelInfo->cachingPeriod = SIGNALING_DEFAULT_API_CALL_CACHE_TTL;
    }

    // Process tags
    // 
    pChannelInfo->tagCount = pOrigChannelInfo->tagCount;
    if (pOrigChannelInfo->tagCount != 0) {
        pChannelInfo->pTags = (PTag) pCurPtr;

        // Package the tags after the structure
        CHK_STATUS(packageTags(pOrigChannelInfo->tagCount, pOrigChannelInfo->pTags, tagsSize, pChannelInfo->pTags, NULL));
    }

CleanUp:

    if (STATUS_FAILED(retStatus)) {
        freeChannelInfo(&pChannelInfo);
    }

    if (ppChannelInfo != NULL) {
        *ppChannelInfo = pChannelInfo;
    }

    LEAVES();
    return retStatus;
}

// 回收ChannelInfo资源
STATUS freeChannelInfo(PChannelInfo* ppChannelInfo)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PChannelInfo pChannelInfo;

    CHK(ppChannelInfo != NULL, STATUS_NULL_ARG);
    pChannelInfo = *ppChannelInfo;

    CHK(pChannelInfo != NULL, retStatus);

    // Warn if we have an unknown version as the free might crash or leak
    if (pChannelInfo->version > CHANNEL_INFO_CURRENT_VERSION) {
        DLOGW("Channel info version check failed 0x%08x", STATUS_SIGNALING_INVALID_CHANNEL_INFO_VERSION);
    }

    MEMFREE(*ppChannelInfo);

    *ppChannelInfo = NULL;

CleanUp:

    LEAVES();
    return retStatus;
}

// 从string获取Channel状态
SIGNALING_CHANNEL_STATUS getChannelStatusFromString(PCHAR status, UINT32 length)
{
    // Assume the channel Deleting status first
    SIGNALING_CHANNEL_STATUS channelStatus = SIGNALING_CHANNEL_STATUS_DELETING;
    // 活跃
    if (0 == STRNCMP((PCHAR) "ACTIVE", status, length)) {
        channelStatus = SIGNALING_CHANNEL_STATUS_ACTIVE;
    }
    // 创建中
    else if (0 == STRNCMP((PCHAR) "CREATING", status, length)) {
        channelStatus = SIGNALING_CHANNEL_STATUS_CREATING;
    }
    // 更新中
    else if (0 == STRNCMP((PCHAR) "UPDATING", status, length)) {
        channelStatus = SIGNALING_CHANNEL_STATUS_UPDATING;
    }
    // 删除中
    else if (0 == STRNCMP((PCHAR) "DELETING", status, length)) {
        channelStatus = SIGNALING_CHANNEL_STATUS_DELETING;
    }

    return channelStatus;
}

// 从string获取Channel类型
SIGNALING_CHANNEL_TYPE getChannelTypeFromString(PCHAR type, UINT32 length)
{
    // Assume the channel Deleting status first
    SIGNALING_CHANNEL_TYPE channelType = SIGNALING_CHANNEL_TYPE_UNKNOWN;

    if (0 == STRNCMP(SIGNALING_CHANNEL_TYPE_SINGLE_MASTER_STR, type, length)) {
        channelType = SIGNALING_CHANNEL_TYPE_SINGLE_MASTER;
    }

    return channelType;
}

// 将ChannelType 转为string
PCHAR getStringFromChannelType(SIGNALING_CHANNEL_TYPE type)
{
    PCHAR typeStr;

    switch (type) {
        case SIGNALING_CHANNEL_TYPE_SINGLE_MASTER:
            typeStr = SIGNALING_CHANNEL_TYPE_SINGLE_MASTER_STR;
            break;
        default:
            typeStr = SIGNALING_CHANNEL_TYPE_UNKNOWN_STR;
            break;
    }

    return typeStr;
}

// 从string获取通道角色类型
SIGNALING_CHANNEL_ROLE_TYPE getChannelRoleTypeFromString(PCHAR type, UINT32 length)
{
    // Assume the channel Deleting status first
    SIGNALING_CHANNEL_ROLE_TYPE channelRoleType = SIGNALING_CHANNEL_ROLE_TYPE_UNKNOWN;

    if (0 == STRNCMP(SIGNALING_CHANNEL_ROLE_TYPE_MASTER_STR, type, length)) {
        channelRoleType = SIGNALING_CHANNEL_ROLE_TYPE_MASTER;
    } else if (0 == STRNCMP(SIGNALING_CHANNEL_ROLE_TYPE_VIEWER_STR, type, length)) {
        channelRoleType = SIGNALING_CHANNEL_ROLE_TYPE_VIEWER;
    }

    return channelRoleType;
}

// 将通道角色类型转为string
PCHAR getStringFromChannelRoleType(SIGNALING_CHANNEL_ROLE_TYPE type)
{
    PCHAR typeStr;

    switch (type) {
        case SIGNALING_CHANNEL_ROLE_TYPE_MASTER:
            typeStr = SIGNALING_CHANNEL_ROLE_TYPE_MASTER_STR;
            break;
        case SIGNALING_CHANNEL_ROLE_TYPE_VIEWER:
            typeStr = SIGNALING_CHANNEL_ROLE_TYPE_VIEWER_STR;
            break;
        default:
            typeStr = SIGNALING_CHANNEL_ROLE_TYPE_UNKNOWN_STR;
            break;
    }

    return typeStr;
}
