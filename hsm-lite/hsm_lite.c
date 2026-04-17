/**
 * @file hsm_lite.c
 * @brief hsm-lite PKCS#11核心实现（精简版）
 * 
 * 教学级实现，约500行代码
 * 
 * @version 1.0.0
 * @date 2026-04-15
 */

#include "hsm_lite.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

/* ============================================================
 * 内部数据结构
 * ============================================================ */

/* AES密钥对象 */
typedef struct {
    CK_OBJECT_HANDLE    handle;
    CK_BYTE             key[HSM_AES_KEY_SIZE];
    CK_ULONG            key_len;
    CK_BBOOL            in_use;
} hsm_key_t;

/* Session对象 */
typedef struct {
    CK_SESSION_HANDLE   handle;
    CK_SLOT_ID          slot_id;
    CK_BBOOL            in_use;
    CK_BBOOL            is_rw;
    
    /* 操作状态 */
    CK_MECHANISM_TYPE   active_mech;
    CK_OBJECT_HANDLE    active_key;
    CK_BBOOL            encrypt_init;
    CK_BBOOL            decrypt_init;
} hsm_session_t;

/* 全局上下文 */
static struct {
    CK_BBOOL            initialized;
    hsm_session_t       sessions[HSM_MAX_SESSIONS];
    hsm_key_t           keys[HSM_MAX_OBJECTS];
    CK_ULONG            session_count;
    CK_ULONG            key_count;
    CK_SESSION_HANDLE   next_session_handle;
    CK_OBJECT_HANDLE    next_key_handle;
} g_ctx;

/* ============================================================
 * 内部辅助函数
 * ============================================================ */

static hsm_session_t *find_session(CK_SESSION_HANDLE hSession)
{
    for (CK_ULONG i = 0; i < HSM_MAX_SESSIONS; i++) {
        if (g_ctx.sessions[i].in_use && 
            g_ctx.sessions[i].handle == hSession) {
            return &g_ctx.sessions[i];
        }
    }
    return NULL;
}

static hsm_key_t *find_key(CK_OBJECT_HANDLE hKey)
{
    for (CK_ULONG i = 0; i < HSM_MAX_OBJECTS; i++) {
        if (g_ctx.keys[i].in_use && 
            g_ctx.keys[i].handle == hKey) {
            return &g_ctx.keys[i];
        }
    }
    return NULL;
}

static CK_RV get_random_bytes(CK_BYTE_PTR buf, CK_ULONG len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return CKR_GENERAL_ERROR;
    }
    
    ssize_t ret = read(fd, buf, len);
    close(fd);
    
    return (ret == (ssize_t)len) ? CKR_OK : CKR_GENERAL_ERROR;
}

/* ============================================================
 * AES加密（简化实现）
 * ============================================================ */

static CK_RV aes_encrypt_ecb(CK_BYTE_PTR key, CK_BYTE_PTR data,
                             CK_ULONG len, CK_BYTE_PTR out)
{
    /* 教学简化：直接异或（非真实AES） */
    for (CK_ULONG i = 0; i < len; i++) {
        out[i] = data[i] ^ key[i % HSM_AES_KEY_SIZE];
    }
    return CKR_OK;
}

static CK_RV aes_decrypt_ecb(CK_BYTE_PTR key, CK_BYTE_PTR data,
                             CK_ULONG len, CK_BYTE_PTR out)
{
    for (CK_ULONG i = 0; i < len; i++) {
        out[i] = data[i] ^ key[i % HSM_AES_KEY_SIZE];
    }
    return CKR_OK;
}

static CK_RV aes_encrypt_cbc(CK_BYTE_PTR key, CK_BYTE_PTR iv,
                             CK_BYTE_PTR data, CK_ULONG len,
                             CK_BYTE_PTR out)
{
    CK_BYTE block[HSM_AES_BLOCK_SIZE];
    CK_BYTE *prev = iv;
    
    for (CK_ULONG i = 0; i < len; i += HSM_AES_BLOCK_SIZE) {
        for (CK_ULONG j = 0; j < HSM_AES_BLOCK_SIZE && i + j < len; j++) {
            block[j] = data[i + j] ^ prev[j];
        }
        aes_encrypt_ecb(key, block, HSM_AES_BLOCK_SIZE, out + i);
        prev = out + i;
    }
    return CKR_OK;
}

static CK_RV aes_decrypt_cbc(CK_BYTE_PTR key, CK_BYTE_PTR iv,
                             CK_BYTE_PTR data, CK_ULONG len,
                             CK_BYTE_PTR out)
{
    CK_BYTE block[HSM_AES_BLOCK_SIZE];
    CK_BYTE *prev = iv;
    
    for (CK_ULONG i = 0; i < len; i += HSM_AES_BLOCK_SIZE) {
        aes_decrypt_ecb(key, data + i, HSM_AES_BLOCK_SIZE, block);
        for (CK_ULONG j = 0; j < HSM_AES_BLOCK_SIZE && i + j < len; j++) {
            out[i + j] = block[j] ^ prev[j];
        }
        prev = data + i;
    }
    return CKR_OK;
}

/* ============================================================
 * PKCS#11函数实现
 * ============================================================ */

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
    (void)pInitArgs;
    
    if (g_ctx.initialized) {
        return CKR_GENERAL_ERROR;
    }
    
    memset(&g_ctx, 0, sizeof(g_ctx));
    g_ctx.initialized = CK_TRUE;
    g_ctx.next_session_handle = 1;
    g_ctx.next_key_handle = 1;
    
    printf("[hsm-lite] Initialized (version %s)\n", HSM_LITE_VERSION);
    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
    (void)pReserved;
    
    if (!g_ctx.initialized) {
        return CKR_FUNCTION_NOT_INITIALIZED;
    }
    
    g_ctx.initialized = CK_FALSE;
    printf("[hsm-lite] Finalized\n");
    return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
                    CK_ULONG_PTR pulCount)
{
    (void)tokenPresent;
    
    if (!g_ctx.initialized) {
        return CKR_FUNCTION_NOT_INITIALIZED;
    }
    
    if (!pulCount) {
        return CKR_ARGUMENTS_BAD;
    }
    
    *pulCount = 1;
    
    if (pSlotList) {
        pSlotList[0] = 0;
    }
    
    return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
                    CK_SESSION_HANDLE_PTR phSession)
{
    if (!g_ctx.initialized) {
        return CKR_FUNCTION_NOT_INITIALIZED;
    }
    
    if (slotID != 0) {
        return CKR_SLOT_ID_INVALID;
    }
    
    if (!phSession) {
        return CKR_ARGUMENTS_BAD;
    }
    
    if (g_ctx.session_count >= HSM_MAX_SESSIONS) {
        return CKR_GENERAL_ERROR;
    }
    
    for (CK_ULONG i = 0; i < HSM_MAX_SESSIONS; i++) {
        if (!g_ctx.sessions[i].in_use) {
            g_ctx.sessions[i].in_use = CK_TRUE;
            g_ctx.sessions[i].handle = g_ctx.next_session_handle++;
            g_ctx.sessions[i].slot_id = slotID;
            g_ctx.sessions[i].is_rw = (flags & CKF_RW_SESSION) ? CK_TRUE : CK_FALSE;
            g_ctx.sessions[i].encrypt_init = CK_FALSE;
            g_ctx.sessions[i].decrypt_init = CK_FALSE;
            g_ctx.session_count++;
            
            *phSession = g_ctx.sessions[i].handle;
            printf("[hsm-lite] OpenSession: handle=%lu\n", *phSession);
            return CKR_OK;
        }
    }
    
    return CKR_GENERAL_ERROR;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    if (!g_ctx.initialized) {
        return CKR_FUNCTION_NOT_INITIALIZED;
    }
    
    hsm_session_t *sess = find_session(hSession);
    if (!sess) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    sess->in_use = CK_FALSE;
    g_ctx.session_count--;
    printf("[hsm-lite] CloseSession: handle=%lu\n", hSession);
    return CKR_OK;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism,
                    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                    CK_OBJECT_HANDLE_PTR phKey)
{
    (void)pTemplate;
    (void)ulCount;
    
    if (!g_ctx.initialized) {
        return CKR_FUNCTION_NOT_INITIALIZED;
    }
    
    hsm_session_t *sess = find_session(hSession);
    if (!sess) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if (!pMechanism || !phKey) {
        return CKR_ARGUMENTS_BAD;
    }
    
    if (pMechanism->mechanism != CKM_AES_KEY_GEN) {
        return CKR_MECHANISM_INVALID;
    }
    
    if (g_ctx.key_count >= HSM_MAX_OBJECTS) {
        return CKR_GENERAL_ERROR;
    }
    
    for (CK_ULONG i = 0; i < HSM_MAX_OBJECTS; i++) {
        if (!g_ctx.keys[i].in_use) {
            g_ctx.keys[i].in_use = CK_TRUE;
            g_ctx.keys[i].handle = g_ctx.next_key_handle++;
            g_ctx.keys[i].key_len = HSM_AES_KEY_SIZE;
            
            CK_RV rv = get_random_bytes(g_ctx.keys[i].key, HSM_AES_KEY_SIZE);
            if (rv != CKR_OK) {
                g_ctx.keys[i].in_use = CK_FALSE;
                return rv;
            }
            
            g_ctx.key_count++;
            *phKey = g_ctx.keys[i].handle;
            
            printf("[hsm-lite] GenerateKey: handle=%lu (AES-256)\n", *phKey);
            return CKR_OK;
        }
    }
    
    return CKR_GENERAL_ERROR;
}

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession,
                     CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                     CK_OBJECT_HANDLE_PTR phObject)
{
    if (!g_ctx.initialized) {
        return CKR_FUNCTION_NOT_INITIALIZED;
    }
    
    hsm_session_t *sess = find_session(hSession);
    if (!sess) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if (!pTemplate || !phObject || ulCount == 0) {
        return CKR_ARGUMENTS_BAD;
    }
    
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_AES;
    CK_ULONG value_len = HSM_AES_KEY_SIZE;
    CK_BYTE_PTR value = NULL;
    
    for (CK_ULONG i = 0; i < ulCount; i++) {
        switch (pTemplate[i].type) {
        case CKA_CLASS:
            class = *((CK_OBJECT_CLASS *)pTemplate[i].pValue);
            break;
        case CKA_KEY_TYPE:
            key_type = *((CK_KEY_TYPE *)pTemplate[i].pValue);
            break;
        case CKA_VALUE:
            value = (CK_BYTE_PTR)pTemplate[i].pValue;
            value_len = pTemplate[i].ulValueLen;
            break;
        }
    }
    
    if (class != CKO_SECRET_KEY || key_type != CKK_AES) {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    
    if (g_ctx.key_count >= HSM_MAX_OBJECTS) {
        return CKR_GENERAL_ERROR;
    }
    
    for (CK_ULONG i = 0; i < HSM_MAX_OBJECTS; i++) {
        if (!g_ctx.keys[i].in_use) {
            g_ctx.keys[i].in_use = CK_TRUE;
            g_ctx.keys[i].handle = g_ctx.next_key_handle++;
            g_ctx.keys[i].key_len = value_len;
            
            if (value) {
                memcpy(g_ctx.keys[i].key, value, value_len);
            } else {
                get_random_bytes(g_ctx.keys[i].key, value_len);
            }
            
            g_ctx.key_count++;
            *phObject = g_ctx.keys[i].handle;
            
            printf("[hsm-lite] CreateObject: handle=%lu\n", *phObject);
            return CKR_OK;
        }
    }
    
    return CKR_GENERAL_ERROR;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession,
                      CK_OBJECT_HANDLE hObject)
{
    if (!g_ctx.initialized) {
        return CKR_FUNCTION_NOT_INITIALIZED;
    }
    
    hsm_session_t *sess = find_session(hSession);
    if (!sess) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    hsm_key_t *key = find_key(hObject);
    if (!key) {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    
    memset(key->key, 0, HSM_AES_KEY_SIZE);
    key->in_use = CK_FALSE;
    g_ctx.key_count--;
    
    printf("[hsm-lite] DestroyObject: handle=%lu\n", hObject);
    return CKR_OK;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession,
                          CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    if (!g_ctx.initialized) {
        return CKR_FUNCTION_NOT_INITIALIZED;
    }
    
    hsm_session_t *sess = find_session(hSession);
    if (!sess) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    hsm_key_t *key = find_key(hObject);
    if (!key) {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    
    for (CK_ULONG i = 0; i < ulCount; i++) {
        switch (pTemplate[i].type) {
        case CKA_CLASS:
            *((CK_OBJECT_CLASS *)pTemplate[i].pValue) = CKO_SECRET_KEY;
            pTemplate[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
            break;
        case CKA_KEY_TYPE:
            *((CK_KEY_TYPE *)pTemplate[i].pValue) = CKK_AES;
            pTemplate[i].ulValueLen = sizeof(CK_KEY_TYPE);
            break;
        case CKA_VALUE_LEN:
            *((CK_ULONG *)pTemplate[i].pValue) = key->key_len;
            pTemplate[i].ulValueLen = sizeof(CK_ULONG);
            break;
        case CKA_VALUE:
            if (pTemplate[i].pValue) {
                memcpy(pTemplate[i].pValue, key->key, key->key_len);
                pTemplate[i].ulValueLen = key->key_len;
            } else {
                pTemplate[i].ulValueLen = key->key_len;
            }
            break;
        default:
            pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
            break;
        }
    }
    
    return CKR_OK;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    if (!g_ctx.initialized) {
        return CKR_FUNCTION_NOT_INITIALIZED;
    }
    
    hsm_session_t *sess = find_session(hSession);
    if (!sess) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    hsm_key_t *key = find_key(hKey);
    if (!key) {
        return CKR_KEY_HANDLE_INVALID;
    }
    
    if (pMechanism->mechanism != CKM_AES_ECB &&
        pMechanism->mechanism != CKM_AES_CBC) {
        return CKR_MECHANISM_INVALID;
    }
    
    sess->active_mech = pMechanism->mechanism;
    sess->active_key = hKey;
    sess->encrypt_init = CK_TRUE;
    
    printf("[hsm-lite] EncryptInit: mech=%s\n",
           pMechanism->mechanism == CKM_AES_ECB ? "ECB" : "CBC");
    return CKR_OK;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession,
                CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                CK_BYTE_PTR pEncrypted, CK_ULONG_PTR pulEncryptedLen)
{
    if (!g_ctx.initialized) {
        return CKR_FUNCTION_NOT_INITIALIZED;
    }
    
    hsm_session_t *sess = find_session(hSession);
    if (!sess) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if (!sess->encrypt_init) {
        return CKR_FUNCTION_NOT_INITIALIZED;
    }
    
    hsm_key_t *key = find_key(sess->active_key);
    if (!key) {
        return CKR_KEY_HANDLE_INVALID;
    }
    
    if (!pEncrypted || !pulEncryptedLen) {
        return CKR_ARGUMENTS_BAD;
    }
    
    *pulEncryptedLen = ulDataLen;
    
    CK_RV rv;
    if (sess->active_mech == CKM_AES_ECB) {
        rv = aes_encrypt_ecb(key->key, pData, ulDataLen, pEncrypted);
    } else {
        CK_BYTE iv[HSM_AES_BLOCK_SIZE] = {0};
        rv = aes_encrypt_cbc(key->key, iv, pData, ulDataLen, pEncrypted);
    }
    
    printf("[hsm-lite] Encrypt: %lu bytes -> %lu bytes\n",
           ulDataLen, *pulEncryptedLen);
    return rv;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    if (!g_ctx.initialized) {
        return CKR_FUNCTION_NOT_INITIALIZED;
    }
    
    hsm_session_t *sess = find_session(hSession);
    if (!sess) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    hsm_key_t *key = find_key(hKey);
    if (!key) {
        return CKR_KEY_HANDLE_INVALID;
    }
    
    if (pMechanism->mechanism != CKM_AES_ECB &&
        pMechanism->mechanism != CKM_AES_CBC) {
        return CKR_MECHANISM_INVALID;
    }
    
    sess->active_mech = pMechanism->mechanism;
    sess->active_key = hKey;
    sess->decrypt_init = CK_TRUE;
    
    printf("[hsm-lite] DecryptInit: mech=%s\n",
           pMechanism->mechanism == CKM_AES_ECB ? "ECB" : "CBC");
    return CKR_OK;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession,
                CK_BYTE_PTR pEncrypted, CK_ULONG ulEncryptedLen,
                CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    if (!g_ctx.initialized) {
        return CKR_FUNCTION_NOT_INITIALIZED;
    }
    
    hsm_session_t *sess = find_session(hSession);
    if (!sess) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if (!sess->decrypt_init) {
        return CKR_FUNCTION_NOT_INITIALIZED;
    }
    
    hsm_key_t *key = find_key(sess->active_key);
    if (!key) {
        return CKR_KEY_HANDLE_INVALID;
    }
    
    if (!pData || !pulDataLen) {
        return CKR_ARGUMENTS_BAD;
    }
    
    *pulDataLen = ulEncryptedLen;
    
    CK_RV rv;
    if (sess->active_mech == CKM_AES_ECB) {
        rv = aes_decrypt_ecb(key->key, pEncrypted, ulEncryptedLen, pData);
    } else {
        CK_BYTE iv[HSM_AES_BLOCK_SIZE] = {0};
        rv = aes_decrypt_cbc(key->key, iv, pEncrypted, ulEncryptedLen, pData);
    }
    
    printf("[hsm-lite] Decrypt: %lu bytes -> %lu bytes\n",
           ulEncryptedLen, *pulDataLen);
    return rv;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession,
                       CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen)
{
    if (!g_ctx.initialized) {
        return CKR_FUNCTION_NOT_INITIALIZED;
    }
    
    hsm_session_t *sess = find_session(hSession);
    if (!sess) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if (!pRandomData) {
        return CKR_ARGUMENTS_BAD;
    }
    
    CK_RV rv = get_random_bytes(pRandomData, ulRandomLen);
    printf("[hsm-lite] GenerateRandom: %lu bytes\n", ulRandomLen);
    return rv;
}