/**
 * @file hsm_common.h
 * @brief hsm-lite公共定义和内部数据结构
 * 
 * @version 1.0.0
 * @date 2026-04-15
 */

#ifndef HSM_COMMON_H
#define HSM_COMMON_H

#include "hsm_types.h"
#include <pthread.h>
#include <stdbool.h>

/* ============================================================
 * 内部数据结构
 * ============================================================ */

/* Token对象（内部表示） */
typedef struct hsm_object {
    CK_OBJECT_HANDLE     handle;
    CK_OBJECT_CLASS      class;
    CK_KEY_TYPE          key_type;
    CK_BBOOL             is_token;
    CK_BBOOL             is_private;
    CK_BBOOL             is_sensitive;
    CK_BBOOL             is_extractable;
    CK_BBOOL             can_sign;
    CK_BBOOL             can_verify;
    CK_BBOOL             can_encrypt;
    CK_BBOOL             can_decrypt;
    
    /* 密钥数据 */
    CK_BYTE             *key_data;
    CK_ULONG             key_data_len;
    
    /* RSA密钥参数 */
    CK_BYTE             *modulus;
    CK_ULONG             modulus_len;
    CK_ULONG             modulus_bits;
    CK_BYTE             *public_exponent;
    CK_ULONG             public_exponent_len;
    CK_BYTE             *private_exponent;
    CK_ULONG             private_exponent_len;
    
    /* EC密钥参数 */
    CK_BYTE             *ec_params;
    CK_ULONG             ec_params_len;
    CK_BYTE             *ec_point;
    CK_ULONG             ec_point_len;
    
    /* 属性标签 */
    CK_CHAR              label[32];
    CK_BYTE              id[32];
    CK_ULONG             id_len;
    
    bool                 in_use;
} hsm_object_t;

/* Session对象 */
typedef struct hsm_session {
    CK_SESSION_HANDLE    handle;
    CK_SLOT_ID           slot_id;
    CK_STATE             state;
    CK_FLAGS             flags;
    CK_BBOOL             is_rw;
    
    /* 操作状态 */
    CK_MECHANISM_TYPE    active_mechanism;
    CK_OBJECT_HANDLE     active_key;
    CK_BBOOL             operation_active;
    
    /* 查找操作 */
    CK_ATTRIBUTE        *find_template;
    CK_ULONG             find_template_count;
    CK_ULONG             find_index;
    CK_BBOOL             find_active;
    
    bool                 in_use;
} hsm_session_t;

/* Slot对象 */
typedef struct hsm_slot {
    CK_SLOT_ID           slot_id;
    CK_BBOOL             token_present;
    CK_SLOT_INFO         info;
} hsm_slot_t;

/* Token对象 */
typedef struct hsm_token {
    CK_SLOT_ID           slot_id;
    CK_TOKEN_INFO        info;
    CK_BBOOL             initialized;
    CK_BBOOL             user_pin_set;
    CK_BBOOL             so_pin_set;
    
    /* PIN状态 */
    CK_ULONG             user_pin_count;
    CK_ULONG             so_pin_count;
    CK_BBOOL             user_pin_locked;
    CK_BBOOL             so_pin_locked;
    
    /* 当前登录状态 */
    CK_USER_TYPE         login_type;
    CK_BBOOL             is_logged_in;
    
    /* 对象存储 */
    hsm_object_t         objects[HSM_MAX_OBJECTS];
    CK_ULONG             object_count;
    CK_OBJECT_HANDLE     next_object_handle;
} hsm_token_t;

/* 全局上下文 */
typedef struct hsm_context {
    CK_BBOOL             initialized;
    CK_INFO              info;
    
    /* Slot和Token */
    hsm_slot_t           slots[HSM_MAX_SLOTS];
    hsm_token_t          tokens[HSM_MAX_SLOTS];
    CK_ULONG             slot_count;
    
    /* Session管理 */
    hsm_session_t        sessions[HSM_MAX_SESSIONS];
    CK_ULONG             session_count;
    CK_SESSION_HANDLE    next_session_handle;
    
    /* 线程安全 */
    pthread_mutex_t      mutex;
    
    /* 存储路径 */
    char                 storage_path[256];
} hsm_context_t;

/* ============================================================
 * 操作类型枚举
 * ============================================================ */

typedef enum {
    HSM_OP_NONE          = 0,
    HSM_OP_ENCRYPT       = 1,
    HSM_OP_DECRYPT       = 2,
    HSM_OP_SIGN          = 3,
    HSM_OP_VERIFY        = 4,
    HSM_OP_DIGEST        = 5,
} hsm_operation_t;

/* ============================================================
 * 错误消息
 * ============================================================ */

static const char *hsm_error_messages[] = {
    "OK",
    "Cancelled",
    "Host memory error",
    "Invalid slot ID",
    "General error",
    "Function failed",
    "Invalid arguments",
    "Function not supported",
    "Function not initialized",
    "Operation not initialized",
    "Session handle invalid",
    "Session closed",
    "Session read only",
    "Object handle invalid",
    "Key handle invalid",
    "Key type inconsistent",
    "Key size range error",
    "PIN invalid",
    "PIN length range error",
    "PIN locked",
    "User already logged in",
    "User not logged in",
    "User PIN not initialized",
    "User type invalid",
    "Attribute type invalid",
    "Attribute value invalid",
    "Attribute sensitive",
    "Attribute read only",
    "Data invalid",
    "Data length range error",
    "Mechanism invalid",
    "Mechanism parameter invalid",
    "Token not present",
    "Token write protected",
    "Encrypted data invalid",
    "Signature invalid",
    "Buffer too small",
};

/* ============================================================
 * 辅助宏
 * ============================================================ */

#define HSM_CHECK_INIT(ctx) \
    do { \
        if (!(ctx)->initialized) { \
            return CKR_FUNCTION_NOT_INITIALIZED; \
        } \
    } while(0)

#define HSM_CHECK_SESSION(ctx, hSession, session) \
    do { \
        if (hSession >= HSM_MAX_SESSIONS || !(ctx)->sessions[hSession].in_use) { \
            return CKR_SESSION_HANDLE_INVALID; \
        } \
        (session) = &(ctx)->sessions[hSession]; \
    } while(0)

#define HSM_CHECK_OBJECT(ctx, hObject, obj) \
    do { \
        hsm_token_t *token = &(ctx)->tokens[session->slot_id]; \
        if (hObject >= HSM_MAX_OBJECTS || !token->objects[hObject].in_use) { \
            return CKR_OBJECT_HANDLE_INVALID; \
        } \
        (obj) = &token->objects[hObject]; \
    } while(0)

#define HSM_CHECK_LOGIN(ctx, session) \
    do { \
        hsm_token_t *token = &(ctx)->tokens[session->slot_id]; \
        if (!token->is_logged_in && token->info.flags & CKF_LOGIN_REQUIRED) { \
            return CKR_USER_NOT_LOGGED_IN; \
        } \
    } while(0)

#define HSM_MUTEX_LOCK(ctx) \
    pthread_mutex_lock(&(ctx)->mutex)

#define HSM_MUTEX_UNLOCK(ctx) \
    pthread_mutex_unlock(&(ctx)->mutex)

/* ============================================================
 * 外部函数声明
 * ============================================================ */

/* Token管理 */
CK_RV hsm_token_init(hsm_context_t *ctx, CK_SLOT_ID slot_id);
CK_RV hsm_token_load(hsm_context_t *ctx, CK_SLOT_ID slot_id);
CK_RV hsm_token_save(hsm_context_t *ctx, CK_SLOT_ID slot_id);

/* Session管理 */
CK_RV hsm_session_create(hsm_context_t *ctx, CK_SLOT_ID slot_id, 
                         CK_FLAGS flags, CK_SESSION_HANDLE_PTR phSession);
CK_RV hsm_session_destroy(hsm_context_t *ctx, CK_SESSION_HANDLE hSession);
CK_RV hsm_session_find(hsm_context_t *ctx, CK_SESSION_HANDLE hSession,
                       hsm_session_t **session);

/* Object管理 */
CK_RV hsm_object_create(hsm_context_t *ctx, hsm_session_t *session,
                        CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                        CK_OBJECT_HANDLE_PTR phObject);
CK_RV hsm_object_destroy(hsm_context_t *ctx, hsm_session_t *session,
                         CK_OBJECT_HANDLE hObject);
CK_RV hsm_object_find(hsm_context_t *ctx, hsm_session_t *session,
                      CK_OBJECT_HANDLE hObject, hsm_object_t **obj);
CK_RV hsm_object_get_attribute(hsm_object_t *obj, CK_ATTRIBUTE_PTR pTemplate);
CK_RV hsm_object_set_attribute(hsm_object_t *obj, CK_ATTRIBUTE_PTR pTemplate);

/* 密码运算 */
CK_RV hsm_crypto_generate_key(hsm_context_t *ctx, hsm_session_t *session,
                              CK_MECHANISM_PTR pMechanism,
                              CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                              CK_OBJECT_HANDLE_PTR phKey);
CK_RV hsm_crypto_generate_key_pair(hsm_context_t *ctx, hsm_session_t *session,
                                   CK_MECHANISM_PTR pMechanism,
                                   CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                   CK_ULONG ulPublicKeyAttributeCount,
                                   CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                   CK_ULONG ulPrivateKeyAttributeCount,
                                   CK_OBJECT_HANDLE_PTR phPublicKey,
                                   CK_OBJECT_HANDLE_PTR phPrivateKey);
CK_RV hsm_crypto_encrypt(hsm_context_t *ctx, hsm_session_t *session,
                         CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                         CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
CK_RV hsm_crypto_decrypt(hsm_context_t *ctx, hsm_session_t *session,
                         CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
                         CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
CK_RV hsm_crypto_sign(hsm_context_t *ctx, hsm_session_t *session,
                      CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                      CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
CK_RV hsm_crypto_verify(hsm_context_t *ctx, hsm_session_t *session,
                        CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                        CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
CK_RV hsm_crypto_digest(hsm_context_t *ctx, hsm_session_t *session,
                        CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                        CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
CK_RV hsm_crypto_random(hsm_context_t *ctx, CK_BYTE_PTR pRandomData,
                        CK_ULONG ulRandomLen);

/* 工具函数 */
CK_RV hsm_template_find_attribute(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                                  CK_ATTRIBUTE_TYPE type, CK_VOID_PTR *ppValue,
                                  CK_ULONG_PTR pulValueLen);
CK_RV hsm_template_copy_value(CK_VOID_PTR pDest, CK_ULONG ulDestLen,
                              CK_VOID_PTR pSrc, CK_ULONG ulSrcLen);
CK_RV hsm_validate_pin(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);

#endif /* HSM_COMMON_H */