/**
 * @file hsm_types.h
 * @brief PKCS#11类型定义（教学简化版）
 * 
 * 基于PKCS#11 v3.1规范简化，实现核心类型定义
 * 注意：本文件为教学简化版本，仅定义常用类型和常量
 * 
 * @version 1.0.0
 * @date 2026-04-15
 */

#ifndef HSM_TYPES_H
#define HSM_TYPES_H

#include <stdint.h>
#include <stddef.h>

/* ============================================================
 * 版本信息
 * ============================================================ */

#define HSM_LITE_VERSION        "1.0.0"
#define HSM_LITE_VERSION_MAJOR  1
#define HSM_LITE_VERSION_MINOR  0
#define HSM_LITE_VERSION_PATCH  0

/* ============================================================
 * 基础类型定义（按依赖顺序）
 * ============================================================ */

typedef unsigned long       CK_ULONG;
typedef long                CK_LONG;
typedef unsigned char       CK_BYTE;
typedef char                CK_CHAR;
typedef unsigned char       CK_BBOOL;
typedef uint8_t             CK_UTF8CHAR;

typedef CK_ULONG            CK_FLAGS;
typedef CK_BYTE            *CK_BYTE_PTR;
typedef CK_ULONG           *CK_ULONG_PTR;
typedef void               *CK_VOID_PTR;
typedef CK_VOID_PTR        *CK_VOID_PTR_PTR;
typedef CK_UTF8CHAR        *CK_UTF8CHAR_PTR;

/* 布尔值 */
#define CK_TRUE              1
#define CK_FALSE             0

/* ============================================================
 * 返回值类型
 * ============================================================ */

typedef CK_ULONG            CK_RV;

/* 成功 */
#define CKR_OK                           0x00000000UL

/* 基础错误 */
#define CKR_CANCELLED                    0x00000001UL
#define CKR_HOST_MEMORY                  0x00000002UL
#define CKR_SLOT_ID_INVALID              0x00000003UL
#define CKR_GENERAL_ERROR                0x00000005UL
#define CKR_FUNCTION_FAILED              0x00000006UL
#define CKR_ARGUMENTS_BAD                0x00000007UL
#define CKR_FUNCTION_NOT_SUPPORTED       0x0000000CUL
#define CKR_FUNCTION_NOT_INITIALIZED     0x0000000DUL
#define CKR_OPERATION_NOT_INITIALIZED    0x0000000EUL

/* 会话错误 */
#define CKR_SESSION_HANDLE_INVALID       0x00000030UL
#define CKR_SESSION_CLOSED               0x00000031UL
#define CKR_SESSION_READ_ONLY            0x00000033UL

/* 对象错误 */
#define CKR_OBJECT_HANDLE_INVALID        0x00000042UL

/* 密钥错误 */
#define CKR_KEY_HANDLE_INVALID           0x00000050UL
#define CKR_KEY_TYPE_INCONSISTENT        0x00000053UL
#define CKR_KEY_SIZE_RANGE               0x00000060UL

/* 认证错误 */
#define CKR_PIN_INVALID                  0x000000A0UL
#define CKR_PIN_LEN_RANGE                0x000000A2UL
#define CKR_PIN_LOCKED                   0x000000A4UL
#define CKR_USER_ALREADY_LOGGED_IN       0x00000100UL
#define CKR_USER_NOT_LOGGED_IN           0x00000101UL
#define CKR_USER_PIN_NOT_INITIALIZED     0x00000102UL
#define CKR_USER_TYPE_INVALID            0x00000103UL

/* 属性错误 */
#define CKR_ATTRIBUTE_TYPE_INVALID       0x00000012UL
#define CKR_ATTRIBUTE_VALUE_INVALID      0x00000013UL
#define CKR_ATTRIBUTE_SENSITIVE          0x00000014UL
#define CKR_ATTRIBUTE_READ_ONLY          0x00000015UL

/* 数据错误 */
#define CKR_DATA_INVALID                 0x00000020UL
#define CKR_DATA_LEN_RANGE               0x00000021UL

/* 机制错误 */
#define CKR_MECHANISM_INVALID            0x00000070UL
#define CKR_MECHANISM_PARAM_INVALID      0x00000071UL

/* Token错误 */
#define CKR_TOKEN_NOT_PRESENT            0x000000E0UL
#define CKR_TOKEN_WRITE_PROTECTED        0x000000E2UL

/* 操作错误 */
#define CKR_ENCRYPTED_DATA_INVALID       0x00000040UL
#define CKR_ENCRYPTED_DATA_LEN_RANGE     0x00000041UL
#define CKR_SIGNATURE_INVALID            0x000000C0UL
#define CKR_SIGNATURE_LEN_RANGE          0x000000C1UL
#define CKR_BUFFER_TOO_SMALL             0x00000150UL

/* ============================================================
 * 用户类型
 * ============================================================ */

typedef CK_ULONG            CK_USER_TYPE;

#define CKU_SO                           0UL
#define CKU_USER                         1UL
#define CKU_CONTEXT_SPECIFIC             2UL

/* ============================================================
 * 对象类型
 * ============================================================ */

typedef CK_ULONG            CK_OBJECT_CLASS;
typedef CK_OBJECT_CLASS    *CK_OBJECT_CLASS_PTR;

#define CKO_CERTIFICATE                  0x00000001UL
#define CKO_PUBLIC_KEY                   0x00000002UL
#define CKO_PRIVATE_KEY                  0x00000003UL
#define CKO_SECRET_KEY                   0x00000004UL
#define CKO_DATA                         0x00000008UL

/* ============================================================
 * 密钥类型
 * ============================================================ */

typedef CK_ULONG            CK_KEY_TYPE;

#define CKK_RSA                          0x00000000UL
#define CKK_EC                           0x00000003UL
#define CKK_AES                          0x0000001FUL
#define CKK_DES3                         0x00000022UL
#define CKK_GENERIC_SECRET               0x00000030UL

/* ============================================================
 * 机制类型
 * ============================================================ */

typedef CK_ULONG            CK_MECHANISM_TYPE;

/* RSA机制 */
#define CKM_RSA_PKCS_KEY_PAIR_GEN        0x00000000UL
#define CKM_RSA_PKCS                     0x00000001UL
#define CKM_RSA_PKCS_PSS                 0x0000000DUL
#define CKM_RSA_PKCS_OAEP                0x00000009UL

/* AES机制 */
#define CKM_AES_KEY_GEN                  0x00001080UL
#define CKM_AES_ECB                      0x00001081UL
#define CKM_AES_CBC                      0x00001082UL
#define CKM_AES_GCM                      0x00001087UL

/* EC机制 */
#define CKM_EC_KEY_PAIR_GEN              0x00001040UL
#define CKM_ECDSA                        0x00001041UL
#define CKM_ECDSA_SHA256                 0x00001048UL
#define CKM_ECDH1_DERIVE                 0x00001050UL

/* SHA机制 */
#define CKM_SHA256                       0x00000250UL
#define CKM_SHA256_HMAC                  0x00000251UL

/* ============================================================
 * 属性类型
 * ============================================================ */

typedef CK_ULONG            CK_ATTRIBUTE_TYPE;

/* 通用属性 */
#define CKA_CLASS                        0x00000000UL
#define CKA_TOKEN                        0x00000001UL
#define CKA_PRIVATE                      0x00000002UL
#define CKA_LABEL                        0x00000003UL
#define CKA_MODIFIABLE                   0x00000070UL
#define CKA_DESTROYABLE                  0x00000072UL

/* 密钥通用属性 */
#define CKA_KEY_TYPE                     0x00000100UL
#define CKA_ID                           0x00000102UL
#define CKA_DERIVE                       0x00000112UL
#define CKA_LOCAL                        0x00000113UL

/* 密钥安全属性 */
#define CKA_SENSITIVE                    0x00000103UL
#define CKA_EXTRACTABLE                  0x00000104UL
#define CKA_ALWAYS_SENSITIVE             0x00000105UL
#define CKA_NEVER_EXTRACTABLE            0x00000106UL
#define CKA_SIGN                         0x00000118UL
#define CKA_VERIFY                       0x00000120UL
#define CKA_ENCRYPT                      0x00000126UL
#define CKA_DECRYPT                      0x00000127UL

/* RSA属性 */
#define CKA_MODULUS                      0x0000008AUL
#define CKA_MODULUS_BITS                 0x0000008BUL
#define CKA_PUBLIC_EXPONENT              0x00000022UL
#define CKA_PRIVATE_EXPONENT             0x00000023UL

/* AES属性 */
#define CKA_VALUE_LEN                    0x00000115UL
#define CKA_VALUE                        0x00000011UL

/* EC属性 */
#define CKA_EC_PARAMS                    0x00000180UL
#define CKA_EC_POINT                     0x00000181UL

/* ============================================================
 * 属性结构
 * ============================================================ */

typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE    type;
    CK_VOID_PTR          pValue;
    CK_ULONG             ulValueLen;
} CK_ATTRIBUTE;

typedef CK_ATTRIBUTE      *CK_ATTRIBUTE_PTR;

/* ============================================================
 * 机制结构
 * ============================================================ */

typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE    mechanism;
    CK_VOID_PTR          pParameter;
    CK_ULONG             ulParameterLen;
} CK_MECHANISM;

typedef CK_MECHANISM      *CK_MECHANISM_PTR;

/* ============================================================
 * Handle类型
 * ============================================================ */

typedef CK_ULONG            CK_SLOT_ID;
typedef CK_SLOT_ID         *CK_SLOT_ID_PTR;
typedef CK_ULONG            CK_SESSION_HANDLE;
typedef CK_SESSION_HANDLE  *CK_SESSION_HANDLE_PTR;
typedef CK_ULONG            CK_OBJECT_HANDLE;
typedef CK_OBJECT_HANDLE   *CK_OBJECT_HANDLE_PTR;

/* ============================================================
 * 版本结构
 * ============================================================ */

typedef struct CK_VERSION {
    CK_BYTE              major;
    CK_BYTE              minor;
} CK_VERSION;

typedef CK_VERSION        *CK_VERSION_PTR;

/* ============================================================
 * Slot信息结构
 * ============================================================ */

typedef struct CK_SLOT_INFO {
    CK_CHAR              slotDescription[64];
    CK_CHAR              manufacturerID[32];
    CK_FLAGS             flags;
    CK_BYTE              hardwareVersion[2];
    CK_BYTE              firmwareVersion[2];
} CK_SLOT_INFO;

typedef CK_SLOT_INFO      *CK_SLOT_INFO_PTR;

/* Slot标志 */
#define CKF_TOKEN_PRESENT                 0x00000001UL
#define CKF_REMOVABLE_DEVICE              0x00000002UL
#define CKF_HW_SLOT                       0x00000004UL

/* ============================================================
 * Token信息结构
 * ============================================================ */

typedef struct CK_TOKEN_INFO {
    CK_CHAR              label[32];
    CK_CHAR              manufacturerID[32];
    CK_CHAR              model[16];
    CK_CHAR              serialNumber[16];
    CK_FLAGS             flags;
    CK_ULONG             ulMaxSessionCount;
    CK_ULONG             ulSessionCount;
    CK_ULONG             ulMaxRwSessionCount;
    CK_ULONG             ulRwSessionCount;
    CK_ULONG             ulMaxPinLen;
    CK_ULONG             ulMinPinLen;
    CK_ULONG             ulTotalPublicMemory;
    CK_ULONG             ulFreePublicMemory;
    CK_ULONG             ulTotalPrivateMemory;
    CK_ULONG             ulFreePrivateMemory;
    CK_BYTE              hardwareVersion[2];
    CK_BYTE              firmwareVersion[2];
    CK_BYTE              utcTime[16];
} CK_TOKEN_INFO;

typedef CK_TOKEN_INFO     *CK_TOKEN_INFO_PTR;

/* Token标志 */
#define CKF_RNG                           0x00000001UL
#define CKF_WRITE_PROTECTED               0x00000002UL
#define CKF_LOGIN_REQUIRED                0x00000004UL
#define CKF_USER_PIN_INITIALIZED          0x00000008UL
#define CKF_TOKEN_INITIALIZED             0x00000400UL

/* ============================================================
 * Session状态和标志
 * ============================================================ */

typedef CK_ULONG            CK_STATE;

#define CKS_RO_PUBLIC_SESSION             0UL
#define CKS_RO_USER_FUNCTIONS             1UL
#define CKS_RW_PUBLIC_SESSION             2UL
#define CKS_RW_USER_FUNCTIONS             3UL
#define CKS_RW_SO_FUNCTIONS               4UL

#define CKF_SERIAL_SESSION                0x00000004UL
#define CKF_RW_SESSION                    0x00000002UL

typedef struct CK_SESSION_INFO {
    CK_SLOT_ID           slotID;
    CK_STATE             state;
    CK_FLAGS             flags;
    CK_ULONG             ulDeviceError;
} CK_SESSION_INFO;

typedef CK_SESSION_INFO   *CK_SESSION_INFO_PTR;

/* ============================================================
 * Notify回调类型
 * ============================================================ */

typedef CK_ULONG            CK_NOTIFICATION;

#define CKN_SURRENDER                      0UL

typedef CK_RV            (*CK_NOTIFY)(CK_SESSION_HANDLE, CK_NOTIFICATION, CK_VOID_PTR);

/* ============================================================
 * Cryptoki信息结构
 * ============================================================ */

typedef struct CK_INFO {
    CK_VERSION           cryptokiVersion;
    CK_CHAR              manufacturerID[32];
    CK_FLAGS             flags;
    CK_CHAR              libraryDescription[32];
    CK_VERSION           libraryVersion;
} CK_INFO;

typedef CK_INFO           *CK_INFO_PTR;

/* ============================================================
 * 函数列表结构（简化版）
 * ============================================================ */

typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST *CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR *CK_FUNCTION_LIST_PTR_PTR;

struct CK_FUNCTION_LIST {
    CK_VERSION           version;
    CK_RV               (*C_Initialize)(CK_VOID_PTR);
    CK_RV               (*C_Finalize)(CK_VOID_PTR);
    CK_RV               (*C_GetInfo)(CK_INFO_PTR);
    CK_RV               (*C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);
    CK_RV               (*C_GetSlotList)(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR);
    CK_RV               (*C_GetSlotInfo)(CK_SLOT_ID, CK_SLOT_INFO_PTR);
    CK_RV               (*C_GetTokenInfo)(CK_SLOT_ID, CK_TOKEN_INFO_PTR);
    CK_RV               (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR);
    CK_RV               (*C_CloseSession)(CK_SESSION_HANDLE);
    CK_RV               (*C_CloseAllSessions)(CK_SLOT_ID);
    CK_RV               (*C_GetSessionInfo)(CK_SESSION_HANDLE, CK_SESSION_INFO_PTR);
    CK_RV               (*C_Login)(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG);
    CK_RV               (*C_Logout)(CK_SESSION_HANDLE);
    CK_RV               (*C_CreateObject)(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
    CK_RV               (*C_DestroyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
    CK_RV               (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
    CK_RV               (*C_FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
    CK_RV               (*C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR);
    CK_RV               (*C_FindObjectsFinal)(CK_SESSION_HANDLE);
    CK_RV               (*C_GenerateKey)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
    CK_RV               (*C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR);
    CK_RV               (*C_EncryptInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
    CK_RV               (*C_Encrypt)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV               (*C_EncryptFinal)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV               (*C_DecryptInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
    CK_RV               (*C_Decrypt)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV               (*C_DecryptFinal)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV               (*C_DigestInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR);
    CK_RV               (*C_Digest)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV               (*C_DigestFinal)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV               (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
    CK_RV               (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV               (*C_SignFinal)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
    CK_RV               (*C_VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
    CK_RV               (*C_Verify)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG);
    CK_RV               (*C_VerifyFinal)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
    CK_RV               (*C_GenerateRandom)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
};

/* ============================================================
 * 特殊值
 * ============================================================ */

#define CK_UNAVAILABLE_INFORMATION           (~0UL)
#define CK_EFFECTIVELY_INFINITE              0UL

/* ============================================================
 * hsm-lite内部配置
 * ============================================================ */

/* 最大值配置 */
#define HSM_MAX_SLOTS                      4
#define HSM_MAX_SESSIONS                   16
#define HSM_MAX_OBJECTS                    64
#define HSM_MAX_PIN_LEN                    32
#define HSM_MIN_PIN_LEN                    4

/* Token存储路径 */
#define HSM_TOKEN_DIR                      "/tmp/hsm-lite"

/* 默认Token标签 */
#define HSM_DEFAULT_LABEL                  "hsm-lite Token"

/* EC曲线OID（简化版仅支持P-256） */
#define HSM_EC_P256_OID_SIZE               10

#endif /* HSM_TYPES_H */