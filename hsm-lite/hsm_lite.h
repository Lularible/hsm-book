/**
 * @file hsm_lite.h
 * @brief hsm-lite公共定义（精简版）
 * 
 * 教学级轻量HSM实现，仅实现PKCS#11核心功能：
 * - 初始化与会话管理
 * - AES密钥生成
 * - AES加密/解密
 * - 随机数生成
 * 
 * @version 1.0.0
 * @date 2026-04-15
 */

#ifndef HSM_LITE_H
#define HSM_LITE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ============================================================
 * 版本信息
 * ============================================================ */

#define HSM_LITE_VERSION        "1.0.0"

/* ============================================================
 * 基础类型（按依赖顺序定义）
 * ============================================================ */

typedef unsigned long       CK_ULONG;
typedef unsigned char       CK_BYTE;
typedef unsigned char       CK_BBOOL;
typedef CK_ULONG            CK_FLAGS;
typedef void               *CK_VOID_PTR;
typedef CK_BYTE            *CK_BYTE_PTR;
typedef CK_ULONG           *CK_ULONG_PTR;

#define CK_TRUE              1
#define CK_FALSE             0

/* ============================================================
 * Handle类型
 * ============================================================ */

typedef CK_ULONG            CK_SLOT_ID;
typedef CK_ULONG            CK_SESSION_HANDLE;
typedef CK_ULONG            CK_OBJECT_HANDLE;

typedef CK_SLOT_ID         *CK_SLOT_ID_PTR;
typedef CK_SESSION_HANDLE  *CK_SESSION_HANDLE_PTR;
typedef CK_OBJECT_HANDLE   *CK_OBJECT_HANDLE_PTR;

/* ============================================================
 * 返回值
 * ============================================================ */

typedef CK_ULONG            CK_RV;

#define CKR_OK                           0
#define CKR_HOST_MEMORY                  2
#define CKR_SLOT_ID_INVALID              3
#define CKR_GENERAL_ERROR                5
#define CKR_FUNCTION_FAILED              6
#define CKR_ARGUMENTS_BAD                7
#define CKR_FUNCTION_NOT_INITIALIZED     13
#define CKR_SESSION_HANDLE_INVALID       48
#define CKR_SESSION_READ_ONLY            51
#define CKR_OBJECT_HANDLE_INVALID        66
#define CKR_KEY_HANDLE_INVALID           80
#define CKR_KEY_TYPE_INCONSISTENT        83
#define CKR_PIN_INVALID                  160
#define CKR_USER_NOT_LOGGED_IN           257
#define CKR_ATTRIBUTE_TYPE_INVALID       18
#define CKR_ATTRIBUTE_VALUE_INVALID      19
#define CKR_MECHANISM_INVALID            112
#define CKR_DATA_LEN_RANGE               33

#define CK_UNAVAILABLE_INFORMATION        (~0UL)

/* ============================================================
 * 用户类型
 * ============================================================ */

typedef CK_ULONG            CK_USER_TYPE;

#define CKU_SO                           0
#define CKU_USER                         1

/* ============================================================
 * 对象与密钥类型
 * ============================================================ */

typedef CK_ULONG            CK_OBJECT_CLASS;
typedef CK_ULONG            CK_KEY_TYPE;

#define CKO_SECRET_KEY                   4
#define CKK_AES                          31

/* ============================================================
 * 机制类型
 * ============================================================ */

typedef CK_ULONG            CK_MECHANISM_TYPE;

#define CKM_AES_KEY_GEN                  0x00001080
#define CKM_AES_ECB                      0x00001081
#define CKM_AES_CBC                      0x00001082

/* ============================================================
 * 属性类型
 * ============================================================ */

typedef CK_ULONG            CK_ATTRIBUTE_TYPE;

#define CKA_CLASS                        0
#define CKA_KEY_TYPE                     256
#define CKA_VALUE_LEN                    277
#define CKA_TOKEN                        1
#define CKA_PRIVATE                      2
#define CKA_LABEL                        3
#define CKA_ENCRYPT                      294
#define CKA_DECRYPT                      295
#define CKA_VALUE                        17

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
 * Session标志
 * ============================================================ */

#define CKF_SERIAL_SESSION                4
#define CKF_RW_SESSION                    2

/* ============================================================
 * 内部常量
 * ============================================================ */

#define HSM_MAX_SESSIONS                   8
#define HSM_MAX_OBJECTS                    16
#define HSM_AES_KEY_SIZE                   32
#define HSM_AES_BLOCK_SIZE                 16

/* ============================================================
 * PKCS#11核心函数声明
 * ============================================================ */

CK_RV C_Initialize(CK_VOID_PTR pInitArgs);
CK_RV C_Finalize(CK_VOID_PTR pReserved);

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
                    CK_ULONG_PTR pulCount);

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
                    CK_SESSION_HANDLE_PTR phSession);
CK_RV C_CloseSession(CK_SESSION_HANDLE hSession);

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession,
                     CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                     CK_OBJECT_HANDLE_PTR phObject);
CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession,
                      CK_OBJECT_HANDLE hObject);
CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession,
                          CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism,
                    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                    CK_OBJECT_HANDLE_PTR phKey);

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV C_Encrypt(CK_SESSION_HANDLE hSession,
                CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                CK_BYTE_PTR pEncrypted, CK_ULONG_PTR pulEncryptedLen);

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV C_Decrypt(CK_SESSION_HANDLE hSession,
                CK_BYTE_PTR pEncrypted, CK_ULONG ulEncryptedLen,
                CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession,
                       CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen);

#endif /* HSM_LITE_H */