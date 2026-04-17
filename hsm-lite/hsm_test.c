/**
 * @file hsm_test.c
 * @brief hsm-lite测试程序
 * 
 * @version 1.0.0
 * @date 2026-04-15
 */

#include "hsm_lite.h"
#include <stdio.h>
#include <string.h>

static void print_bytes(const char *label, CK_BYTE_PTR data, CK_ULONG len)
{
    printf("%s: ", label);
    for (CK_ULONG i = 0; i < len && i < 16; i++) {
        printf("%02x", data[i]);
    }
    if (len > 16) {
        printf("... (%lu bytes)", len);
    }
    printf("\n");
}

static int test_basic_flow(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;
    CK_SLOT_ID slots[1];
    CK_ULONG slot_count;
    
    printf("\n=== Test 1: Basic Flow ===\n\n");
    
    /* 初始化 */
    rv = C_Initialize(NULL);
    if (rv != CKR_OK) {
        printf("FAIL: C_Initialize returned %lu\n", rv);
        return -1;
    }
    printf("PASS: C_Initialize\n");
    
    /* 获取Slot列表 */
    rv = C_GetSlotList(CK_TRUE, slots, &slot_count);
    if (rv != CKR_OK || slot_count != 1) {
        printf("FAIL: C_GetSlotList returned %lu, count=%lu\n", rv, slot_count);
        return -1;
    }
    printf("PASS: C_GetSlotList (count=%lu)\n", slot_count);
    
    /* 打开Session */
    rv = C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, &hSession);
    if (rv != CKR_OK) {
        printf("FAIL: C_OpenSession returned %lu\n", rv);
        return -1;
    }
    printf("PASS: C_OpenSession (handle=%lu)\n", hSession);
    
    /* 清理 */
    rv = C_CloseSession(hSession);
    if (rv != CKR_OK) {
        printf("FAIL: C_CloseSession returned %lu\n", rv);
        return -1;
    }
    printf("PASS: C_CloseSession\n");
    
    rv = C_Finalize(NULL);
    if (rv != CKR_OK) {
        printf("FAIL: C_Finalize returned %lu\n", rv);
        return -1;
    }
    printf("PASS: C_Finalize\n");
    
    return 0;
}

static int test_key_generation(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;
    CK_OBJECT_HANDLE hKey;
    CK_MECHANISM mechanism = {CKM_AES_KEY_GEN, NULL, 0};
    CK_BYTE key_value[32];
    CK_ULONG key_len;
    
    printf("\n=== Test 2: Key Generation ===\n\n");
    
    rv = C_Initialize(NULL);
    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, &hSession);
    
    /* 生成AES密钥 */
    rv = C_GenerateKey(hSession, &mechanism, NULL, 0, &hKey);
    if (rv != CKR_OK) {
        printf("FAIL: C_GenerateKey returned %lu\n", rv);
        return -1;
    }
    printf("PASS: C_GenerateKey (handle=%lu)\n", hKey);
    
    /* 获取密钥值 */
    CK_ATTRIBUTE template[] = {
        {CKA_VALUE, key_value, sizeof(key_value)},
        {CKA_VALUE_LEN, &key_len, sizeof(key_len)}
    };
    
    rv = C_GetAttributeValue(hSession, hKey, template, 2);
    if (rv != CKR_OK) {
        printf("FAIL: C_GetAttributeValue returned %lu\n", rv);
        return -1;
    }
    print_bytes("Key value", key_value, key_len);
    printf("PASS: C_GetAttributeValue (len=%lu)\n", key_len);
    
    /* 销毁密钥 */
    rv = C_DestroyObject(hSession, hKey);
    if (rv != CKR_OK) {
        printf("FAIL: C_DestroyObject returned %lu\n", rv);
        return -1;
    }
    printf("PASS: C_DestroyObject\n");
    
    C_CloseSession(hSession);
    C_Finalize(NULL);
    
    return 0;
}

static int test_encrypt_decrypt(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;
    CK_OBJECT_HANDLE hKey;
    CK_MECHANISM key_mech = {CKM_AES_KEY_GEN, NULL, 0};
    CK_MECHANISM enc_mech = {CKM_AES_ECB, NULL, 0};
    
    CK_BYTE plaintext[32] = "Hello, hsm-lite!";
    CK_ULONG pt_len = 17;
    CK_BYTE ciphertext[32];
    CK_ULONG ct_len;
    CK_BYTE decrypted[32];
    CK_ULONG dec_len;
    
    printf("\n=== Test 3: Encrypt/Decrypt ===\n\n");
    
    rv = C_Initialize(NULL);
    rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, &hSession);
    rv = C_GenerateKey(hSession, &key_mech, NULL, 0, &hKey);
    
    print_bytes("Plaintext", plaintext, pt_len);
    
    /* 加密 */
    ct_len = sizeof(ciphertext);
    rv = C_EncryptInit(hSession, &enc_mech, hKey);
    if (rv != CKR_OK) {
        printf("FAIL: C_EncryptInit returned %lu\n", rv);
        return -1;
    }
    
    rv = C_Encrypt(hSession, plaintext, pt_len, ciphertext, &ct_len);
    if (rv != CKR_OK) {
        printf("FAIL: C_Encrypt returned %lu\n", rv);
        return -1;
    }
    print_bytes("Ciphertext", ciphertext, ct_len);
    printf("PASS: Encrypt (%lu -> %lu bytes)\n", pt_len, ct_len);
    
    /* 解密 */
    dec_len = sizeof(decrypted);
    rv = C_DecryptInit(hSession, &enc_mech, hKey);
    if (rv != CKR_OK) {
        printf("FAIL: C_DecryptInit returned %lu\n", rv);
        return -1;
    }
    
    rv = C_Decrypt(hSession, ciphertext, ct_len, decrypted, &dec_len);
    if (rv != CKR_OK) {
        printf("FAIL: C_Decrypt returned %lu\n", rv);
        return -1;
    }
    print_bytes("Decrypted", decrypted, dec_len);
    printf("PASS: Decrypt (%lu -> %lu bytes)\n", ct_len, dec_len);
    
    /* 验证 */
    if (memcmp(plaintext, decrypted, pt_len) == 0) {
        printf("PASS: Plaintext matches decrypted text\n");
    } else {
        printf("FAIL: Plaintext does NOT match decrypted text\n");
        return -1;
    }
    
    C_DestroyObject(hSession, hKey);
    C_CloseSession(hSession);
    C_Finalize(NULL);
    
    return 0;
}

static int test_random(void)
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;
    CK_BYTE random[32];
    
    printf("\n=== Test 4: Random Generation ===\n\n");
    
    rv = C_Initialize(NULL);
    rv = C_OpenSession(0, CKF_SERIAL_SESSION, &hSession);
    
    rv = C_GenerateRandom(hSession, random, sizeof(random));
    if (rv != CKR_OK) {
        printf("FAIL: C_GenerateRandom returned %lu\n", rv);
        return -1;
    }
    print_bytes("Random", random, sizeof(random));
    printf("PASS: C_GenerateRandom\n");
    
    C_CloseSession(hSession);
    C_Finalize(NULL);
    
    return 0;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    
    printf("========================================\n");
    printf("  hsm-lite Test Suite (version %s)\n", HSM_LITE_VERSION);
    printf("========================================\n");
    
    int failed = 0;
    
    failed += test_basic_flow();
    failed += test_key_generation();
    failed += test_encrypt_decrypt();
    failed += test_random();
    
    printf("\n========================================\n");
    if (failed == 0) {
        printf("  ALL TESTS PASSED\n");
    } else {
        printf("  %d TESTS FAILED\n", failed);
    }
    printf("========================================\n");
    
    return failed;
}