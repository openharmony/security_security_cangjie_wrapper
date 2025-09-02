/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ohos_app_cangjie_entry

internal import std.unittest.*
import std.unittest.testmacro.*
internal import kit.UniversalKeystoreKit.*
import std.unittest.testmacro.*
import std.unittest.*
import std.unittest.common.*
import std.unittest.testmacro.*
import ohos.base.*

@Test
class Test_SecurityHuks_Aes {
    // aes cbc + pkcs7
    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_encrypt_decrypt_cbc_pkcs7() {
        // ref: https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/security/UniversalKeystoreKit/huks-encryption-decryption-ndk.md
        // ref: https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/security/UniversalKeystoreKit/huks-encryption-decryption-arkts.md
        let keyAlias = "test_encrypt_decrypt_cbc_pkcs711111"
        clean(keyAlias)

        try {
            let plainText = "123456"
            let iv = "1122334455667788"
            let options = HuksOptions(
                properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_AES),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_AES_KEY_SIZE_128),
                    HuksParam(
                        HuksTag.HuksTagPurpose,
                       // HuksParamValue.Uint32Value(1 | 2)
                        HuksParamValue.Uint32Value(1 | 2)
                    ),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_PKCS7),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CBC),
                    HuksParam(HuksTag.HuksTagIv, HuksParamValue.BytesValue(iv.toArray()))
                ],
                inData: Bytes()
            )
            let encOptions = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_AES),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_AES_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_PKCS7),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CBC),
                    HuksParam(HuksTag.HuksTagIv, HuksParamValue.BytesValue(iv.toArray()))
                ],
                inData: plainText.toArray()
            )

            generateKeyItem(keyAlias, options)
            let bytes: Array<UInt8> = []
            // encrypt
            let handle1 = initSession(keyAlias, encOptions).handle
            let cipherData = finishSession(handle1, encOptions, token: bytes)

            let decOptions = HuksOptions(
                properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_AES),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_AES_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_PKCS7),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CBC),
                    HuksParam(HuksTag.HuksTagIv, HuksParamValue.BytesValue(iv.toArray()))
                ],
                inData: cipherData.getOrThrow()
            )

            // decrypt
            let handle2 = initSession(keyAlias, decOptions).handle
            let decData = finishSession(handle2, decOptions,token: bytes)
            let dec = String.fromUtf8(decData.getOrThrow())

            @Expect(plainText == dec)
             abortSession(handle1, encOptions)
            abortSession(handle2, decOptions)
        } finally {
            clean(keyAlias)
        }
    }

     // aes cbc + nopadding
    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_encrypt_decrypt_cbc_nopadding() {
        // ref: https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/security/UniversalKeystoreKit/huks-encryption-decryption-ndk.md
        // ref: https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/security/UniversalKeystoreKit/huks-encryption-decryption-arkts.md
        let keyAlias = "test_encrypt_decrypt_cbc_nopadding"
        clean(keyAlias)

        try {
            let plainText = "1234567812345678"
            let iv = "1122334455667788"
            let options = HuksOptions(
                properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_AES),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_AES_KEY_SIZE_128),
                    HuksParam(
                        HuksTag.HuksTagPurpose,
                        //HuksParamValue.Uint32Value(1 | 2)
                         HuksParamValue.Uint32Value(1 | 2)
                    ),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CBC),
                    HuksParam(HuksTag.HuksTagIv, HuksParamValue.BytesValue(iv.toArray()))
                ],
                inData: Bytes()
            )
            let encOptions = HuksOptions(
                 properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_AES),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_AES_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CBC),
                    HuksParam(HuksTag.HuksTagIv, HuksParamValue.BytesValue(iv.toArray()))
                ],
                inData: plainText.toArray()
            )

            generateKeyItem(keyAlias, options)
             let bytes: Array<UInt8> = []
            // encrypt
            let handle1 = initSession(keyAlias, encOptions).handle
            let cipherData = finishSession(handle1, encOptions, token: bytes)

            let decOptions = HuksOptions(
                properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_AES),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_AES_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CBC),
                    HuksParam(HuksTag.HuksTagIv, HuksParamValue.BytesValue(iv.toArray()))
                ],
                inData: cipherData.getOrThrow()
            )

            // decrypt
            let handle2 = initSession(keyAlias, decOptions).handle
            let decData = finishSession(handle2, decOptions, token: bytes)
            let dec = String.fromUtf8(decData.getOrThrow())

            @Expect(plainText == dec)
             abortSession(handle1, encOptions)
            abortSession(handle2, decOptions)
        } finally {
            clean(keyAlias)
        }
    }

    // aes ctr + nopadding
    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_encrypt_decrypt_ctr_nopadding() {
        // ref: https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/security/UniversalKeystoreKit/huks-encryption-decryption-ndk.md
        // ref: https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/security/UniversalKeystoreKit/huks-encryption-decryption-arkts.md
        let keyAlias = "test_encrypt_decrypt_ctr_nopadding"
        clean(keyAlias)

        try {
            let plainText = "1234567812345678"
            let iv = "1122334455667788"
            let options = HuksOptions(
                properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_AES),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_AES_KEY_SIZE_128),
                    HuksParam(
                        HuksTag.HuksTagPurpose,
                        HuksParamValue.Uint32Value(1 | 2)
                    ),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CTR),
                    HuksParam(HuksTag.HuksTagIv, HuksParamValue.BytesValue(iv.toArray()))
                ],
                 inData: Bytes()
            )
            let encOptions = HuksOptions(
                properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_AES),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_AES_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CTR),
                    HuksParam(HuksTag.HuksTagIv, HuksParamValue.BytesValue(iv.toArray()))
                ],
                inData: plainText.toArray()
            )

            generateKeyItem(keyAlias, options)
             let bytes: Array<UInt8> = []
            // encrypt
            let handle1 = initSession(keyAlias, encOptions).handle
            let cipherData = finishSession(handle1, encOptions, token: bytes)

            let decOptions = HuksOptions(
                properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_AES),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_AES_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CTR),
                    HuksParam(HuksTag.HuksTagIv, HuksParamValue.BytesValue(iv.toArray()))
                ],
                inData: cipherData.getOrThrow()
            )

            // decrypt
            let handle2 = initSession(keyAlias, decOptions).handle
            let decData = finishSession(handle2, decOptions,token: bytes)
            let dec = String.fromUtf8(decData.getOrThrow())

            @Expect(plainText == dec)

            abortSession(handle1, encOptions)
            abortSession(handle2, decOptions)
        } finally {
            clean(keyAlias)
        }
    }

     // aes ecb + pkcs7
    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_encrypt_decrypt_ecb_pkcs7() {
        // ref: https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/security/UniversalKeystoreKit/huks-encryption-decryption-ndk.md
        // ref: https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/security/UniversalKeystoreKit/huks-encryption-decryption-arkts.md
        let keyAlias = "test_encrypt_decrypt_ecb_pkcs7"
        clean(keyAlias)

        try {
            let plainText = "123456"
            let options = HuksOptions(
                properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_AES),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_AES_KEY_SIZE_128),
                    HuksParam(
                        HuksTag.HuksTagPurpose,
                        HuksParamValue.Uint32Value(1 | 2)
                    ),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_PKCS7),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_ECB)
                ],
               inData: Bytes()
            )
            let encOptions = HuksOptions(
                  properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_AES),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_AES_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_PKCS7),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_ECB)
                ],
                inData: plainText.toArray()
            )

            generateKeyItem(keyAlias, options)

            // encrypt
            let handle1 = initSession(keyAlias, encOptions).handle
            let bytes: Array<UInt8> = []
            let cipherData = finishSession(handle1, encOptions,token: bytes)

            let decOptions = HuksOptions(
                properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_AES),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_AES_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_PKCS7),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_ECB)
                ],
                inData: cipherData.getOrThrow()
            )

            // decrypt
            let handle2 = initSession(keyAlias, decOptions).handle
            let decData = finishSession(handle2, decOptions, token: bytes)
            let dec = String.fromUtf8(decData.getOrThrow())

            // @Expect(plainText == dec)
            // 不支持 ecb + pkcs7
            @Expect(false)
             abortSession(handle1, encOptions)
            abortSession(handle2, decOptions)
        } catch (e: BusinessException) {
            @Expect(e.code, 401)
        } finally {
            clean(keyAlias)
        }
    }

    // aes ecb + nopadding
    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_encrypt_decrypt_ecb_nopadding() {
        // ref: https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/security/UniversalKeystoreKit/huks-encryption-decryption-ndk.md
        // ref: https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/security/UniversalKeystoreKit/huks-encryption-decryption-arkts.md
        let keyAlias = "test_encrypt_decrypt_ecb_nopadding"
        clean(keyAlias)

        try {
            let plainText = "1234567812345678"
            let options = HuksOptions(
                properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_AES),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_AES_KEY_SIZE_128),
                    HuksParam(
                        HuksTag.HuksTagPurpose,
                        HuksParamValue.Uint32Value(1 | 2)
                    ),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_ECB)
                ],
                inData: Bytes()
            )
            let encOptions = HuksOptions(
                properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_AES),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_AES_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_ECB)
                ],
                inData: plainText.toArray()
            )

            generateKeyItem(keyAlias, options)
            let bytes: Array<UInt8> = []

            // encrypt
            let handle1 = initSession(keyAlias, encOptions).handle
            let cipherData = finishSession(handle1, encOptions, token: bytes)

            let decOptions = HuksOptions(
                properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_AES),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_AES_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_ECB)
                ],
                inData: cipherData.getOrThrow()
            )

            // decrypt
            let handle2 = initSession(keyAlias, decOptions).handle
            let decData = finishSession(handle2, decOptions, token: bytes)
            let dec = String.fromUtf8(decData.getOrThrow())

            // @Expect(plainText == dec)
            // 不支持 ecb + nopadding
            @Expect(false)
            abortSession(handle1, encOptions)
            abortSession(handle2, decOptions)
        } catch (e: BusinessException) {
            @Expect(e.code, 401)
        } finally {
            clean(keyAlias)
        }
    }

    // aes gcm + nopadding
    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_encrypt_decrypt_gcm_nopadding() {
        // ref: https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/security/UniversalKeystoreKit/huks-encryption-decryption-ndk.md
        // ref: https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/security/UniversalKeystoreKit/huks-encryption-decryption-arkts.md
        let keyAlias = "test_encrypt_decrypt_gcm_nopadding"
        clean(keyAlias)

        try {
            let plainText = "1234567812345678"
            let AEAD = "1234567890123456"
            let Nonce = "123456789012"
            let AAD = "1234567890123456"
            let options = HuksOptions(
                properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_AES),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_AES_KEY_SIZE_128),
                    HuksParam(
                        HuksTag.HuksTagPurpose,
                        HuksParamValue.Uint32Value(1 | 2)
                    ),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_GCM)
                ],
               inData: Bytes()
            )
            let encOptions = HuksOptions(
               properties:  [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_AES),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_AES_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_GCM),
                    HuksParam(HuksTag.HuksTagNonce, HuksParamValue.BytesValue(Nonce.toArray())),
                    HuksParam(HuksTag.HuksTagAssociatedData, HuksParamValue.BytesValue(AAD.toArray())),
                    HuksParam(HuksTag.HuksTagAeTag, HuksParamValue.BytesValue(AEAD.toArray()))
                ],
                inData: plainText.toArray()
            )

            generateKeyItem(keyAlias, options)
            let bytes: Array<UInt8> = []

            // encrypt
            let handle1 = initSession(keyAlias, encOptions).handle
            let cipherData = finishSession(handle1, encOptions, token: bytes).getOrThrow()

            let decOptions = HuksOptions(
                properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_AES),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_AES_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_GCM),
                    HuksParam(HuksTag.HuksTagNonce, HuksParamValue.BytesValue(Nonce.toArray())),
                    HuksParam(HuksTag.HuksTagAssociatedData, HuksParamValue.BytesValue(AAD.toArray())),
                    // aead
                    HuksParam(
                        HuksTag.HuksTagAeTag,
                        HuksParamValue.BytesValue(cipherData.slice(cipherData.size - 16, 16))
                    )
                ],
               inData: cipherData.slice(0, cipherData.size - 16)
            )

            // decrypt
            let handle2 = initSession(keyAlias, decOptions).handle
            let decData = finishSession(handle2, decOptions, token: bytes)
            let dec = String.fromUtf8(decData.getOrThrow())

            @Expect(plainText == dec)

            abortSession(handle1, encOptions)
            abortSession(handle2, decOptions)
        } finally {
            clean(keyAlias)
        }
    }

}
