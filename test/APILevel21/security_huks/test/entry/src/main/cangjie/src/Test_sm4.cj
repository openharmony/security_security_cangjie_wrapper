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
class Test_SecurityHuks_SM4 {
    // sm4 cbc + pkcs7
    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_sm4_encrypt_decrypt_cbc_pkcs7() {
        let keyAlias = "test_sm4_encrypt_decrypt_cbc_pkcs7"
        try {
            let plainText = "123456"
            let iv = "0011223344556677"
            clean(keyAlias)
            let options = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(
                        HuksTag.HuksTagPurpose,
                        HuksParamValue.Uint32Value(1 | 2)
                    ),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_PKCS7),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CBC)
                ],
               inData: Bytes()
            )
            let initOptions = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_PKCS7),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CBC),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT),
                    HuksParam(HuksTag.HuksTagIv, HuksParamValue.BytesValue(iv.toArray()))
                ],
               inData: Bytes()
            )

            let finiOptions = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_PKCS7),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CBC),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT),
                    HuksParam(HuksTag.HuksTagIv, HuksParamValue.BytesValue(iv.toArray()))
                ],
                inData:  plainText.toArray()
            )

            generateKeyItem(keyAlias, options)
             let bytes: Array<UInt8> = []
            // encrypt
            let handle1 = initSession(keyAlias, initOptions).handle
            let cipherData = finishSession(handle1, finiOptions,token: bytes)

            let decInitOptions = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_PKCS7),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CBC),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT),
                    HuksParam(HuksTag.HuksTagIv, HuksParamValue.BytesValue(iv.toArray()))
                ],
               inData: Bytes()
            )
            let decFiniOptions = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_PKCS7),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CBC),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT),
                    HuksParam(HuksTag.HuksTagIv, HuksParamValue.BytesValue(iv.toArray()))
                ],
                 inData: cipherData.getOrThrow()
            )

            // decrypt
            let handle2 = initSession(keyAlias, decInitOptions).handle
            let decData = finishSession(handle2, decFiniOptions,token: bytes).getOrThrow()
            let dec = String.fromUtf8(decData)

            @Expect(plainText == dec)
            abortSession(handle1, initOptions)
            abortSession(handle2, decFiniOptions)
        } finally {
            clean(keyAlias)
        }
    }
    // sm4 ecb + pkcs7
    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_sm4_encrypt_decrypt_ecb_pkcs7() {
        let keyAlias = "test_sm4_encrypt_decrypt_ecb_pkcs7"
        try {
            let plainText = "123456"
            clean(keyAlias)
            let options = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(
                        HuksTag.HuksTagPurpose,
                        HuksParamValue.Uint32Value(1 | 2)
                    ),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_PKCS7),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_ECB)
                ],
               inData: Bytes()
            )
            let initOptions = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_PKCS7),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_ECB)
                // don't need iv
                ],
               inData: Bytes()
            )

            let finiOptions = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_PKCS7),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_ECB)
                // don't need iv
                ],
                inData:  plainText.toArray()
            )

            generateKeyItem(keyAlias, options)

            // encrypt
             let bytes: Array<UInt8> = []
            let handle1 = initSession(keyAlias, initOptions).handle
            let cipherData = finishSession(handle1, finiOptions,token: bytes)

            let decInitOptions = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_PKCS7),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_ECB)
                ],
               inData: Bytes()
            )

            let decFiniOptions = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_PKCS7),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_ECB)
                ],
                  inData: cipherData.getOrThrow()
            )

            // decrypt
            let handle2 = initSession(keyAlias, decInitOptions).handle
            let decData = finishSession(handle2, decFiniOptions,token: bytes).getOrThrow()
            let dec = String.fromUtf8(decData)

             @Expect(plainText == dec)
            // 不支持 ecb + pkcs7

            abortSession(handle1, initOptions)
            abortSession(handle2, decInitOptions)
        } catch (e: BusinessException) {
            @Expect(e.code, 12000003)
        } finally {
            clean(keyAlias)
        }
    }
    // sm4 ecb + nopadding
    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_sm4_encrypt_decrypt_ecb_nopadding() {
        let keyAlias = "test_sm4_encrypt_decrypt_ecb_nopadding"
        try {
            let plainText = "1234567812345678"
            clean(keyAlias)
            let options = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(
                        HuksTag.HuksTagPurpose,
                        HuksParamValue.Uint32Value(1 | 2)
                    ),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_ECB)
                ],
               inData: Bytes()
            )

            let initOptions = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_ECB)
                // don't need iv
                ],
               inData: Bytes()
            )

            let finiOptions = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_ECB)
                // don't need iv
                ],
                inData:  plainText.toArray()
            )

            generateKeyItem(keyAlias, options)

            // encrypt
             let bytes: Array<UInt8> = []
            let handle1 = initSession(keyAlias, initOptions).handle
            let cipherData = finishSession(handle1, finiOptions,token: bytes)

            let decInitOptions = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_ECB)
                ],
               inData: Bytes()
            )
            let decFiniOptions = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_ECB)
                ],
                inData: cipherData.getOrThrow()
            )

            // decrypt
            let handle2 = initSession(keyAlias, decInitOptions).handle
            let decData = finishSession(handle2, decFiniOptions,token: bytes).getOrThrow()
            let dec = String.fromUtf8(decData)

             @Expect(plainText == dec)
            // 不支持 ecb + nopadding

            abortSession(handle1, initOptions)
            abortSession(handle2, decInitOptions)
        } catch (e: BusinessException) {
            @Expect(e.code, 12000003)
        } finally {
            clean(keyAlias)
        }
    }
    // sm4 cbc + nopadding
    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_sm4_encrypt_decrypt_cbc_nopadding() {
        let keyAlias = "test_sm4_encrypt_decrypt_cbc_nopadding"
        try {
            let plainText = "1234567812345678"
            let iv = "0011223344556677"
            clean(keyAlias)
            let options = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(
                        HuksTag.HuksTagPurpose,
                        HuksParamValue.Uint32Value(1 | 2)
                    ),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CBC)
                ],
               inData: Bytes()
            )
            let initOptions = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CBC),
                    HuksParam(HuksTag.HuksTagIv, HuksParamValue.BytesValue(iv.toArray()))
                ],
               inData: Bytes()
            )

            let finiOptions = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CBC),
                    HuksParam(HuksTag.HuksTagIv, HuksParamValue.BytesValue(iv.toArray()))
                ],
                inData:  plainText.toArray()
            )

            generateKeyItem(keyAlias, options)
             let bytes: Array<UInt8> = []
            // encrypt
            let handle1 = initSession(keyAlias, initOptions).handle
            let cipherData = finishSession(handle1, finiOptions,token: bytes)

            let decInitOptions = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CBC),
                    HuksParam(HuksTag.HuksTagIv, HuksParamValue.BytesValue(iv.toArray()))
                ],
               inData: Bytes()
            )
            let decFiniOptions = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CBC),
                    HuksParam(HuksTag.HuksTagIv, HuksParamValue.BytesValue(iv.toArray()))
                ],
                inData: cipherData.getOrThrow()
            )

            // decrypt
            let handle2 = initSession(keyAlias, decInitOptions).handle
            let decData = finishSession(handle2, decFiniOptions, token: bytes).getOrThrow()
            let dec = String.fromUtf8(decData)

            @Expect(plainText == dec)
            abortSession(handle1, initOptions)
            abortSession(handle2, decInitOptions)
        } finally {
            clean(keyAlias)
        }
    }
    // sm4 ctr + nopadding
    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_sm4_encrypt_decrypt_ctr_nopadding() {
        let keyAlias = "test_sm4_encrypt_decrypt_ctr_nopadding"
        try {
            let plainText = "1234567812345678"
            let iv = "0011223344556677"
            clean(keyAlias)
            let options = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(
                        HuksTag.HuksTagPurpose,
                        HuksParamValue.Uint32Value(1 | 2)
                    ),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CTR)
                ],
               inData: Bytes()
            )
            let initOptions = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CTR),
                    HuksParam(HuksTag.HuksTagIv, HuksParamValue.BytesValue(iv.toArray()))
                ],
               inData: Bytes()
            )
             let bytes: Array<UInt8> = []
            let finiOptions = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CTR),
                    HuksParam(HuksTag.HuksTagIv, HuksParamValue.BytesValue(iv.toArray()))
                ],
                inData:  plainText.toArray()
            )

            generateKeyItem(keyAlias, options)

            // encrypt
            let handle1 = initSession(keyAlias, initOptions).handle
            let cipherData = finishSession(handle1, finiOptions, token: bytes)

            let decInitOptions = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CTR),
                    HuksParam(HuksTag.HuksTagIv, HuksParamValue.BytesValue(iv.toArray()))
                ],
               inData: Bytes()
            )
            let decFiniOptions = HuksOptions(
               properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_SM4),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_SM4_KEY_SIZE_128),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_NONE),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_CTR),
                    HuksParam(HuksTag.HuksTagIv, HuksParamValue.BytesValue(iv.toArray()))
                ],
                  inData: cipherData.getOrThrow()
            )

            // decrypt
            let handle2 = initSession(keyAlias, decInitOptions).handle
            let decData = finishSession(handle2, decFiniOptions, token:bytes).getOrThrow()
            let dec = String.fromUtf8(decData)

            @Expect(plainText == dec)
            abortSession(handle1, initOptions)
            abortSession(handle2, decInitOptions)
        } finally {
            clean(keyAlias)
        }
    }
}
