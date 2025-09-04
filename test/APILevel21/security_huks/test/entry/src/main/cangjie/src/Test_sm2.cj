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
class Test_SecurityHuks_SM2 {
    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_sm2_import_export() {
        // ref: https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/security/UniversalKeystoreKit/huks-import-key-in-plaintext-ndk.md
        let keyAlias = "test_sm2_import_export"

        let keyAliasBak = keyAlias + ".bak"

        clean(keyAlias)
        clean(keyAliasBak)

        try {
            let options = HuksOptions(
                properties: [
                    HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_SM2)),
                    // 不支持agree
                    HuksParam(
                        HuksTag.HUKS_TAG_PURPOSE,
                        HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_VERIFY | HuksKeyPurpose.HUKS_KEY_PURPOSE_SIGN)
                    ),
                    HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_SM2_KEY_SIZE_256)),
                    // 摘要算法sm3
                    HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SM3))
                ],
                 inData: Bytes()
            )

            generateKeyItem(keyAlias, options)
            let pubKey: Array<UInt8> = exportKeyItem(keyAlias, options)

            importKeyItem(
                keyAliasBak,
                HuksOptions(
                  properties:  [
                        HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_SM2)),
                        HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_VERIFY)),
                        HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_SM2_KEY_SIZE_256)),
                        HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SM3))
                    ],
                    inData: pubKey
                )
            )
            @Expect(isKeyItemExist(keyAlias, HuksOptions()))
            @Expect(isKeyItemExist(keyAliasBak, HuksOptions()))
        } finally {
            clean(keyAlias)
            clean(keyAliasBak)
        }
    }
    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_sm2_sign_verify() {
        let keyAlias = "test_sm2_sign_verify"
        let inData1 = "Hks_SM2_Test_0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000_string"
        clean(keyAlias)
        try {
            /* 1. Generate Key */
            generateKeyItem(
                keyAlias,
                HuksOptions(
                  properties:  [
                        HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_SM2)),
                        HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_SM2_KEY_SIZE_256)),
                        HuksParam(
                            HuksTag.HUKS_TAG_PURPOSE,
                            HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_VERIFY | HuksKeyPurpose.HUKS_KEY_PURPOSE_SIGN)
                        ),
                        HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SM3))
                    ],
                     inData: Bytes()
                )
            )
            /* 2. Sign */
            let signHandle = initSession(
                keyAlias,
                HuksOptions(
                  properties:  [
                        HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_SM2)),
                        HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_SM2_KEY_SIZE_256)),
                        HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_SIGN)),
                        HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SM3))
                    ],
                     inData: Bytes()
                )
            ).handle
            let bytes: Array<UInt8> = []
            updateSession(
                signHandle,
                HuksOptions(
                   properties: [
                        HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_SM2)),
                        HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_SM2_KEY_SIZE_256)),
                        HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_SIGN)),
                        HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SM3))
                    ],
                   inData: inData1.toArray()
                ),
                token: bytes
            )

            let sign = finishSession(
                signHandle,
                HuksOptions(
                   properties: [
                        HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_SM2)),
                        HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_SM2_KEY_SIZE_256)),
                        HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_SIGN)),
                        HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SM3))
                    ],
                     inData: Bytes()
                ),
                token: bytes
            ).getOrThrow()

          //  abortSession(signHandle, HuksOptions())
             var flag1 = false
             try {
                abortSession(signHandle,HuksOptions())
             } catch (e: BusinessException) {
               flag1 = true
             } finally {
               @Expect(flag1)
             }

            /* 3. Verify */
            let verifyHandle = initSession(
                keyAlias,
                HuksOptions(
                   properties: [
                        HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_SM2)),
                        HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_SM2_KEY_SIZE_256)),
                        HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_VERIFY)),
                        HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SM3))
                    ],
                     inData: Bytes()
                )
            ).handle

            updateSession(
                verifyHandle,
                HuksOptions(
                  properties:  [
                        HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_SM2)),
                        HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_SM2_KEY_SIZE_256)),
                        HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_VERIFY)),
                        HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SM3))
                    ],
                  inData: inData1.toArray()
                ),
                token: bytes
            )

            let verify = finishSession(
                verifyHandle,
                HuksOptions(
                  properties:  [
                        HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_SM2)),
                        HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_SM2_KEY_SIZE_256)),
                        HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_VERIFY)),
                        HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SM3))
                    ],
                    inData: sign
                ),
                token: bytes
            ).getOrThrow()

            @Expect(!verify.isEmpty())
           // abortSession(verifyHandle, HuksOptions())
             var flag2 = false
             try {
                abortSession(verifyHandle,HuksOptions())
             } catch (e: BusinessException) {
               flag2 = true
             } finally {
               @Expect(flag2)
             }
        } finally {
            clean(keyAlias)
        }
    }
    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_sm2_encrypt_decrypt() {
        let keyAlias = "test_sm2_sign_verify"
        let inData1 = "Hks_SM2_Test_0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000_string"
        clean(keyAlias)
        try {
            /* 1. Generate Key */
            generateKeyItem(
                keyAlias,
                HuksOptions(
                   properties: [
                        HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_SM2)),
                        HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_SM2_KEY_SIZE_256)),
                        HuksParam(
                            HuksTag.HUKS_TAG_PURPOSE,
                            HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT)
                        ),
                        HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SM3))
                    ],
                     inData: Bytes()
                )
            )
            /* 2. Encrypt */
            let encHandle = initSession(
                keyAlias,
                HuksOptions(
                   properties: [
                        HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_SM2)),
                        HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_SM2_KEY_SIZE_256)),
                        HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT)),
                        HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SM3))
                    ],
                     inData: Bytes()
                )
            ).handle
            let bytes: Array<UInt8> = []
            updateSession(
                encHandle,
                HuksOptions(
                   properties: [
                        HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_SM2)),
                        HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_SM2_KEY_SIZE_256)),
                        HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT)),
                        HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SM3))
                    ],
                   inData: inData1.toArray()
                ),
                token: bytes
            )

            let enc = finishSession(
                encHandle,
                HuksOptions(
                   properties: [
                        HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_SM2)),
                        HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_SM2_KEY_SIZE_256)),
                        HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT)),
                        HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SM3))
                    ],
                     inData: Bytes()
                ),
                 token: bytes
            ).getOrThrow()

            //abortSession(encHandle, HuksOptions())
             var flag2 = false
             try {
                abortSession(encHandle,HuksOptions())
             } catch (e: BusinessException) {
               flag2 = true
             } finally {
               @Expect(flag2)
             }

            /* 3. Decrypt */
            let decHandle = initSession(
                keyAlias,
                HuksOptions(
                  properties:  [
                        HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_SM2)),
                        HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_SM2_KEY_SIZE_256)),
                        HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT)),
                        HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SM3))
                    ],
                      inData: enc
                )

            ).handle

            updateSession(
                decHandle,
                HuksOptions(
                   properties: [
                        HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_SM2)),
                        HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_SM2_KEY_SIZE_256)),
                        HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT)),
                        HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SM3))
                    ],
                    inData: enc
                ),
                 token: bytes
            )

            let dec = finishSession(
                decHandle,
                HuksOptions(
                  properties:  [
                        HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_SM2)),
                        HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_SM2_KEY_SIZE_256)),
                        HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT)),
                        HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SM3))
                    ],
                     inData: enc
                ),
                 token: bytes
            ).getOrThrow()

            let decData = String.fromUtf8(dec)
            @Expect(decData == inData1)
            //abortSession(decHandle, HuksOptions())
            var flag1 = false
             try {
                abortSession(decHandle,HuksOptions())
             } catch (e: BusinessException) {
               flag1 = true
             } finally {
               @Expect(flag1)
             }
        } finally {
            clean(keyAlias)
        }
    }
}
