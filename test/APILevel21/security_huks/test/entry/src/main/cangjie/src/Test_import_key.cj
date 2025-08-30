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
class Test_SecurityHuks_ImportKey {
    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_import_aes() {
        // ref: https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/security/UniversalKeystoreKit/huks-import-key-in-plaintext-arkts.md
        let keyAlias = "test_import_aes"
        clean(keyAlias)
        try {
            let key = Array<UInt8>(Int64(256 / 8),
                {i => UInt8(i & 0xFF)});
            importKeyItem(
                keyAlias,
                HuksOptions(
                    properties: [
                        HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_AES),
                        HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_AES_KEY_SIZE_256),
                        HuksParam(
                            HuksTag.HuksTagPurpose,
                            HuksParamValue.Uint32Value(1 | 2)
                        )
                    ],
                   inData: key
                )
            )
            @Expect(isKeyItemExist(keyAlias, HuksOptions()))
        } finally {
            clean(keyAlias)
        }
    }

    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_import_ecc() {
        // ref: https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/security/UniversalKeystoreKit/huks-import-key-in-plaintext-ndk.md
        let keyAlias = "test_import_ecc"
        let keyAliasBak = keyAlias + ".bak"

        clean(keyAlias)
        clean(keyAliasBak)

        try {
            let options = HuksOptions(
                properties:  [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_ECC),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_AGREE),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_ECC_KEY_SIZE_256),
                    HuksParam(HuksTag.HuksTagDigest, HuksKeyDigest.HUKS_DIGEST_NONE)
                ],
                inData: Bytes()
            )

            generateKeyItem(keyAlias, options)
            let pubKey: Array<UInt8> = exportKeyItem(keyAlias, options)

            importKeyItem(
                keyAliasBak,
                HuksOptions(
                    properties: [
                        HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_ECC),
                        HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_AGREE),
                        HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_ECC_KEY_SIZE_256),
                        HuksParam(HuksTag.HuksTagDigest, HuksKeyDigest.HUKS_DIGEST_NONE)
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
    func test_import_empty_alias() {
        let keyAlias = ""
        var flag = false
        try {
            let key = Array<UInt8>(Int64(256 / 8),
                {i => UInt8(i & 0xFF)});
            importKeyItem(
                keyAlias,
                HuksOptions(
                   properties:  [
                        HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_AES),
                        HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_AES_KEY_SIZE_256),
                        HuksParam(
                            HuksTag.HuksTagPurpose,
                           HuksParamValue.Uint32Value(1 | 2)
                        )
                    ],
                   inData: key
                )
            )
        } catch (e: BusinessException) {
            flag = true
        } finally {
            @Expect(flag)
        }
    }

    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_import_none_properties() {
        let keyAlias = "test_import"
        var flag = false
        try {
            let key = Array<UInt8>(Int64(256 / 8),
                {i => UInt8(i & 0xFF)});
            importKeyItem(
                keyAlias,
                HuksOptions(
                    properties:[],
                    inData: key
                )
            )
        } catch (e: BusinessException) {
            flag = true
        } finally {
            @Expect(flag)
        }
    }

    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_import_none_indata() {
        let keyAlias = "test_import"
          let key = Array<UInt8>(Int64(256 / 8),
                {i => UInt8(i & 0xFF)});
        clean(keyAlias)
        var flag = true
        try {
            importKeyItem(
                keyAlias,
                HuksOptions(
                    properties: [
                        HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_AES),
                        HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_AES_KEY_SIZE_256),
                        HuksParam(
                            HuksTag.HuksTagPurpose,
                            HuksParamValue.Uint32Value(1 | 2)
                        )
                    ],
                    inData: key
                )
            )
        } catch (e: BusinessException) {
            flag = false
        } finally {
            @Expect(flag)
            clean(keyAlias)
        }
    }
}
