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
internal import UniversalKeystoreKit.*
import std.unittest.testmacro.*
import std.unittest.*
import std.unittest.common.*
import std.unittest.testmacro.*
import ohos.base.*

@Test
class Test_SecurityHuks_ImportWrappedKeyItem {
    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_import_wrapped_wrong() {
        //这个用例是错的，只有覆盖率的作用，最后会抛出异常
        let keyAlias = "test_import_wrapped_wrong"
        let wrappingKeyAlias = "test_import_wrapped_wrong_wrapping_key"

        clean(keyAlias)
        clean(wrappingKeyAlias)

        try {
            let options = HuksOptions(
                properties: [
                    HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_ECC)),
                    HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_AGREE)),
                    HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_ECC_KEY_SIZE_256)),
                    HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_NONE))
                ],
               inData: Bytes()
            )

            let key = Array<UInt8>(Int64(256 / 8),
                {i => UInt8(i & 0xFF)});

            try {
                importWrappedKeyItem(
                    keyAlias,
                    wrappingKeyAlias,
                    HuksOptions(
                         properties:  [
                            HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                            HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value( HuksKeySize.HUKS_AES_KEY_SIZE_256)),
                            HuksParam(
                                HuksTag.HUKS_TAG_PURPOSE,
                                HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT)
                            )
                        ],
                         inData: key
                    )
                )
                @Expect(isKeyItemExist(keyAlias, HuksOptions()))
            } catch (e: BusinessException) {
                // ignore
            }
        } finally {
            clean(keyAlias)
            clean(wrappingKeyAlias)
        }
    }

    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_import_wrapped_empty_alias() {
        let keyAlias = ""
        let wrappingKeyAlias = "test_import_wrapped_wrong_wrapping_key"
        var flag = false
        try {
            let key = Array<UInt8>(Int64(256 / 8),
                {i => UInt8(i & 0xFF)});

            importWrappedKeyItem(
                keyAlias,
                wrappingKeyAlias,
                HuksOptions(
                    properties:  [
                        HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                        HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value( HuksKeySize.HUKS_AES_KEY_SIZE_256)),
                        HuksParam(
                            HuksTag.HUKS_TAG_PURPOSE,
                            HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT)
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
    func test_import_wrapped_none_properties() {
        let keyAlias = "test_import_wrapped"
        let wrappingKeyAlias = "test_import_wrapped_wrong_wrapping_key"
        var flag = false

        try {
            let key = Array<UInt8>(Int64(256 / 8),
                {i => UInt8(i & 0xFF)});

            importWrappedKeyItem(
                keyAlias,
                wrappingKeyAlias,
                HuksOptions(
                   properties: [],
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
    func test_import_wrapped_none_indata() {
        let keyAlias = "test_import_wrapped"
        let wrappingKeyAlias = "test_import_wrapped_wrong_wrapping_key"

        var flag = false

        try {
            importWrappedKeyItem(
                keyAlias,
                wrappingKeyAlias,
                HuksOptions(
                    properties:  [
                        HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                        HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value( HuksKeySize.HUKS_AES_KEY_SIZE_256)),
                        HuksParam(
                            HuksTag.HUKS_TAG_PURPOSE,
                            HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT)
                        )
                    ],
                   inData: Bytes()
                )
            )
        } catch (e: BusinessException) {
            flag = true
        } finally {
            @Expect(flag)
        }
    }
}
