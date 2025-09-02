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
class Test_SecurityHuks_AbortSession {
    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_abort() {
        let keyAlias = "test_abort_session_11111111"
        clean(keyAlias)
        try {
            let plainText = "123456"
            let iv = "0011223344556677"
            let options = HuksOptions(
                properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_AES),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_AES_KEY_SIZE_128),
                    HuksParam(
                        HuksTag.HuksTagPurpose,
                      //  HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT
                         HuksParamValue.Uint32Value(1 | 2)
                    )
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

            // encrypt and abort
            let handle = initSession(keyAlias, encOptions).handle

            abortSession(handle, encOptions)
        } finally {
            clean(keyAlias)
        }
    }
}
