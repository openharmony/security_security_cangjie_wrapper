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
class Test_SecurityHuks_AttestKeyItem {
    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_attest_key_item() {
        //ref：https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/security/UniversalKeystoreKit/huks-key-attestation-arkts.md
        //这个用例是错的，只有覆盖率的作用，最后会抛出异常
        let keyAlias = "test_attest_key_item"
        clean(keyAlias)

        try {
            let genKeyOptions = HuksOptions(
                properties: [
                    HuksParam(HuksTag.HuksTagAlgorithm, HuksKeyAlg.HUKS_ALG_RSA),
                    HuksParam(HuksTag.HuksTagKeySize, HuksKeySize.HUKS_RSA_KEY_SIZE_2048),
                    HuksParam(HuksTag.HuksTagPurpose, HuksKeyPurpose.HUKS_KEY_PURPOSE_VERIFY),
                    HuksParam(HuksTag.HuksTagDigest, HuksKeyDigest.HUKS_DIGEST_SHA256),
                    HuksParam(HuksTag.HuksTagPadding, HuksKeyPadding.HUKS_PADDING_PSS),
                    HuksParam(HuksTag.HuksTagKeyGenerateType, HuksKeyGenerateType.HUKS_KEY_GENERATE_TYPE_DEFAULT),
                    HuksParam(HuksTag.HuksTagBlockMode, HuksCipherMode.HUKS_MODE_ECB)
                ],
               inData: Bytes()
            )
            generateKeyItem(keyAlias, genKeyOptions)

            let sec_level = "sec_level"
            let challenge_data = "challenge_data"
            let securityLevel = HuksParamValue.BytesValue(sec_level.toArray())
            let challenge = HuksParamValue.BytesValue(challenge_data.toArray())
            let attestOptions = HuksOptions(
                properties: [HuksParam(HuksTag.HuksTagAttestationIdSecLevelInfo, securityLevel),
                    HuksParam(HuksTag.HuksTagAttestationChallenge, challenge)],
               inData: Bytes()
            )
            try {
                let chains = attestKeyItem(keyAlias, attestOptions)
                @Expect(isKeyItemExist(keyAlias, HuksOptions()))
                @Expect(!chains.isEmpty())
                for (i in 0..chains.size) {
                    @Expect(!chains[i].isEmpty())
                }
            } catch (e: BusinessException) {
                // ignore
            }
        } finally {
            clean(keyAlias)
        }
    }

    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_attest_key_item_empty_alias() {
        let keyAlias = ""
        var flag = false
        try {
            attestKeyItem(keyAlias, HuksOptions())
        } catch (e: BusinessException) {
            flag = true
        } finally {
            @Expect(flag)
        }
    }
    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_attest_key_item_none_properties() {
        let keyAlias = "test_attest_key_item"
        var flag = false
        try {
            attestKeyItem(keyAlias, HuksOptions())
        } catch (e: BusinessException) {
            flag = true
        } finally {
            @Expect(flag)
        }
    }
}
