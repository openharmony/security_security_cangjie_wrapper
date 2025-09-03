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
import kit.PerformanceAnalysisKit.Hilog

@Test
class Test_SecurityHuks_Enum {
    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_EnumHuksTag() {
        try {
            let tagsArr: Array<HuksTag> = [
                HUKS_TAG_ALGORITHM,
                HUKS_TAG_PURPOSE,
                HUKS_TAG_KEY_SIZE,
                HUKS_TAG_DIGEST,
                HUKS_TAG_PADDING,
                HUKS_TAG_BLOCK_MODE,
                HUKS_TAG_KEY_TYPE,
                HUKS_TAG_ASSOCIATED_DATA,
                HUKS_TAG_NONCE,
                HUKS_TAG_IV,
                HUKS_TAG_INFO,
                HUKS_TAG_SALT,
                HUKS_TAG_ITERATION,
                HUKS_TAG_KEY_GENERATE_TYPE,
                HUKS_TAG_AGREE_ALG,
                HUKS_TAG_AGREE_PUBLIC_KEY_IS_KEY_ALIAS,
                HUKS_TAG_AGREE_PRIVATE_KEY_ALIAS,
                HUKS_TAG_AGREE_PUBLIC_KEY,
                HUKS_TAG_KEY_ALIAS,
                HUKS_TAG_DERIVE_KEY_SIZE,
                HUKS_TAG_IMPORT_KEY_TYPE,
                HUKS_TAG_UNWRAP_ALGORITHM_SUITE,
                HUKS_TAG_DERIVED_AGREED_KEY_STORAGE_FLAG,
                HUKS_TAG_RSA_PSS_SALT_LEN_TYPE,
                HUKS_TAG_USER_ID,
                HUKS_TAG_NO_AUTH_REQUIRED,
                HUKS_TAG_USER_AUTH_TYPE,
                HUKS_TAG_AUTH_TIMEOUT,
                HUKS_TAG_AUTH_TOKEN,
                HUKS_TAG_KEY_AUTH_ACCESS_TYPE,
                HUKS_TAG_KEY_SECURE_SIGN_TYPE,
                HUKS_TAG_CHALLENGE_TYPE,
                HUKS_TAG_CHALLENGE_POS,
                HUKS_TAG_KEY_AUTH_PURPOSE,
                HUKS_TAG_AUTH_STORAGE_LEVEL,
                HUKS_TAG_ATTESTATION_CHALLENGE,
                HUKS_TAG_IS_KEY_ALIAS,
                HUKS_TAG_KEY_STORAGE_FLAG,
                HUKS_TAG_IS_ALLOWED_WRAP,
                HUKS_TAG_KEY_WRAP_TYPE,
                HUKS_TAG_KEY_AUTH_ID,
                HUKS_TAG_KEY_FLAG,
                HUKS_TAG_KEY,
                HUKS_TAG_AE_TAG
            ]
            for (i in 0..tagsArr.size) {
                let params = HuksParam(tagsArr[i], HuksParamValue.Uint32Value(1))
                try {
                    generateKeyItem("keyAliasTest_${i}", HuksOptions(properties: [params]))
                } catch (e: Exception) {
                    // 12000002, message: Failed to obtain the algorithm. It is not set in ParamSet.
                    // 401, message: tag type and value mismatch
                    @Expect(true)
                }
            }
        } catch (e: Exception) {
            Hilog.info(0, "CangjieTest", "${e}")
            @Expect(false)
        }
    }

    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_huks_constructor() {
        try {
            let a1 = HuksTagType()
            let a2 = HuksKeyPurpose()
            let a3 = HuksKeyDigest()
            let a4 = HuksKeyPadding()
            let a5 = HuksCipherMode()
            let a6 = HuksKeySize()
            let a7 = HuksKeyAlg()
            let a8 = HuksUnwrapSuite()
            let a9 = HuksAuthStorageLevel()
            let a10 = HuksKeyGenerateType()
            let a11 = HuksKeyFlag()
            let a12 = HuksKeyStorageType()
            let a13 = HuksImportKeyType()
            let a14 = HuksRsaPssSaltLenType()
            let a15 = HuksUserAuthType()
            let a16 = HuksAuthAccessType()
            let a17 = HuksChallengeType()
            let a18 = HuksChallengePosition()
            let a19 = HuksSecureSignType()
            let a20 = HuksSendType()
            let a21 = HuksTagType()
        } catch (e: Exception) {
            @Expect(false)
        }
    }
}
