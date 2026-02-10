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
    @Tag[APILevel22, TestLevel0]
    func test_EnumHuksTag() {
        try {
            let tagsArr: Array<UInt32> = [
                HuksTag.HUKS_TAG_ALGORITHM,
                HuksTag.HUKS_TAG_PURPOSE,
                HuksTag.HUKS_TAG_KEY_SIZE,
                HuksTag.HUKS_TAG_DIGEST,
                HuksTag.HUKS_TAG_PADDING,
                HuksTag.HUKS_TAG_BLOCK_MODE,
                HuksTag.HUKS_TAG_KEY_TYPE,
                HuksTag.HUKS_TAG_ASSOCIATED_DATA,
                HuksTag.HUKS_TAG_NONCE,
                HuksTag.HUKS_TAG_IV,
                HuksTag.HUKS_TAG_INFO,
                HuksTag.HUKS_TAG_SALT,
                HuksTag.HUKS_TAG_ITERATION,
                HuksTag.HUKS_TAG_KEY_GENERATION_TYPE,
                HuksTag.HUKS_TAG_ALG_FOR_AGREEMENT,
                HuksTag.HUKS_TAG_AGREE_PUBLIC_KEY_IS_KEY_ALIAS,
                HuksTag.HUKS_TAG_PRIVATE_KEY_ALIAS_FOR_AGREEMENT,
                HuksTag.HUKS_TAG_PUBLIC_KEY_FOR_AGREEMENT,
                HuksTag.HUKS_TAG_KEY_ALIAS,
                HuksTag.HUKS_TAG_DERIVE_KEY_SIZE,
                HuksTag.HUKS_TAG_IMPORT_KEY_TYPE,
                HuksTag.HUKS_TAG_UNWRAP_ALGORITHM_SUITE,
                HuksTag.HUKS_TAG_DERIVED_AGREED_KEY_STORAGE_FLAG,
                HuksTag.HUKS_TAG_RSA_PSS_SALT_LEN_TYPE,
                HuksTag.HUKS_TAG_USER_ID,
                HuksTag.HUKS_TAG_NO_AUTH_REQUIRED,
                HuksTag.HUKS_TAG_USER_AUTH_TYPE,
                HuksTag.HUKS_TAG_AUTH_TIMEOUT,
                HuksTag.HUKS_TAG_AUTH_TOKEN,
                HuksTag.HUKS_TAG_KEY_AUTH_ACCESS_TYPE,
                HuksTag.HUKS_TAG_KEY_SECURE_SIGN_TYPE,
                HuksTag.HUKS_TAG_CHALLENGE_TYPE,
                HuksTag.HUKS_TAG_CHALLENGE_POS,
                HuksTag.HUKS_TAG_KEY_AUTH_PURPOSE,
                HuksTag.HUKS_TAG_AUTH_STORAGE_LEVEL,
                HuksTag.HUKS_TAG_ATTESTATION_CHALLENGE,
                HuksTag.HUKS_TAG_IS_KEY_ALIAS,
                HuksTag.HUKS_TAG_KEY_STORAGE_FLAG,
                HuksTag.HUKS_TAG_IS_ALLOWED_WRAP,
                HuksTag.HUKS_TAG_KEY_WRAP_TYPE,
                HuksTag.HUKS_TAG_KEY_AUTH_ID,
                HuksTag.HUKS_TAG_KEY_FLAG,
                HuksTag.HUKS_TAG_KEY,
                HuksTag.HUKS_TAG_AE_TAG
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
}
