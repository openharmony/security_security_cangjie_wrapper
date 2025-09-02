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
                HuksTagAlgorithm,
                HuksTagPurpose,
                HuksTagKeySize,
                HuksTagDigest,
                HuksTagPadding,
                HuksTagBlockMode,
                HuksTagKeyType,
                HuksTagAssociatedData,
                HuksTagNonce,
                HuksTagIv,
                HuksTagInfo,
                HuksTagSalt,
                HuksTagIteration,
                HuksTagKeyGenerateType,
                HuksTagAgreeAlg,
                HuksTagAgreePublicKeyIsKeyAlias,
                HuksTagAgreePrivateKeyAlias,
                HuksTagAgreePublicKey,
                HuksTagKeyAlias,
                HuksTagDeriveKeySize,
                HuksTagImportKeyType,
                HuksTagUnwrapAlgorithmSuite,
                HuksTagDerivedAgreedKeyStorageFlag,
                HuksTagRsaPssSaltLenType,
                HuksTagAllUsers,
                HuksTagUserId,
                HuksTagNoAuthRequired,
                HuksTagUserAuthType,
                HuksTagAuthTimeout,
                HuksTagAuthToken,
                HuksTagKeyAuthAccessType,
                HuksTagKeySecureSignType,
                HuksTagChallengeType,
                HuksTagChallengePos,
                HuksTagKeyAuthPurpose,
                HuksTagAuthStorageLevel,
                HuksTagAttestationChallenge,
                HuksTagAttestationApplicationId,
                HuksTagAttestationIdSecLevelInfo,
                HuksTagAttestationIdVersionInfo,
                HuksTagAttestationBase64,
                HuksTagAttestationMode,
                HuksTagAttestationApplicationIdType,
                HuksTagIsKeyAlias,
                HuksTagKeyStorageFlag,
                HuksTagIsAllowedWrap,
                HuksTagKeyWrapType,
                HuksTagKeyAuthId,
                HuksTagKeyRole,
                HuksTagKeyFlag,
                HuksTagIsAsynchronized,
                HuksTagKeyDomain,
                HuksTagProcessName,
                HuksTagKey,
                HuksTagKeyVersion,
                HuksTagAeTag,
                HuksTagIsKeyHandle,
                HuksTagOsVersion,
                HuksTagOsPatchlevel,
                HuksTagSymmetricKeyData,
                HuksTagAsymmetricPublicKeyData,
                HuksTagAsymmetricPrivateKeyData,
                HuksTagScreenState,
                HuksTagDeriveMainKeyMode
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
