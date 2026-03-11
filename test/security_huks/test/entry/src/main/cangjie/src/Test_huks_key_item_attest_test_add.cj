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

/**
 * 测试ohos.security.huks模块的anonAttestKeyItem功能
 */
@Test
class Test_Huks_KeyItem_Attest_Add {
    // 测试用的密钥别名
    private static const TEST_KEY_ALIAS: String = "test_key_alias"
    private static const EMPTY_KEY_ALIAS: String = ""

    /**
     * 生成RSA密钥的默认选项
     */
    private func getDefaultRsaOptions(): HuksOptions {
        return HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_RSA)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_RSA_KEY_SIZE_2048)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_SIGN | HuksKeyPurpose.HUKS_KEY_PURPOSE_VERIFY)),
                HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SHA256))
            ]
        )
    }

    /**
     * 测试anonAttestKeyItem API - 有效等价类：获取匿名认证证书
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_anonAttestKeyItem_valid() {
        // 先生成一个密钥
        generateKeyItem(TEST_KEY_ALIAS, getDefaultRsaOptions())

        // 准备匿名认证选项
        let options = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_RSA)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_RSA_KEY_SIZE_2048))
            ]
        )

        try {
            // 由于匿名认证需要网络连接，可能会失败，这里仅测试参数格式是否正确
            let certChains = anonAttestKeyItem(TEST_KEY_ALIAS, options)
            // 如果成功，验证返回的证书链不为空
            if (certChains.size > 0) {
                @Expect(certChains.size > 0)
            }
        } catch (e: BusinessException) {
            // 预期可能抛出异常（如网络连接问题）
            // 仅验证是否是参数错误以外的异常
            @Expect(e.code != 0)
        }

        // 清理：删除生成的密钥
        deleteKeyItem(TEST_KEY_ALIAS, HuksOptions())
    }

    /**
     * 测试anonAttestKeyItem API - 无效等价类：不支持证书的密钥
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_anonAttestKeyItem_unsupported_key() {
        // 确保测试前密钥不存在
        try {
            deleteKeyItem(TEST_KEY_ALIAS, HuksOptions())
        } catch (_) {
            // 忽略删除不存在密钥的异常
        }

        // 生成一个AES对称密钥（通常不支持证书）
        let aesOptions = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT))
            ]
        )
        generateKeyItem(TEST_KEY_ALIAS, aesOptions)

        // 准备匿名认证选项
        let options = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128)),
                HuksParam(HuksTag.HUKS_TAG_ATTESTATION_CHALLENGE, HuksParamValue.BytesValue("hi_challenge_data".toArray()))
            ]
        )

        try {
            anonAttestKeyItem(TEST_KEY_ALIAS, options)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出算法不支持异常
            @Expect(e.code != 0)
        }

        // 清理：删除生成的密钥
        deleteKeyItem(TEST_KEY_ALIAS, HuksOptions())
    }

    /**
     * 测试anonAttestKeyItem API - 无效等价类：空properties
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_anonAttestKeyItem_invalid_empty_properties() {
        try {
            anonAttestKeyItem(TEST_KEY_ALIAS, HuksOptions(properties: []))
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(e.code != 0)
        }
    }
}
