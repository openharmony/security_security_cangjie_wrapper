/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

import std.unittest.*
import kit.UniversalKeystoreKit.*
import std.unittest.common.*
import std.unittest.testmacro.*
import ohos.base.*

/**
 * 测试ohos.security.huks模块的会话管理功能
 */
@Test
class Test_Huks_Session_Add {
    // 测试用的密钥别名
    private static const AES_KEY_ALIAS: String = "test_aes_key"
    private static const RSA_KEY_ALIAS: String = "test_rsa_key"
    private static const INVALID_KEY_ALIAS: String = "invalid_key_alias"
    private static const ONE_CHAR_ALIAS: String = "a"

    /**
     * 生成AES密钥的默认选项
     */
    private func getDefaultAesOptions(): HuksOptions {
        return HuksOptions(properties:[HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)), HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128)), HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT)), HuksParam(HuksTag.HUKS_TAG_PADDING, HuksParamValue.Uint32Value(HuksKeyPadding.HUKS_PADDING_PKCS7)), HuksParam(HuksTag.HUKS_TAG_BLOCK_MODE, HuksParamValue.Uint32Value(HuksCipherMode.HUKS_MODE_ECB))])
    }

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
                HuksParam(HuksTag.HUKS_TAG_PADDING, HuksParamValue.Uint32Value(HuksKeyPadding.HUKS_PADDING_PKCS1_V1_5)),
                HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SHA256))
            ]
        )
    }

    /**
     * 测试initSession API - 无效等价类：空密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_initSession_keyAlias_empty() {
        try {
            initSession("", getDefaultAesOptions())
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(e.code == 401)
        }
    }

    /**
     * 测试initSession API - 无效等价类：无效密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_initSession_keyAlias_nonexistent() {
        try {
            initSession(INVALID_KEY_ALIAS, getDefaultAesOptions())
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出异常
            @Expect(e.code == 12000011)
        }
    }

    /**
     * 测试updateSession API - 无效等价类：使用无效会话ID更新会话
     */
     /*
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_updateSession_handle_invalid() {
        try {
            // 使用不存在的会话ID更新会话
            let sessionResult = initSession(AES_KEY_ALIAS, getDefaultAesOptions())
            let sessionId = sessionResult.handle
            // 先中止会话使其失效
            abortSession(sessionId, getDefaultAesOptions())
            // 再尝试使用已失效的会话ID
            updateSession(sessionId, getDefaultAesOptions(), token: [0x01, 0x02, 0x03])
            @Expect(false)
        } catch(e: BusinessException) {
            // 预期会抛出异常
            @Expect(true)
        } finally {
            // 清理：删除密钥
            deleteKeyItem(AES_KEY_ALIAS, getDefaultAesOptions())
        }
    }
    */

    /**
     * 测试finishSession API - 无效等价类：使用无效会话ID完成会话
     */
     /*
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_finishSession_handle_invalid() {
        try {
            // 使用不存在的会话ID完成会话
            let sessionResult = initSession(AES_KEY_ALIAS, getDefaultAesOptions())
            let sessionId = sessionResult.handle
            // 先中止会话使其失效
            abortSession(sessionId, getDefaultAesOptions())
            // 再尝试使用已失效的会话ID
            finishSession(sessionId, getDefaultAesOptions())
            @Expect(false)
        } catch(e: BusinessException) {
            // 预期会抛出异常
            @Expect(true)
        } finally {
            // 清理：删除密钥
            deleteKeyItem(AES_KEY_ALIAS, getDefaultAesOptions())
        }
    }
    */

    /**
     * 测试abortSession API - 无效等价类：使用无效会话ID中止会话
     */
     /*
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_abortSession_handle_invalid() {
        try {
            // 使用不存在的会话ID中止会话
            let sessionResult = initSession(AES_KEY_ALIAS, getDefaultAesOptions())
            let sessionId = sessionResult.handle
            // 先中止会话使其失效
            abortSession(sessionId, getDefaultAesOptions())
            // 再尝试使用已失效的会话ID
            abortSession(sessionId, getDefaultAesOptions())
            @Expect(false)
        } catch(e: BusinessException) {
            // 预期会抛出异常
            @Expect(true)
        } finally {
            // 清理：删除密钥
            deleteKeyItem(AES_KEY_ALIAS, getDefaultAesOptions())
        }
    } */

    /**
     * 测试initSession API - 无效等价类：空properties
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_initSession_options_empty_properties() {
        try {
            // 使用空的properties初始化会话
            let options = HuksOptions(properties: [])
            initSession(AES_KEY_ALIAS, options)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(true)
        }
    }

    /**
     * 测试updateSession API - 无效等价类：空properties
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_updateSession_options_empty_properties() {
        // 先生成一个AES密钥
        generateKeyItem(AES_KEY_ALIAS, getDefaultAesOptions())

        try {
            // 初始化会话
            let sessionResult = initSession(AES_KEY_ALIAS, getDefaultAesOptions())
            let sessionId = sessionResult.handle
            
            // 使用空的properties更新会话
            let testData: Bytes = [0x01, 0x02, 0x03]
            updateSession(sessionId, HuksOptions(properties: []), token: testData)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(true)
        } finally {
            // 清理：删除密钥
            deleteKeyItem(AES_KEY_ALIAS, getDefaultAesOptions())
        }
    }

    /**
     * 测试finishSession API - 无效等价类：空properties
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_finishSession_options_empty_properties() {
        // 先生成一个AES密钥
        generateKeyItem(AES_KEY_ALIAS, getDefaultAesOptions())

        try {
            // 初始化会话
            let sessionResult = initSession(AES_KEY_ALIAS, getDefaultAesOptions())
            let sessionId = sessionResult.handle
            
            // 使用空的properties完成会话
            finishSession(sessionId, HuksOptions(properties: []))
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(true)
        } finally {
            // 清理：删除密钥
            deleteKeyItem(AES_KEY_ALIAS, getDefaultAesOptions())
        }
    }

    /**
     * 测试abortSession API - 无效等价类：空properties
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_abortSession_options_empty_properties() {
        // 先生成一个AES密钥
        generateKeyItem(AES_KEY_ALIAS, getDefaultAesOptions())

        try {
            // 初始化会话
            let sessionResult = initSession(AES_KEY_ALIAS, getDefaultAesOptions())
            let sessionId = sessionResult.handle
            
            // 使用空的properties中止会话
            abortSession(sessionId, HuksOptions(properties: []))
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(true)
        } finally {
            // 清理：删除密钥
            deleteKeyItem(AES_KEY_ALIAS, getDefaultAesOptions())
        }
    }
}