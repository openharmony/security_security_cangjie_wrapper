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
 * 测试ohos.security.huks模块的generateKeyItem功能
 */
@Test
class Test_Huks_KeyItem_Generate_Add {
    // 测试用的密钥别名
    private static const TEST_KEY_ALIAS: String = "test_key_alias"
    private static const EMPTY_KEY_ALIAS: String = ""
    private static const LONG_KEY_ALIAS: String = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 超出最大长度128 (129个a)
    private static const SPECIAL_CHAR_KEY_ALIAS: String = "key@#$%"
    private static const ONE_CHAR_KEY_ALIAS: String = "a"
    private static const MAX_LENGTH_KEY_ALIAS: String = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 最大长度128

    /**
     * 生成AES密钥的默认选项
     */
    private func getDefaultAesOptions(): HuksOptions {
        return HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT))
            ]
        )
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
                HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SHA256))
            ]
        )
    }

    /**
     * 测试generateKeyItem API - 有效等价类：使用有效的密钥别名和AES选项
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_generateKeyItem_keyAlias_valid() {
        // 确保测试前密钥不存在
        try {
            deleteKeyItem(TEST_KEY_ALIAS, HuksOptions())
        } catch (_) {
            // 忽略删除不存在密钥的异常
        }

        // 生成密钥
        generateKeyItem(TEST_KEY_ALIAS, getDefaultAesOptions())

        // 验证密钥存在
        let exists = hasKeyItem(TEST_KEY_ALIAS, HuksOptions())
        @Expect(exists)

        // 清理：删除生成的密钥
        deleteKeyItem(TEST_KEY_ALIAS, HuksOptions())
    }


    /**
     * 测试generateKeyItem API - 无效等价类：空密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_generateKeyItem_keyAlias_empty() {
        try {
            generateKeyItem(EMPTY_KEY_ALIAS, getDefaultAesOptions())
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(true)
        }
    }

    /**
     * 测试generateKeyItem API - 无效等价类：空properties
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_generateKeyItem_options_empty_properties() {
        try {
            generateKeyItem(TEST_KEY_ALIAS, HuksOptions(properties: []))
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(true)
        }
    }

    /**
     * 测试generateKeyItem API - 无效等价类：缺少算法参数
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_generateKeyItem_options_missing_algorithm() {
        try {
            let options = HuksOptions(
                properties: [
                    HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128)),
                    HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                        HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT))
                ]
            )
            generateKeyItem(TEST_KEY_ALIAS, options)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(true)
        }
    }

    /**
     * 测试generateKeyItem API - 无效等价类：缺少密钥大小参数
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_generateKeyItem_options_missing_key_size() {
        try {
            let options = HuksOptions(
                properties: [
                    HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                    HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                        HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT))
                ]
            )
            generateKeyItem(TEST_KEY_ALIAS, options)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(true)
        }
    }

    /**
     * 测试generateKeyItem API - 无效等价类：缺少密钥用途参数
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_generateKeyItem_options_missing_purpose() {
        try {
            let options = HuksOptions(
                properties: [
                    HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                    HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128))
                ]
            )
            generateKeyItem(TEST_KEY_ALIAS, options)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(true)
        }
    }

    /**
     * 测试generateKeyItem API - 边界值：长度为1的密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_generateKeyItem_keyAlias_length_1() {
        // 确保测试前密钥不存在
        try {
            deleteKeyItem(ONE_CHAR_KEY_ALIAS, HuksOptions())
        } catch (_) {
            // 忽略删除不存在密钥的异常
        }

        // 生成密钥
        generateKeyItem(ONE_CHAR_KEY_ALIAS, getDefaultAesOptions())

        // 验证密钥存在
        let exists = hasKeyItem(ONE_CHAR_KEY_ALIAS, HuksOptions())
        @Expect(exists)

        // 清理：删除生成的密钥
        deleteKeyItem(ONE_CHAR_KEY_ALIAS, HuksOptions())
    }

    /**
     * 测试generateKeyItem API - 边界值：最大长度的密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_generateKeyItem_keyAlias_length_128() {
        // 确保测试前密钥不存在
        try {
            deleteKeyItem(MAX_LENGTH_KEY_ALIAS, HuksOptions())
        } catch (_) {
            // 忽略删除不存在密钥的异常
        }

        // 生成密钥
        generateKeyItem(MAX_LENGTH_KEY_ALIAS, getDefaultAesOptions())

        // 验证密钥存在
        let exists = hasKeyItem(MAX_LENGTH_KEY_ALIAS, HuksOptions())
        @Expect(exists)

        // 清理：删除生成的密钥
        deleteKeyItem(MAX_LENGTH_KEY_ALIAS, HuksOptions())
    }

    /**
     * 测试generateKeyItem API - 边界值：超出最大长度的密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_generateKeyItem_keyAlias_length_129() {
        try {
            generateKeyItem(LONG_KEY_ALIAS, getDefaultAesOptions())
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(true)
        }
    }

    /**
     * 测试generateKeyItem API - 特殊值：包含特殊字符的密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_generateKeyItem_keyAlias_special_chars() {
        // 确保测试前密钥不存在
        try {
            deleteKeyItem(SPECIAL_CHAR_KEY_ALIAS, HuksOptions())
        } catch (_) {
            // 忽略删除不存在密钥的异常
        }

        // 生成密钥
        generateKeyItem(SPECIAL_CHAR_KEY_ALIAS, getDefaultAesOptions())

        // 验证密钥存在
        let exists = hasKeyItem(SPECIAL_CHAR_KEY_ALIAS, HuksOptions())
        @Expect(exists)

        // 清理：删除生成的密钥
        deleteKeyItem(SPECIAL_CHAR_KEY_ALIAS, HuksOptions())
    }

    /**
     * 测试generateKeyItem API - 异常处理：无效的算法参数
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_generateKeyItem_exception_12000003() {
        try {
            // 创建无效的密钥参数（AES算法使用RSA密钥长度）
            let options = HuksOptions(
                properties: [
                    HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                    HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_RSA_KEY_SIZE_2048)),
                    HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                        HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT))
                ]
            )
            generateKeyItem(TEST_KEY_ALIAS, options)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出算法参数无效异常
            @Expect(true)
        }
    }

    /**
     * 测试generateKeyItem API - 正常处理：同名密钥已存在
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_generateKeyItem_exception_12000017() {
        // 先生成一个密钥
        generateKeyItem(TEST_KEY_ALIAS, getDefaultAesOptions())

        try {
            // 再次生成同名密钥
            generateKeyItem(TEST_KEY_ALIAS, getDefaultAesOptions())
            @Expect(true) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出同名密钥已存在异常
            @Expect(true)
        } finally {
            // 清理：删除生成的密钥
            deleteKeyItem(TEST_KEY_ALIAS, HuksOptions())
        }
    }
}