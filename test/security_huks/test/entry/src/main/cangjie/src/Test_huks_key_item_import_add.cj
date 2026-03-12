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
 * 测试ohos.security.huks模块的importKeyItem功能
 */
@Test
class Test_Huks_KeyItem_Import_Add {
    // 测试用的密钥别名
    private static const TEST_KEY_ALIAS: String = "test_key_alias"
    private static const EMPTY_KEY_ALIAS: String = ""
    private static const ONE_CHAR_KEY_ALIAS: String = "a"
    private static const MAX_LENGTH_KEY_ALIAS: String = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 最大长度128
    private static const LONG_KEY_ALIAS: String = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 超出最大长度128 (129个a)

    /**
     * 测试importKeyItem API - 有效等价类：有效的密钥别名和选项
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_importKeyItem_keyAlias_valid() {
        // 确保测试前密钥不存在
        try {
            deleteKeyItem(TEST_KEY_ALIAS, HuksOptions())
        } catch (_) {
            // 忽略删除不存在密钥的异常
        }

        // 准备要导入的密钥数据
        let keyData: Bytes = Array(16, { i => UInt8(i & 0xFF) })

        // 准备导入选项
        let options = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT))
            ],
            inData: keyData
        )

        // 导入密钥
        importKeyItem(TEST_KEY_ALIAS, options)

        // 验证密钥存在
        let exists = hasKeyItem(TEST_KEY_ALIAS, HuksOptions())
        @Expect(exists)

        // 清理：删除导入的密钥
        deleteKeyItem(TEST_KEY_ALIAS, HuksOptions())
    }

    /**
     * 测试importKeyItem API - 无效等价类：空密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_importKeyItem_keyAlias_empty() {
        // 准备要导入的密钥数据
        let keyData: Bytes = Array(16, { i => UInt8(i & 0xFF) })

        // 准备导入选项
        let options = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT))
            ],
            inData: keyData
        )

        try {
            importKeyItem(EMPTY_KEY_ALIAS, options)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(true)
        }
    }

    /**
     * 测试importKeyItem API - 无效等价类：空properties
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_importKeyItem_options_empty_properties() {
        // 准备要导入的密钥数据
        let keyData: Bytes = Array(16, { i => UInt8(i & 0xFF) })

        // 准备导入选项
        let options = HuksOptions(
            properties: [],
            inData: keyData
        )

        try {
            importKeyItem(TEST_KEY_ALIAS, options)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(true)
        }
    }

    /**
     * 测试importKeyItem API - 无效等价类：空inData
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_importKeyItem_options_empty_indata() {
        // 准备导入选项
        let options = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT))
            ],
            inData: []
        )

        try {
            importKeyItem(TEST_KEY_ALIAS, options)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(true)
        }
    }

    /**
     * 测试importKeyItem API - 无效等价类：缺少算法参数
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_importKeyItem_options_missing_algorithm() {
        // 准备要导入的密钥数据
        let keyData: Bytes = Array(16, { i => UInt8(i & 0xFF) })

        // 准备导入选项
        let options = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT))
            ],
            inData: keyData
        )

        try {
            importKeyItem(TEST_KEY_ALIAS, options)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(true)
        }
    }

    /**
     * 测试importKeyItem API - 边界值：长度为1的密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_importKeyItem_keyAlias_length_1() {
        // 确保测试前密钥不存在
        try {
            deleteKeyItem(ONE_CHAR_KEY_ALIAS, HuksOptions())
        } catch (_) {
            // 忽略删除不存在密钥的异常
        }

        // 准备要导入的密钥数据
        let keyData: Bytes = Array(16, { i => UInt8(i & 0xFF) })

        // 准备导入选项
        let options = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT))
            ],
            inData: keyData
        )

        // 导入密钥
        importKeyItem(ONE_CHAR_KEY_ALIAS, options)

        // 验证密钥存在
        let exists = hasKeyItem(ONE_CHAR_KEY_ALIAS, HuksOptions())
        @Expect(exists)

        // 清理：删除导入的密钥
        deleteKeyItem(ONE_CHAR_KEY_ALIAS, HuksOptions())
    }

    /**
     * 测试importKeyItem API - 边界值：最大长度的密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_importKeyItem_keyAlias_length_128() {
        // 确保测试前密钥不存在
        try {
            deleteKeyItem(MAX_LENGTH_KEY_ALIAS, HuksOptions())
        } catch (_) {
            // 忽略删除不存在密钥的异常
        }

        // 准备要导入的密钥数据
        let keyData: Bytes = Array(16, { i => UInt8(i & 0xFF) })

        // 准备导入选项
        let options = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT))
            ],
            inData: keyData
        )

        // 导入密钥
        importKeyItem(MAX_LENGTH_KEY_ALIAS, options)

        // 验证密钥存在
        let exists = hasKeyItem(MAX_LENGTH_KEY_ALIAS, HuksOptions())
        @Expect(exists)

        // 清理：删除导入的密钥
        deleteKeyItem(MAX_LENGTH_KEY_ALIAS, HuksOptions())
    }

    /**
     * 测试importKeyItem API - 边界值：超出最大长度的密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_importKeyItem_keyAlias_length_129() {
        // 准备要导入的密钥数据
        let keyData: Bytes = Array(16, { i => UInt8(i & 0xFF) })

        // 准备导入选项
        let options = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT))
            ],
            inData: keyData
        )

        try {
            importKeyItem(LONG_KEY_ALIAS, options)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(true)
        }
    }

    /**
     * 测试importKeyItem API - 正常处理：同名密钥已存在
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_importKeyItem_exception_12000017() {
        // 确保测试前密钥不存在
        try {
            deleteKeyItem(TEST_KEY_ALIAS, HuksOptions())
        } catch (_) {
            // 忽略删除不存在密钥的异常
        }

        // 先导入一个密钥
        let keyData: Bytes = Array(16, { i => UInt8(i & 0xFF) })
        let options = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT))
            ],
            inData: keyData
        )
        importKeyItem(TEST_KEY_ALIAS, options)

        try {
            // 再次导入同名密钥
            importKeyItem(TEST_KEY_ALIAS, options)
            @Expect(true) // 应该执行到这里
        } catch (e: BusinessException) {
            @Expect(false)
        } finally {
            // 清理：删除导入的密钥
            deleteKeyItem(TEST_KEY_ALIAS, HuksOptions())
        }
    }
}
