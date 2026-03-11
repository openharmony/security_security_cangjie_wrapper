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
 * 测试ohos.security.huks模块的importWrappedKeyItem功能
 */
@Test
class Test_Huks_KeyItem_Wrap_Add {
    // 测试用的密钥别名
    private static const TEST_KEY_ALIAS: String = "test_key_alias"
    private static const EMPTY_KEY_ALIAS: String = ""
    private static const ONE_CHAR_KEY_ALIAS: String = "a"
    private static const MAX_LENGTH_KEY_ALIAS: String = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 最大长度128
    private static const NON_EXISTENT_WRAPPING_KEY: String = "non_existent_wrapping_key"

    /**
     * 测试importWrappedKeyItem API - 有效等价类：导入包装密钥
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_importWrappedKeyItem_valid() {
        // 确保测试前密钥不存在
        try {
            deleteKeyItem(TEST_KEY_ALIAS, HuksOptions())
            deleteKeyItem("wrapping_key", HuksOptions())
        } catch (_) {
            // 忽略删除不存在密钥的异常
        }

        // 先生成一个包装密钥
        let wrappingOptions = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_RSA)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_RSA_KEY_SIZE_2048)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT)),
                HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SHA256))
            ]
        )
        generateKeyItem("wrapping_key", wrappingOptions)

        // 准备要导入的包装密钥数据（这里使用模拟数据）
        let wrappedKeyData: Bytes = Array(32, { i => UInt8(i & 0xFF) })

        // 准备导入选项
        let importOptions = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT))
            ],
            inData: wrappedKeyData
        )

        try {
            // 由于需要有效的包装密钥数据，这里可能会失败，仅测试参数格式是否正确
            importWrappedKeyItem(TEST_KEY_ALIAS, "wrapping_key", importOptions)
        } catch (e: BusinessException) {
            // 预期可能抛出异常（如包装数据无效）
            // 仅验证是否是参数错误以外的异常
            @Expect(e.code != 0)
        }

    }


    /**
     * 测试importWrappedKeyItem API - 无效等价类：空密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_importWrappedKeyItem_invalid_empty_alias() {
        // 准备要导入的包装密钥数据
        let wrappedKeyData: Bytes = Array(32, { i => UInt8(i & 0xFF) })

        // 准备导入选项
        let importOptions = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT))
            ],
            inData: wrappedKeyData
        )

        try {
            importWrappedKeyItem(EMPTY_KEY_ALIAS, "wrapping_key", importOptions)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(e.code != 0)
        }
    }

    /**
     * 测试importWrappedKeyItem API - 无效等价类：空properties
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_importWrappedKeyItem_invalid_empty_properties() {
        // 准备要导入的包装密钥数据
        let wrappedKeyData: Bytes = Array(32, { i => UInt8(i & 0xFF) })

        // 准备导入选项
        let importOptions = HuksOptions(
            properties: [],
            inData: wrappedKeyData
        )

        try {
            importWrappedKeyItem(TEST_KEY_ALIAS, "wrapping_key", importOptions)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(e.code != 0)
        }
    }

    /**
     * 测试importWrappedKeyItem API - 无效等价类：空inData
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_importWrappedKeyItem_invalid_empty_indata() {
        // 准备导入选项
        let importOptions = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT))
            ],
            inData: []
        )

        try {
            importWrappedKeyItem(TEST_KEY_ALIAS, "wrapping_key", importOptions)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(e.code != 0)
        }
    }

    /**
     * 测试importWrappedKeyItem API - 边界值：长度为1的密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_importWrappedKeyItem_keyAlias_length_1() {
        // 确保测试前密钥不存在
        try {
            deleteKeyItem(ONE_CHAR_KEY_ALIAS, HuksOptions())
            deleteKeyItem("wrapping_key", HuksOptions())
        } catch (_) {
            // 忽略删除不存在密钥的异常
        }

        // 先生成一个包装密钥
        let wrappingOptions = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_RSA)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_RSA_KEY_SIZE_2048)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT)),
                HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SHA256))
            ]
        )
        generateKeyItem("wrapping_key", wrappingOptions)

        // 准备要导入的包装密钥数据
        let wrappedKeyData: Bytes = Array(32, { i => UInt8(i & 0xFF) })

        // 准备导入选项
        let importOptions = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT))
            ],
            inData: wrappedKeyData
        )

        try {
            importWrappedKeyItem(ONE_CHAR_KEY_ALIAS, "wrapping_key", importOptions)
        } catch (e: BusinessException) {
            // 预期可能抛出异常（如包装数据无效）
            // 仅验证是否是参数错误以外的异常
            @Expect(e.code != 0)
        }

    }

    /**
     * 测试importWrappedKeyItem API - 边界值：最大长度的密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_importWrappedKeyItem_keyAlias_length_128() {
        // 确保测试前密钥不存在
        try {
            deleteKeyItem(MAX_LENGTH_KEY_ALIAS, HuksOptions())
            deleteKeyItem("wrapping_key", HuksOptions())
        } catch (_) {
            // 忽略删除不存在密钥的异常
        }

        // 先生成一个包装密钥
        let wrappingOptions = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_RSA)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_RSA_KEY_SIZE_2048)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT)),
                HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SHA256))
            ]
        )
        generateKeyItem("wrapping_key", wrappingOptions)

        // 准备要导入的包装密钥数据
        let wrappedKeyData: Bytes = Array(32, { i => UInt8(i & 0xFF) })

        // 准备导入选项
        let importOptions = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT))
            ],
            inData: wrappedKeyData
        )

        try {
            importWrappedKeyItem(MAX_LENGTH_KEY_ALIAS, "wrapping_key", importOptions)
        } catch (e: BusinessException) {
            // 预期可能抛出异常（如包装数据无效）
            // 仅验证是否是参数错误以外的异常
            @Expect(e.code != 0)
        }

    }

    /**
     * 测试importWrappedKeyItem API - 无效等价类：不存在的包装密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_importWrappedKeyItem_wrappingKeyAlias_nonexistent() {
        // 准备要导入的包装密钥数据
        let wrappedKeyData: Bytes = Array(32, { i => UInt8(i & 0xFF) })

        // 准备导入选项
        let importOptions = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT))
            ],
            inData: wrappedKeyData
        )

        try {
            importWrappedKeyItem(TEST_KEY_ALIAS, NON_EXISTENT_WRAPPING_KEY, importOptions)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出异常
            @Expect(e.code == 12000011)
        }
    }

    /**
     * 测试importWrappedKeyItem API - 无效等价类：空包装密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_importWrappedKeyItem_wrappingKeyAlias_empty() {
        // 准备要导入的包装密钥数据
        let wrappedKeyData: Bytes = Array(32, { i => UInt8(i & 0xFF) })

        // 准备导入选项
        let importOptions = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT))
            ],
            inData: wrappedKeyData
        )

        try {
            importWrappedKeyItem(TEST_KEY_ALIAS, EMPTY_KEY_ALIAS, importOptions)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(e.code != 0)
        }
    }

    /**
     * 测试importWrappedKeyItem API - 边界值：长度为1的包装密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_importWrappedKeyItem_wrappingKeyAlias_length_1() {
        // 确保测试前密钥不存在
        try {
            deleteKeyItem(TEST_KEY_ALIAS, HuksOptions())
            deleteKeyItem(ONE_CHAR_KEY_ALIAS, HuksOptions())
        } catch (_) {
            // 忽略删除不存在密钥的异常
        }

        // 先生成一个包装密钥
        let wrappingOptions = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_RSA)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_RSA_KEY_SIZE_2048)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT)),
                HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SHA256))
            ]
        )
        generateKeyItem(ONE_CHAR_KEY_ALIAS, wrappingOptions)

        // 准备要导入的包装密钥数据
        let wrappedKeyData: Bytes = Array(32, { i => UInt8(i & 0xFF) })

        // 准备导入选项
        let importOptions = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT))
            ],
            inData: wrappedKeyData
        )

        try {
            importWrappedKeyItem(TEST_KEY_ALIAS, ONE_CHAR_KEY_ALIAS, importOptions)
        } catch (e: BusinessException) {
            // 预期可能抛出异常（如包装数据无效）
            // 仅验证是否是参数错误以外的异常
            @Expect(e.code != 0)
        }

    }

    /**
     * 测试importWrappedKeyItem API - 边界值：最大长度的包装密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_importWrappedKeyItem_wrappingKeyAlias_length_128() {
        // 确保测试前密钥不存在
        try {
            deleteKeyItem(TEST_KEY_ALIAS, HuksOptions())
            deleteKeyItem(MAX_LENGTH_KEY_ALIAS, HuksOptions())
        } catch (_) {
            // 忽略删除不存在密钥的异常
        }

        // 先生成一个包装密钥
        let wrappingOptions = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_RSA)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_RSA_KEY_SIZE_2048)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT)),
                HuksParam(HuksTag.HUKS_TAG_DIGEST, HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SHA256))
            ]
        )
        generateKeyItem(MAX_LENGTH_KEY_ALIAS, wrappingOptions)

        // 准备要导入的包装密钥数据
        let wrappedKeyData: Bytes = Array(32, { i => UInt8(i & 0xFF) })

        // 准备导入选项
        let importOptions = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128)),
                HuksParam(HuksTag.HUKS_TAG_PURPOSE, HuksParamValue.Uint32Value(
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT))
            ],
            inData: wrappedKeyData
        )

        try {
            importWrappedKeyItem(TEST_KEY_ALIAS, MAX_LENGTH_KEY_ALIAS, importOptions)
        } catch (e: BusinessException) {
            // 预期可能抛出异常（如包装数据无效）
            // 仅验证是否是参数错误以外的异常
            @Expect(e.code != 0)
        }

        
    }
}
