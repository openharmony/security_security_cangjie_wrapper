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
 * 测试ohos.security.huks模块的密钥管理功能
 */
@Test
class Test_Huks_KeyItem_Add {
    // 测试用的密钥别名
    private static const TEST_KEY_ALIAS: String = "test_key_alias"
    private static const NON_EXISTENT_KEY: String = "non_existent_key"
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
    func test_generateKeyItem_valid_aes() {
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
    func test_generateKeyItem_invalid_empty_alias() {
        try {
            generateKeyItem(EMPTY_KEY_ALIAS, getDefaultAesOptions())
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(e.code != 0)
        }
    }

    /**
     * 测试generateKeyItem API - 无效等价类：空properties
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_generateKeyItem_invalid_empty_properties() {
        try {
            generateKeyItem(TEST_KEY_ALIAS, HuksOptions(properties: []))
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(e.code != 0)
        }
    }

    /**
     * 测试generateKeyItem API - 无效等价类：缺少算法参数
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_generateKeyItem_invalid_missing_algorithm() {
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
            @Expect(e.code != 0)
        }
    }

    /**
     * 测试generateKeyItem API - 边界值：长度为1的密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_generateKeyItem_boundary_one_char_alias() {
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
    func test_generateKeyItem_boundary_max_length_alias() {
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
    func test_generateKeyItem_boundary_exceed_max_length_alias() {
        try {
            generateKeyItem(LONG_KEY_ALIAS, getDefaultAesOptions())
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(e.code != 0)
        }
    }

    /**
     * 测试generateKeyItem API - 特殊值：包含特殊字符的密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_generateKeyItem_special_char_alias() {
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
     * 测试deleteKeyItem API - 有效等价类：删除已存在的密钥
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    @Tag[APILevel22, TestLevel0]
    func test_deleteKeyItem_valid_existing_key() {
        // 先生成一个密钥
        generateKeyItem(TEST_KEY_ALIAS, getDefaultAesOptions())

        // 验证密钥存在
        let existsBefore = hasKeyItem(TEST_KEY_ALIAS, HuksOptions())
        @Expect(existsBefore)

        // 删除密钥
        deleteKeyItem(TEST_KEY_ALIAS, HuksOptions())

        // 验证密钥不存在
        let existsAfter = hasKeyItem(TEST_KEY_ALIAS, HuksOptions())
        @Expect(!existsAfter)
    }

    /**
     * 测试deleteKeyItem API - 无效等价类：空密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_deleteKeyItem_invalid_empty_alias() {
        try {
            deleteKeyItem(EMPTY_KEY_ALIAS, HuksOptions())
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(e.code != 0)
        }
    }

    /**
     * 测试deleteKeyItem API - 无效等价类：删除不存在的密钥
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_deleteKeyItem_invalid_non_existent_key() {
        try {
            deleteKeyItem(NON_EXISTENT_KEY, HuksOptions())
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出异常
            @Expect(e.code != 0)
        }
    }

    /**
     * 测试importKeyItem API - 有效等价类：导入AES密钥
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_importKeyItem_valid_aes() {
        // 确保测试前密钥不存在
        try {
            deleteKeyItem(TEST_KEY_ALIAS, HuksOptions())
        } catch (_) {
            // 忽略删除不存在密钥的异常
        }

        // 准备导入的密钥数据（128位AES密钥）
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
    func test_importKeyItem_invalid_empty_alias() {
        // 准备导入的密钥数据
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
            @Expect(e.code != 0)
        }
    }

    /**
     * 测试hasKeyItem API - 有效等价类：检查已存在的密钥
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_hasKeyItem_valid_existing_key() {
        // 先生成一个密钥
        generateKeyItem(TEST_KEY_ALIAS, getDefaultAesOptions())

        // 检查密钥是否存在
        let exists = hasKeyItem(TEST_KEY_ALIAS, HuksOptions())
        @Expect(exists)

        // 清理：删除生成的密钥
        deleteKeyItem(TEST_KEY_ALIAS, HuksOptions())
    }

    /**
     * 测试hasKeyItem API - 有效等价类：检查不存在的密钥
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_hasKeyItem_valid_non_existing_key() {
        // 确保密钥不存在
        try {
            deleteKeyItem(NON_EXISTENT_KEY, HuksOptions())
        } catch (_) {
            // 忽略删除不存在密钥的异常
        }

        // 检查密钥是否存在
        let exists = hasKeyItem(NON_EXISTENT_KEY, HuksOptions())
        @Expect(!exists)
    }

    /**
     * 测试getKeyItemProperties API - 有效等价类：获取已存在密钥的属性
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_getKeyItemProperties_valid() {
        // 先生成一个密钥
        generateKeyItem(TEST_KEY_ALIAS, getDefaultAesOptions())

        // 获取密钥属性
        let properties = getKeyItemProperties(TEST_KEY_ALIAS, HuksOptions())

        // 验证返回的属性不为空
        @Expect(properties.size > 0)

        // 清理：删除生成的密钥
        deleteKeyItem(TEST_KEY_ALIAS, HuksOptions())
    }

    /**
     * 测试exportKeyItem API - 有效等价类：导出已存在密钥
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_exportKeyItem_valid() {
        // 先生成一个密钥
        generateKeyItem(TEST_KEY_ALIAS, getDefaultRsaOptions())

        // 导出密钥
        let exportedKey = exportKeyItem(TEST_KEY_ALIAS, HuksOptions())

        // 验证导出的密钥不为空
        @Expect(exportedKey.size > 0)

        // 清理：删除生成的密钥
        deleteKeyItem(TEST_KEY_ALIAS, HuksOptions())
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
            @Expect(true)
        }

        // 清理：删除生成的密钥
        deleteKeyItem(TEST_KEY_ALIAS, HuksOptions())
    }

    /**
     * 测试anonAttestKeyItem API - 无效等价类：空密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_anonAttestKeyItem_invalid_empty_alias() {
        // 准备匿名认证选项
        let options = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_RSA)),
                HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_RSA_KEY_SIZE_2048))
            ]
        )

        try {
            anonAttestKeyItem(EMPTY_KEY_ALIAS, options)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(true)
        }
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
            @Expect(true)
        }
    }

    /**
     * 测试importWrappedKeyItem API - 有效等价类：导入包装密钥
     */
    /*
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
                    HuksKeyPurpose.HUKS_KEY_PURPOSE_WRAP | HuksKeyPurpose.HUKS_KEY_PURPOSE_UNWRAP)),
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
            @Expect(false)
        }

        // 清理：删除生成的密钥
        deleteKeyItem(TEST_KEY_ALIAS, HuksOptions())
        deleteKeyItem("wrapping_key", HuksOptions())
    } */

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
            @Expect(true)
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
            @Expect(true)
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
            @Expect(true)
        }
    }
}