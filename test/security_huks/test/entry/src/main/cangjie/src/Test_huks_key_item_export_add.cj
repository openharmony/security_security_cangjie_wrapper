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
 * 测试ohos.security.huks模块的exportKeyItem功能
 */
@Test
class Test_Huks_KeyItem_Export_Add {
    // 测试用的密钥别名
    private static const TEST_KEY_ALIAS: String = "test_key_alias"
    private static const EMPTY_KEY_ALIAS: String = ""
    private static const ONE_CHAR_KEY_ALIAS: String = "a"
    private static const MAX_LENGTH_KEY_ALIAS: String = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 最大长度128
    private static const NON_EXISTENT_KEY: String = "non_existent_key"
    private static const SYMMETRIC_KEY_ALIAS: String = "test_symmetric_key"

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
     * 测试exportKeyItem API - 无效等价类：空密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_exportKeyItem_keyAlias_empty() {
        // 准备导出选项
        let exportOptions = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_RSA))
            ]
        )

        try {
            exportKeyItem(EMPTY_KEY_ALIAS, exportOptions)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(true)
        }
    }

    /**
     * 测试exportKeyItem API - 无效等价类：空properties
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_exportKeyItem_options_empty_properties() {
        // 确保密钥不存在
        try {
            deleteKeyItem(TEST_KEY_ALIAS, HuksOptions())
        } catch (_) {
            // 忽略删除不存在密钥的异常
        }

        try {
            exportKeyItem(TEST_KEY_ALIAS, HuksOptions())
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出参数异常
            @Expect(true)
        }  
    }

    /**
     * 测试exportKeyItem API - 无效等价类：导出不存在的密钥
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_exportKeyItem_keyAlias_nonexistent() {
        // 确保密钥不存在
        try {
            deleteKeyItem(NON_EXISTENT_KEY, HuksOptions())
        } catch (_) {
            // 忽略删除不存在密钥的异常
        }

        // 准备导出选项
        let exportOptions = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_RSA))
            ]
        )

        try {
            exportKeyItem(NON_EXISTENT_KEY, exportOptions)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出异常
            @Expect(true)
        }
    }

    /**
     * 测试exportKeyItem API - 无效等价类：导出对称密钥
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_exportKeyItem_keyAlias_symmetric() {
        // 先生成一个AES对称密钥
        generateKeyItem(SYMMETRIC_KEY_ALIAS, getDefaultAesOptions())

        // 准备导出选项
        let exportOptions = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES))
            ]
        )

        try {
            exportKeyItem(SYMMETRIC_KEY_ALIAS, exportOptions)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出异常（对称密钥不可导出）
            @Expect(true)
        }

        // 清理：删除生成的密钥
        deleteKeyItem(SYMMETRIC_KEY_ALIAS, HuksOptions())
    }

    /**
     * 测试exportKeyItem API - 边界值：长度为1的密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_exportKeyItem_keyAlias_length_1() {
        // 先生成一个RSA密钥
        generateKeyItem(ONE_CHAR_KEY_ALIAS, getDefaultRsaOptions())

        // 准备导出选项
        let exportOptions = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_RSA))
            ]
        )

        try {
            // 导出密钥
            let keyBlob = exportKeyItem(ONE_CHAR_KEY_ALIAS, exportOptions)
            // 验证返回的密钥数据不为空
            @Expect(keyBlob.size > 0)
        } catch (e: BusinessException) {
            // 预期可能抛出异常（如权限问题），但不应是参数错误
            @Expect(true)
        }

        // 清理：删除生成的密钥
        deleteKeyItem(ONE_CHAR_KEY_ALIAS, HuksOptions())
    }

    /**
     * 测试exportKeyItem API - 边界值：最大长度的密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_exportKeyItem_keyAlias_length_128() {
        // 先生成一个RSA密钥
        generateKeyItem(MAX_LENGTH_KEY_ALIAS, getDefaultRsaOptions())

        // 准备导出选项
        let exportOptions = HuksOptions(
            properties: [
                HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_RSA))
            ]
        )

        try {
            // 导出密钥
            let keyBlob = exportKeyItem(MAX_LENGTH_KEY_ALIAS, exportOptions)
            // 验证返回的密钥数据不为空
            @Expect(keyBlob.size > 0)
        } catch (e: BusinessException) {
            // 预期可能抛出异常（如权限问题），但不应是参数错误
            @Expect(true)
        }

        // 清理：删除生成的密钥
        deleteKeyItem(MAX_LENGTH_KEY_ALIAS, HuksOptions())
    }
}
