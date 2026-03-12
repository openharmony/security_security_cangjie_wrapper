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
 * 测试ohos.security.huks模块的deleteKeyItem功能
 */
@Test
class Test_Huks_KeyItem_Delete_Add {
    // 测试用的密钥别名
    private static const TEST_KEY_ALIAS: String = "test_key_alias"
    private static const NON_EXISTENT_KEY: String = "non_existent_key"
    private static const EMPTY_KEY_ALIAS: String = ""
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
     * 测试deleteKeyItem API - 边界值：长度为1的密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_deleteKeyItem_keyAlias_length_1() {
        // 先生成一个密钥
        generateKeyItem(ONE_CHAR_KEY_ALIAS, getDefaultAesOptions())

        // 验证密钥存在
        let existsBefore = hasKeyItem(ONE_CHAR_KEY_ALIAS, HuksOptions())
        @Expect(existsBefore)

        // 删除密钥
        deleteKeyItem(ONE_CHAR_KEY_ALIAS, HuksOptions())

        // 验证密钥不存在
        let existsAfter = hasKeyItem(ONE_CHAR_KEY_ALIAS, HuksOptions())
        @Expect(!existsAfter)
    }

    /**
     * 测试deleteKeyItem API - 边界值：最大长度的密钥别名
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_deleteKeyItem_keyAlias_length_128() {
        // 先生成一个密钥
        generateKeyItem(MAX_LENGTH_KEY_ALIAS, getDefaultAesOptions())

        // 验证密钥存在
        let existsBefore = hasKeyItem(MAX_LENGTH_KEY_ALIAS, HuksOptions())
        @Expect(existsBefore)

        // 删除密钥
        deleteKeyItem(MAX_LENGTH_KEY_ALIAS, HuksOptions())

        // 验证密钥不存在
        let existsAfter = hasKeyItem(MAX_LENGTH_KEY_ALIAS, HuksOptions())
        @Expect(!existsAfter)
    }

    /**
     * 测试deleteKeyItem API - 组合场景：重复删除同一个密钥
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_deleteKeyItem_twice() {
        // 先生成一个密钥
        generateKeyItem(TEST_KEY_ALIAS, getDefaultAesOptions())

        // 第一次删除密钥
        deleteKeyItem(TEST_KEY_ALIAS, HuksOptions())

        // 第二次删除同一个密钥，预期抛出异常
        try {
            deleteKeyItem(TEST_KEY_ALIAS, HuksOptions())
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 预期抛出密钥不存在异常
            @Expect(true)
        }
    }
}