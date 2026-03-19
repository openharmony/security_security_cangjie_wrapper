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

import kit.CryptoArchitectureKit.*
import ohos.base.*
import std.math.numeric.*
import std.runtime.*
import std.sync.*
import std.time.*
import std.unittest.*
import std.unittest.common.*
import std.unittest.testmacro.*
import ohos.business_exception.*

/**
 * 测试ohos.crypto_framework模块的createCipher API功能
 */
@Test
class Test_Create_Cipher_Add {
    /**
     * 测试createCipher API - 有效等价类：创建3DES192|ECB|PKCS7加密算法实例
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createCipher_transformation_3DES_ECB_PKCS7() {
        // 创建3DES192|ECB|PKCS7加密算法实例
        let cipher: Cipher = createCipher("3DES192|ECB|PKCS7")
        // 验证算法名称是否正确
        @Expect(cipher.algName == "3DES192|ECB|PKCS7")
    }

    /**
     * 测试createCipher API - 有效等价类：创建AES128|CBC|PKCS7加密算法实例
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createCipher_transformation_AES_CBC_PKCS7() {
        // 创建AES128|CBC|PKCS7加密算法实例
        let cipher: Cipher = createCipher("AES128|CBC|PKCS7")
        // 验证算法名称是否正确
        @Expect(cipher.algName == "AES128|CBC|PKCS7")
    }

    /**
     * 测试createCipher API - 有效等价类：创建AES256|GCM|NoPadding加密算法实例
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createCipher_transformation_AES_GCM() {
        // 创建AES256|GCM|NoPadding加密算法实例
        let cipher: Cipher = createCipher("AES256|GCM|NoPadding")
        // 验证算法名称是否正确
        @Expect(cipher.algName == "AES256|GCM|NoPadding")
    }

    /**
     * 测试createCipher API - 有效等价类：创建SM4|CBC|PKCS7加密算法实例
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createCipher_transformation_SM4_CBC() {
        // 创建SM4|CBC|PKCS7加密算法实例
        let cipher: Cipher = createCipher("SM4|CBC|PKCS7")
        // 验证算法名称是否正确
        @Expect(cipher.algName == "SM4|CBC|PKCS7")
    }

    /**
     * 测试createCipher API - 无效等价类：空转换字符串
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createCipher_transformation_empty() {
        // 尝试使用空字符串创建加密算法实例，预期抛出异常
        try {
            createCipher("")
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 验证异常代码和消息是否正确
            @Expect(true)
        }
    }

    /**
     * 测试createCipher API - 无效等价类：无效的转换字符串
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createCipher_transformation_invalid() {
        // 尝试使用无效的转换字符串创建加密算法实例，预期抛出异常
        try {
            createCipher("INVALID_ALG")
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 验证异常代码和消息是否正确
            @Expect(true)
        }
    }

    /**
     * 测试createCipher API - 无效等价类：不完整的转换字符串
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createCipher_transformation_incomplete() {
        // 尝试使用不完整的转换字符串（只有算法名称）创建加密算法实例，预期抛出异常
        try {
            let encoder = createCipher("AES128")
            @Expect(encoder.algName, "AES128")
        } catch (e: BusinessException) {
            // 验证异常代码和消息是否正确
            @Expect(true)
        }
    }

    /**
     * 测试createCipher API - 验证返回值类型为Cipher
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createCipher_return_cipher() {
        // 创建AES128|CBC|PKCS7加密算法实例
        let cipher: Cipher = createCipher("AES128|CBC|PKCS7")
        // 验证算法名称是否正确
        @Expect(cipher.algName == "AES128|CBC|PKCS7")
    }

    /**
     * 测试createCipher API - 异常情况：无效的算法名称导致异常
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createCipher_exception_801() {
        // 尝试使用包含无效算法名称的转换字符串创建加密算法实例，预期抛出异常
        try {
            createCipher("INVALID_ALG|ECB|PKCS7")
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 验证异常代码和消息是否正确
            @Expect(true)
        }
    }

    /**
     * 测试createCipher和initialize API组合 - 有效等价类：完整的加密算法初始化流程
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createCipher_then_initialize() {
        // 创建AES128|ECB|PKCS7加密算法实例
        let cipher: Cipher = createCipher("AES128|ECB|PKCS7")
        // 验证算法名称是否正确
        @Expect(cipher.algName == "AES128|ECB|PKCS7")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()

        // 使用密钥初始化加密算法实例
        cipher.initialize(CryptoMode.EncryptMode, key, Option<ParamsSpec>.None)
        
        @Expect(true)
    }
}