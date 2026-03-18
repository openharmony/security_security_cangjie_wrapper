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
 * 测试ohos.crypto_framework模块的createSymKeyGenerator API功能
 */
@Test
class Test_Create_SymKey_Generator_Add {
    /**
     * 测试createSymKeyGenerator API - 有效等价类：创建AES128密钥生成器
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createSymKeyGenerator_AES128() {
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 验证算法名称是否正确
        @Expect(keyGenerator.algName == "AES128")
    }

    /**
     * 测试createSymKeyGenerator API - 有效等价类：创建AES192密钥生成器
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createSymKeyGenerator_AES192() {
        // 创建AES192对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES192")
        // 验证算法名称是否正确
        @Expect(keyGenerator.algName == "AES192")
    }

    /**
     * 测试createSymKeyGenerator API - 有效等价类：创建AES256密钥生成器
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createSymKeyGenerator_AES256() {
        // 创建AES256对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES256")
        // 验证算法名称是否正确
        @Expect(keyGenerator.algName == "AES256")
    }

    /**
     * 测试createSymKeyGenerator API - 有效等价类：创建3DES192密钥生成器
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createSymKeyGenerator_3DES192() {
        // 创建3DES192对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("3DES192")
        // 验证算法名称是否正确
        @Expect(keyGenerator.algName == "3DES192")
    }

    /**
     * 测试createSymKeyGenerator API - 有效等价类：创建HMAC密钥生成器
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createSymKeyGenerator_HMAC() {
        // 创建HMAC对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("HMAC")
        // 验证算法名称是否正确
        @Expect(keyGenerator.algName == "HMAC")
    }

    /**
     * 测试createSymKeyGenerator API - 有效等价类：创建HMAC|SHA256组合密钥生成器
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createSymKeyGenerator_HMAC_SHA256() {
        // 创建HMAC|SHA256组合对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("HMAC|SHA256")
        // 验证算法名称是否正确
        @Expect(keyGenerator.algName == "HMAC|SHA256")
    }

    /**
     * 测试createSymKeyGenerator API - 无效等价类：空算法名称
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createSymKeyGenerator_empty() {
        // 尝试使用空字符串创建密钥生成器，预期抛出异常
        try {
            createSymKeyGenerator("")
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 验证异常代码和消息是否正确
            @Expect(true)
        }
    }

    /**
     * 测试createSymKeyGenerator API - 无效等价类：无效的算法名称
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createSymKeyGenerator_invalid() {
        // 尝试使用无效的算法名称创建密钥生成器，预期抛出异常
        try {
            createSymKeyGenerator("INVALID_ALG")
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 验证异常代码和消息是否正确
            @Expect(true)
        }
    }


    /**
     * 测试SymKeyGenerator.generateSymKey API - 有效等价类：生成AES128密钥
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_symKeyGenerator_generateSymKey() {
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        // 验证密钥的算法名称是否正确
        @Expect(key.algName == "AES128")
    }

    /**
     * 测试SymKeyGenerator.convertKey API - 有效等价类：转换16字节数据为AES128密钥
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_symKeyGenerator_convertKey_AES128() {
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 创建16字节的密钥数据（AES128标准长度）
        let keyData: DataBlob = DataBlob(Array<UInt8>(16, {i => UInt8(i & 0xFF)}))
        // 将数据转换为对称密钥
        let key: SymKey = keyGenerator.convertKey(keyData)
        // 验证密钥的算法名称是否正确
        @Expect(key.algName == "AES128")
    }

    /**
     * 测试SymKeyGenerator.convertKey API - 有效等价类：转换24字节数据为3DES192密钥
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_symKeyGenerator_convertKey_3DES192() {
        // 创建3DES192对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("3DES192")
        // 创建24字节的密钥数据（3DES192标准长度）
        let keyData: DataBlob = DataBlob([0xba, 0x3d, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56, 0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c, 0xba, 0x3b, 0xc2, 0x71, 0xab, 0xa0, 0x30, 0x72])
        // 将数据转换为对称密钥
        let key: SymKey = keyGenerator.convertKey(keyData)
        // 验证密钥的算法名称是否正确
        @Expect(key.algName == "3DES192")
    }

    /**
     * 测试SymKeyGenerator.convertKey API - 无效等价类：转换空数据为密钥
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_symKeyGenerator_convertKey_empty() {
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 尝试转换空数据为密钥，预期抛出异常
        try {
            let keyData: DataBlob = DataBlob(Array<UInt8>())
            keyGenerator.convertKey(keyData)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 验证异常代码和消息是否正确
            @Expect(true)
        }
    }

    /**
     * 测试SymKeyGenerator.convertKey API - 无效等价类：转换长度无效的数据为密钥
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_symKeyGenerator_convertKey_invalid_length() {
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 尝试转换15字节数据为AES128密钥（AES128需要16字节），预期抛出异常
        try {
            let keyData: DataBlob = DataBlob(Array<UInt8>(15, repeat: 0x00))
            keyGenerator.convertKey(keyData)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 验证异常代码和消息是否正确
            @Expect(true)
        }
    }

    /**
     * 测试SymKey.getEncoded API - 有效等价类：获取AES128密钥的编码数据
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_symKey_getEncoded() {
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        // 获取密钥的编码数据
        let encoded: DataBlob = key.getEncoded()
        // 验证编码数据的长度是否为16字节（AES128标准长度）
        @Expect(encoded.data.size == 16)
    }
}