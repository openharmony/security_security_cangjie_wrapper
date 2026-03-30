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
 * 测试ohos.crypto_framework模块的Cipher类操作功能
 */
@Test
class Test_Cipher_Operations_Add {
    /**
     * 测试Cipher.initialize API - 有效等价类：加密模式
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_initialize_opMode_encrypt() {
        // 创建AES128|ECB|PKCS7加密算法实例
        let cipher: Cipher = createCipher("AES128|ECB|PKCS7")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()

        try {
            // 使用加密模式初始化Cipher
            cipher.initialize(CryptoMode.EncryptMode, key, Option<ParamsSpec>.None)
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }
    
    /**
     * 测试Cipher.initialize API - 有效等价类：解密模式
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_initialize_opMode_decrypt() {
        // 创建AES128|ECB|PKCS7加密算法实例
        let cipher: Cipher = createCipher("AES128|ECB|PKCS7")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        
        try {
            // 使用解密模式初始化Cipher
            cipher.initialize(CryptoMode.DecryptMode, key, Option<ParamsSpec>.None)
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }
    
    /**
     * 测试Cipher.initialize API - 有效等价类：有效密钥
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_initialize_key_valid() {
        // 创建AES128|ECB|PKCS7加密算法实例
        let cipher: Cipher = createCipher("AES128|ECB|PKCS7")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成有效的对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        
        try {
            // 使用有效密钥初始化Cipher
            cipher.initialize(CryptoMode.EncryptMode, key, Option<ParamsSpec>.None)  
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }
    
    /**
     * 测试Cipher.initialize API - 有效等价类：使用IvParamsSpec参数
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_initialize_params_IvParamsSpec() {
        // 创建AES128|CBC|PKCS7加密算法实例（需要初始化向量）
        let cipher: Cipher = createCipher("AES128|CBC|PKCS7")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        // 创建16字节的初始化向量
        let iv: DataBlob = DataBlob(Array<UInt8>(16, repeat: 0x00))
        // 创建IvParamsSpec参数
        let ivParams: IvParamsSpec = IvParamsSpec("IvParamsSpec", iv)

        try {
            // 使用IvParamsSpec参数初始化Cipher
            cipher.initialize(CryptoMode.EncryptMode, key, Some(ivParams))
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }
    
    /**
     * 测试Cipher.initialize API - 有效等价类：使用GcmParamsSpec参数
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_initialize_params_GcmParamsSpec() {
        // 创建AES128|GCM|NoPadding加密算法实例（需要GCM参数）
        let cipher: Cipher = createCipher("AES128|GCM|NoPadding")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        // 创建12字节的初始化向量
        let iv: DataBlob = DataBlob(Array<UInt8>(12, repeat: 0x00))
        // 创建8字节的附加认证数据
        let aad: DataBlob = DataBlob(Array<UInt8>(8, repeat: 0x00))
        // 创建16字节的认证标签
        let authTag: DataBlob = DataBlob(Array<UInt8>(16, repeat: 0x00))
        // 创建GcmParamsSpec参数
        let gcmParams: GcmParamsSpec = GcmParamsSpec("GcmParamsSpec", iv, aad, authTag)
        
        try {
            // 使用GcmParamsSpec参数初始化Cipher
            cipher.initialize(CryptoMode.EncryptMode, key, Some(gcmParams))    
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }
    
    /**
     * 测试Cipher.initialize API - 有效等价类：无参数（Option.None）
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_initialize_params_None() {
        // 创建AES128|ECB|PKCS7加密算法实例（不需要额外参数）
        let cipher: Cipher = createCipher("AES128|ECB|PKCS7")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        
        try {
            // 使用Option.None参数初始化Cipher
            cipher.initialize(CryptoMode.EncryptMode, key, Option<ParamsSpec>.None)
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试Cipher.update API - 有效等价类：16字节的输入数据（AES块大小）
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_update_data_valid_16bytes() {
        // 创建AES128|ECB|PKCS7加密算法实例
        let cipher: Cipher = createCipher("AES128|ECB|PKCS7")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        // 初始化加密算法实例
        cipher.initialize(CryptoMode.EncryptMode, key, Option<ParamsSpec>.None)
        
        // 创建16字节的输入数据（刚好是AES的块大小）
        let inputData: DataBlob = DataBlob(Array<UInt8>(16, repeat: 0x00))
        // 更新加密计算
        let result: DataBlob = cipher.update(inputData)
        // 验证结果大小是否有效
        @Expect(result.data.size > 0)
    }
}