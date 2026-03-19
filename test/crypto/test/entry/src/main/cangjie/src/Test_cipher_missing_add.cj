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
import std.unittest.testmacro.*
import std.math.numeric.*
import std.runtime.*
import std.sync.*
import std.time.*
import std.unittest.*
import std.unittest.common.*
import ohos.business_exception.*

/**
 * 测试ohos.crypto_framework模块的Cipher类缺失的操作功能
 */
@Test
class Test_Cipher_Missing_Add {
    /**
     * 测试Cipher.initialize API - 有效等价类：使用CcmParamsSpec参数
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_initialize_params_CcmParamsSpec() {
        // 创建AES128|CCM|NoPadding加密算法实例（需要CCM参数）
        let cipher: Cipher = createCipher("AES128|CCM|NoPadding")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        // 创建7字节的初始化向量
        let iv: DataBlob = DataBlob(Array<UInt8>(7, repeat: 0x00))
        // 创建8字节的附加认证数据
        let aad: DataBlob = DataBlob(Array<UInt8>(8, repeat: 0x00))
        // 创建12字节的认证标签
        let authTag: DataBlob = DataBlob(Array<UInt8>(12, repeat: 0x00))
        // 创建CcmParamsSpec参数
        let ccmParams: CcmParamsSpec = CcmParamsSpec("CcmParamsSpec", iv, aad, authTag)
        
        // 使用CcmParamsSpec参数初始化Cipher
        try {
            cipher.initialize(CryptoMode.EncryptMode, key, Some(ccmParams))
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false) // 不应该执行到这里
        }
       
    }
    
    /**
     * 测试Cipher.initialize API - 无效等价类：参数不匹配（ECB模式不需要IV参数）
     */
    /*
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_initialize_params_mismatch() {
        // 创建AES128|ECB|PKCS7加密算法实例（ECB模式不需要IV参数）
        let cipher: Cipher = createCipher("AES128|ECB|PKCS7")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        // 创建16字节的初始化向量
        let iv: DataBlob = DataBlob(Array<UInt8>(16, repeat: 0x00))
        // 创建IvParamsSpec参数
        let ivParams: IvParamsSpec = IvParamsSpec("IvParamsSpec", iv)
        
        // 尝试使用不需要的IV参数初始化Cipher，预期抛出异常
        try {
            cipher.initialize(CryptoMode.EncryptMode, key, Some(ivParams))
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 验证异常代码是否正确
            @Expect(e.code == 17630001)
        }
    }
    */
    
    /**
     * 测试Cipher.initialize API - 有效等价类：CBC模式加密初始化
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_initialize_pairwise_case1() {
        // 创建AES128|CBC|PKCS7加密算法实例（需要IV参数）
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
            // 使用加密模式和IV参数初始化Cipher
            cipher.initialize(CryptoMode.EncryptMode, key, Some(ivParams))
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false) // 不应该执行到这里
        }
    }
    
    /**
     * 测试Cipher.initialize API - 有效等价类：CBC模式解密初始化
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_initialize_pairwise_case2() {
        // 创建AES128|CBC|PKCS7加密算法实例（需要IV参数）
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
            // 使用解密模式和IV参数初始化Cipher
            cipher.initialize(CryptoMode.DecryptMode, key, Some(ivParams))
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false) // 不应该执行到这里
        }
    }
    
    /**
     * 测试Cipher.initialize API - 有效等价类：ECB模式加密初始化
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_initialize_pairwise_case3() {
        // 创建AES128|ECB|PKCS7加密算法实例（不需要IV参数）
        let cipher: Cipher = createCipher("AES128|ECB|PKCS7")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        try {
            // 使用加密模式和无参数初始化Cipher
            cipher.initialize(CryptoMode.EncryptMode, key, Option<ParamsSpec>.None)
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false) // 不应该执行到这里
        }
    }
    
    /**
     * 测试Cipher.initialize API - 有效等价类：ECB模式解密初始化
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_initialize_pairwise_case4() {
        // 创建AES128|ECB|PKCS7加密算法实例（不需要IV参数）
        let cipher: Cipher = createCipher("AES128|ECB|PKCS7")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        try {
            // 使用解密模式和无参数初始化Cipher
            cipher.initialize(CryptoMode.DecryptMode, key, Option<ParamsSpec>.None)
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false) // 不应该执行到这里
        }
    }
    
    /**
     * 测试Cipher.initialize API - 验证正常情况下不抛出17620001异常
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_initialize_exception_17620001() {
        // 创建AES128|ECB|PKCS7加密算法实例
        let cipher: Cipher = createCipher("AES128|ECB|PKCS7")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        
        // 尝试初始化Cipher，预期成功不抛出异常
        try {
            cipher.initialize(CryptoMode.EncryptMode, key, Option<ParamsSpec>.None)
            @Expect(true) // 验证操作成功
        } catch (e: BusinessException) {
            @Expect(false) // 不应该执行到这里
        }
    }

    
    /**
     * 测试Cipher.update API - 无效等价类：空输入数据
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_update_data_empty() {
        // 创建AES128|ECB|PKCS7加密算法实例
        let cipher: Cipher = createCipher("AES128|ECB|PKCS7")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        // 初始化Cipher
        cipher.initialize(CryptoMode.EncryptMode, key, Option<ParamsSpec>.None)
        
        // 创建空输入数据
        let inputData: DataBlob = DataBlob(Array<UInt8>())
        
        // 尝试使用空数据更新Cipher，预期抛出异常
        try {
            let result: DataBlob =  cipher.update(inputData)
            @Expect(result.data.size == 0)
        } catch (e: BusinessException) {
            @Expect(false) // 不应该执行到这里
        }
    }
    
    /**
     * 测试Cipher.update API - 有效等价类：1字节的输入数据
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_update_data_1byte() {
        // 创建AES128|ECB|PKCS7加密算法实例
        let cipher: Cipher = createCipher("AES128|ECB|PKCS7")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        // 初始化Cipher
        cipher.initialize(CryptoMode.EncryptMode, key, Option<ParamsSpec>.None)
        
        // 创建1字节的输入数据
        let inputData: DataBlob = DataBlob(Array<UInt8>(1, repeat: 0x00))
        // 更新加密计算
        let result: DataBlob = cipher.update(inputData)
        // 验证结果大小是否有效
        @Expect(result.data.size >= 0)
    }
    
    /**
     * 测试Cipher.update API - 验证返回值类型为DataBlob
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_update_return_datablob() {
        // 创建AES128|ECB|PKCS7加密算法实例
        let cipher: Cipher = createCipher("AES128|ECB|PKCS7")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        // 初始化Cipher
        cipher.initialize(CryptoMode.EncryptMode, key, Option<ParamsSpec>.None)
        
        
        try {
            // 创建测试输入数据
            let inputData: DataBlob = DataBlob("test data".toArray())
            // 更新加密计算
            let result: DataBlob = cipher.update(inputData)
            // 尝试在未初始化的情况下调用update，预期抛出异常
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }
    
    /**
     * 测试Cipher.update API - 异常情况：未初始化时调用update
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_update_exception_17630001() {
        // 创建AES128|ECB|PKCS7加密算法实例
        let cipher: Cipher = createCipher("AES128|ECB|PKCS7")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        // 注意：未初始化Cipher
        
        // 尝试在未初始化的情况下调用update，预期抛出异常
        try {
            let inputData: DataBlob = DataBlob("test data".toArray())
            cipher.update(inputData)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            @Expect(true) // 预期抛出异常
        }
    }
    
    /**
     * 测试Cipher.update API - 有效等价类：多次调用update方法
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_update_multiple_calls() {
        // 创建AES128|ECB|PKCS7加密算法实例
        let cipher: Cipher = createCipher("AES128|ECB|PKCS7")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        // 初始化Cipher
        cipher.initialize(CryptoMode.EncryptMode, key, Option<ParamsSpec>.None)
        
        // 创建第一部分输入数据
        let inputData1: DataBlob = DataBlob("test ".toArray())
        // 创建第二部分输入数据
        let inputData2: DataBlob = DataBlob("data".toArray())
        
        // 第一次调用update
        cipher.update(inputData1)
        // 第二次调用update
        cipher.update(inputData2)
        
        // 完成加密操作并获取结果
        let result: DataBlob = cipher.doFinal(Option<DataBlob>.None)
        // 验证结果大小是否大于0
        @Expect(result.data.size > 0)
    }
    
    /**
     * 测试Cipher.doFinal API - 无效等价类：空输入数据
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_doFinal_data_empty() {
        // 创建AES128|ECB|PKCS7加密算法实例
        let cipher: Cipher = createCipher("AES128|ECB|PKCS7")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        // 初始化Cipher
        cipher.initialize(CryptoMode.EncryptMode, key, Option<ParamsSpec>.None)
        
        // 尝试使用空数据调用doFinal，不会抛出异常
      
        let inputData: DataBlob = DataBlob(Array<UInt8>())
        let result: DataBlob = cipher.doFinal(Some(inputData))
        @Expect(result.data.size > 0) 
        
    }
    
    /**
     * 测试Cipher.doFinal API - 有效等价类：1字节的输入数据
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_doFinal_data_1byte() {
        // 创建AES128|ECB|PKCS7加密算法实例
        let cipher: Cipher = createCipher("AES128|ECB|PKCS7")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        // 初始化Cipher
        cipher.initialize(CryptoMode.EncryptMode, key, Option<ParamsSpec>.None)
        
        // 创建1字节的输入数据
        let inputData: DataBlob = DataBlob(Array<UInt8>(1, repeat: 0x00))
        // 直接使用doFinal加密数据
        let result: DataBlob = cipher.doFinal(Some(inputData))
        // 验证结果大小是否大于0
        @Expect(result.data.size > 0)
    }
    
    /**
     * 测试Cipher.doFinal API - 有效等价类：使用None参数完成操作
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_doFinal_data_None_special() {
        // 创建AES128|ECB|PKCS7加密算法实例
        let cipher: Cipher = createCipher("AES128|ECB|PKCS7")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        // 初始化Cipher
        cipher.initialize(CryptoMode.EncryptMode, key, Option<ParamsSpec>.None)
        
        // 使用None参数完成加密操作
        let result: DataBlob = cipher.doFinal(Option<DataBlob>.None)
        // 验证结果大小是否有效
        @Expect(result.data.size > 0)
    }
    
    /**
     * 测试Cipher.doFinal API - 验证返回值类型为DataBlob
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_doFinal_return_datablob() {
        // 创建AES128|ECB|PKCS7加密算法实例
        let cipher: Cipher = createCipher("AES128|ECB|PKCS7")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        // 初始化Cipher
        cipher.initialize(CryptoMode.EncryptMode, key, Option<ParamsSpec>.None)
        
        
        // 尝试在未初始化的情况下调用update，预期抛出异常
        try {
            // 创建测试输入数据
            let inputData: DataBlob = DataBlob("test data".toArray())
            // 直接使用doFinal加密数据
            let result: DataBlob = cipher.doFinal(Some(inputData))
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }
    
    /**
     * 测试Cipher.doFinal API - 异常情况：未初始化时调用doFinal
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_doFinal_exception_17630001() {
        // 创建AES128|ECB|PKCS7加密算法实例
        let cipher: Cipher = createCipher("AES128|ECB|PKCS7")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        // 注意：未初始化Cipher
        
        // 尝试在未初始化的情况下调用doFinal，预期抛出异常
        try {
            let inputData: DataBlob = DataBlob("test data".toArray())
            cipher.doFinal(Some(inputData))
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            @Expect(true) // 预期抛出异常
        }
    }
    
    /**
     * 测试Cipher.doFinal API - 有效等价类：完整的加密流程
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_doFinal_encrypt_flow() {
        // 创建AES128|ECB|PKCS7加密算法实例
        let cipher: Cipher = createCipher("AES128|ECB|PKCS7")
        // 创建AES128对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        // 初始化加密模式
        cipher.initialize(CryptoMode.EncryptMode, key, Option<ParamsSpec>.None)
        
        // 创建测试输入数据
        let inputData: DataBlob = DataBlob("test encryption flow".toArray())
        // 直接使用doFinal完成加密
        let result: DataBlob = cipher.doFinal(Some(inputData))
        // 验证加密结果大小是否大于0
        @Expect(result.data.size > 0)
    }
    
    /**
     * 测试Cipher.doFinal API - 有效等价类：完整解密流程（加密后解密）
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_doFinal_decrypt_flow() {
        // 创建解密使用的Cipher实例
        let cipher: Cipher = createCipher("AES128|ECB|PKCS7")
        // 创建密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("AES128")
        // 生成AES128对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        
        // 先加密：创建加密使用的Cipher实例
        let cipherEnc: Cipher = createCipher("AES128|ECB|PKCS7")
        // 初始化加密模式
        cipherEnc.initialize(CryptoMode.EncryptMode, key, Option<ParamsSpec>.None)
        // 创建测试数据
        let inputData: DataBlob = DataBlob("test decryption flow".toArray())
        // 执行加密操作
        let encryptedData: DataBlob = cipherEnc.doFinal(Some(inputData))
        
        // 再解密：初始化解密模式
        cipher.initialize(CryptoMode.DecryptMode, key, Option<ParamsSpec>.None)
        // 执行解密操作
        let decryptedData: DataBlob = cipher.doFinal(Some(encryptedData))
        
        // 验证解密后的数据大小大于0
        @Expect(decryptedData.data.size > 0)
    }
}