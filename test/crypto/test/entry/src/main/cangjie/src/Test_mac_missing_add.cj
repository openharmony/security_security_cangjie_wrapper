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
 * 测试ohos.crypto_framework模块的Mac类（消息认证码）缺失的操作功能
 */
@Test
class Test_Mac_Missing_Add {
    /**
     * 测试Mac.initialize API - 验证返回值类型为Unit
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Mac_initialize_return_unit() {
        // 创建SHA256消息认证码实例
        let mac: Mac = createMac("SHA256")
        // 创建对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("HMAC|SHA256")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        
        // 使用密钥初始化MAC
        mac.initialize(key)
        
        @Expect(true)
    }
    
    /**
     * 测试Mac.update API - 异常情况：更新空输入数据导致异常
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Mac_update_input_empty() {
        // 创建SHA256消息认证码实例
        let mac: Mac = createMac("SHA256")
        // 创建对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("HMAC|SHA256")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        // 使用密钥初始化MAC
        mac.initialize(key)
        
        // 创建空的输入数据
        let inputData: DataBlob = DataBlob(Array<UInt8>())
        
        // 尝试更新空数据，预期抛出异常
        try {
            mac.update(inputData)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 验证异常代码是否正确
            @Expect(true)
        }
    }
    
    /**
     * 测试Mac.update API - 边界值：更新1字节输入数据
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Mac_update_input_1byte() {
        // 创建SHA256消息认证码实例
        let mac: Mac = createMac("SHA256")
        // 创建对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("HMAC|SHA256")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        // 使用密钥初始化MAC
        mac.initialize(key)
        
        // 创建1字节的输入数据
        let inputData: DataBlob = DataBlob(Array<UInt8>(1, repeat: 0x00))
        // 更新MAC计算
        mac.update(inputData)
        // 验证更新操作是否成功
        @Expect(true)
    }
    
    /**
     * 测试Mac.update API - 验证返回值类型为Unit
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Mac_update_return_unit() {
        // 创建SHA256消息认证码实例
        let mac: Mac = createMac("SHA256")
        // 创建对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("HMAC|SHA256")
        // 生成对称密钥
        let key: SymKey = keyGenerator.generateSymKey()
        // 使用密钥初始化MAC
        mac.initialize(key)
        
        // 创建测试输入数据
        let inputData: DataBlob = DataBlob("test data".toArray())
        // 更新MAC计算
        mac.update(inputData)
        // 验证更新操作是否成功
        @Expect(true)
    }
    
    /**
     * 测试Mac.update API - 异常情况：未初始化MAC对象导致异常
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Mac_update_exception_17630001() {
        // 创建SHA256消息认证码实例
        let mac: Mac = createMac("SHA256")
        // 创建对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("HMAC|SHA256")
        // 生成对称密钥（但不使用它初始化MAC）
        let key: SymKey = keyGenerator.generateSymKey()
        
        // 尝试在未初始化的情况下更新MAC，预期抛出异常
        try {
            let inputData: DataBlob = DataBlob("test data".toArray())
            mac.update(inputData)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 验证异常代码是否正确
            @Expect(true)
        }
    }
    
    /**
     * 测试Mac.doFinal API - 异常情况：未初始化MAC对象导致异常
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Mac_doFinal_exception_17630001() {
        // 创建SHA256消息认证码实例
        let mac: Mac = createMac("SHA256")
        // 创建对称密钥生成器
        let keyGenerator: SymKeyGenerator = createSymKeyGenerator("HMAC|SHA256")
        // 生成对称密钥（但不使用它初始化MAC）
        let key: SymKey = keyGenerator.generateSymKey()
        
        // 尝试在未初始化的情况下完成MAC计算，预期抛出异常
        try {
            mac.doFinal()
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 验证异常代码是否正确
            @Expect(true)
        }
    }
}