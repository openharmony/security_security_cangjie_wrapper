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
 * 测试ohos.crypto_framework模块的Mac类（消息认证码）操作功能
 */
@Test
class Test_Mac_Operations_Add {
    
    /**
     * 测试Mac.doFinal API - 有效等价类：生成MAC值并验证返回类型
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Mac_doFinal_return_datablob() {
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
        // 完成MAC计算并获取结果
        let result: DataBlob = mac.doFinal()
        
        // 验证MAC结果大小是否大于0
        @Expect(result.data.size > 0)
    }
    
    /**
     * 测试Mac.getMacLength API - 有效等价类：获取SHA256 MAC长度
     */
    /*
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Mac_getMacLength_return_uint32() {
        // 创建SHA256消息认证码实例
        let mac: Mac = createMac("SHA256")
        // 获取MAC长度
        let length: UInt32 = mac.getMacLength()
        
        // 验证MAC长度是否为32字节（SHA256标准长度）
        @Expect(length == 32) // SHA256 MAC长度为32字节
    }*/
    
    
}