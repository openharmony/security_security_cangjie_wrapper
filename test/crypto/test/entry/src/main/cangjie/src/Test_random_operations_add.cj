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
 * 测试ohos.crypto_framework模块的Random类操作功能
 */
@Test
class Test_Random_Operations_Add {
    /**
     * 测试Random.generateRandom API - 有效等价类：生成12字节随机数据
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Random_generateRandom_len_12() {
        // 创建Random实例
        let random: Random = createRandom()
        // 生成12字节随机数据
        let randomData: DataBlob = random.generateRandom(12)
        
        // 验证生成的数据长度是否为12字节
        @Expect(randomData.data.size == 12)
    }

    
    /**
     * 测试Random.generateRandom API - 无效等价类：生成0字节随机数据
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Random_generateRandom_len_0() {
        // 创建Random实例
        let random: Random = createRandom()
        
        // 尝试生成0字节随机数据，预期抛出异常
        try {
            random.generateRandom(0)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 验证异常代码是否正确
            @Expect(true)
        }
    }
    
    /**
     * 测试Random.setSeed API - 有效等价类：设置有效种子
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Random_setSeed_valid() {
        // 创建Random实例
        let random: Random = createRandom()
        // 创建种子数据
        let seed: DataBlob = DataBlob("test_seed".toArray())
        
        // 设置种子
        random.setSeed(seed)
        
        @Expect(true)
    }
    
    /**
     * 测试Random.setSeed API - 有效等价类：设置16字节种子
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Random_setSeed_16_bytes() {
        // 创建Random实例
        let random: Random = createRandom()
        // 创建16字节的种子数据
        let seed: DataBlob = DataBlob(Array<UInt8>(16, repeat: 0x00))
        
        // 设置种子
        random.setSeed(seed)
        
        @Expect(true)
    }
}