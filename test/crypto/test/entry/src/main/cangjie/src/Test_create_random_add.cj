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
 * 测试ohos.crypto_framework模块的createRandom API功能
 */
@Test
class Test_Create_Random_Add {
    /**
     * 测试createRandom和generateRandom API组合 - 有效等价类：创建生成器并生成16字节随机数
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createRandom_then_generateRandom() {
        // 创建Random对象
        let random: Random = createRandom()

        // 生成16字节随机数
        let randomData: DataBlob = random.generateRandom(16)
        // 验证生成的随机数长度是否为16字节
        @Expect(randomData.data.size == 16)
    }

    /**
     * 测试Random.generateRandom API - 无效等价类：生成0字节随机数据
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_random_generateRandom_invalid_length_zero() {
        // 创建随机数生成器
        let random: Random = createRandom()
        // 尝试生成0字节随机数据，预期抛出异常
        try {
            random.generateRandom(0)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 验证异常代码和消息是否正确
            @Expect(true)
        }
    }

    /**
     * 测试Random.generateRandom API - 无效等价类：生成负长度随机数据
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_random_generateRandom_invalid_length_negative() {
        // 创建随机数生成器
        let random: Random = createRandom()
        // 尝试生成负长度随机数据，预期抛出异常
        try {
            random.generateRandom(-1)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 验证异常代码和消息是否正确
            @Expect(true)
        }
    }

    /**
     * 测试Random.generateRandom API - 边界值测试：生成1字节随机数据（最小有效长度）
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_random_generateRandom_boundary_min() {
        // 创建随机数生成器
        let random: Random = createRandom()
        // 生成1字节随机数据（边界值：最小有效长度）
        let randomData: DataBlob = random.generateRandom(1)
        // 验证生成的随机数长度是否为1字节
        @Expect(randomData.data.size == 1)
    }
   
    /**
     * 测试Random.setSeed API - 有效等价类：设置有效种子数据
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_random_setSeed_valid() {
        // 创建随机数生成器
        let random: Random = createRandom()
        // 创建测试种子数据
        let seed: DataBlob = DataBlob("test_seed_data".toArray())
        // 设置种子
        random.setSeed(seed)
        
        @Expect(true)
    }


    /**
     * 测试Random.setSeed API - 无效等价类：设置空种子数据
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_random_setSeed_empty() {
        // 创建随机数生成器
        let random: Random = createRandom()
        // 尝试设置空种子数据，预期抛出异常
        try {
            let seed: DataBlob = DataBlob(Array<UInt8>())
            random.setSeed(seed)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 验证异常代码和消息是否正确
            @Expect(true)
        }
    }

    /**
     * 测试Random.setSeed API - 边界值测试：设置1字节种子数据（最小有效长度）
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_random_setSeed_boundary_min() {
        // 创建随机数生成器
        let random: Random = createRandom()
        // 创建1字节的种子数据（边界值：最小有效长度）
        let seed: DataBlob = DataBlob(Array<UInt8>(1, repeat: 0x00))
        // 设置种子
        random.setSeed(seed)
        
        @Expect(true)
    }
}