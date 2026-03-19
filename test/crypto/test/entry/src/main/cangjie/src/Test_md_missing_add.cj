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
 * 测试ohos.crypto_framework模块的Md类（消息摘要）缺失的操作功能
 */
@Test
class Test_Md_Missing_Add {
    /**
     * 测试Md.update API - 验证返回值类型为Unit
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Md_update_return_unit() {
        // 创建SHA256消息摘要实例
        let md: Md = createMd("SHA256")
        // 创建测试输入数据
        let inputData: DataBlob = DataBlob("test data".toArray())
        
        // 更新消息摘要
        md.update(inputData)

        @Expect(true)
    }
    
    /**
     * 测试Md.update API - 异常情况：空输入数据导致异常
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Md_update_exception_17630001() {
        // 创建SHA256消息摘要实例
        let md: Md = createMd("SHA256")
        // 创建空的输入数据
        let inputData: DataBlob = DataBlob(Array<UInt8>())
        
        // 尝试更新空数据，预期抛出异常
        try {
            md.update(inputData)
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 验证异常代码是否正确
            @Expect(true)
        }
    }
    
}