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
 * 测试ohos.crypto_framework模块的Md类（消息摘要）操作功能
 */
@Test
class Test_Md_Operations_Add {
    
    /**
     * 测试Md.update API - 边界值：更新1字节输入数据
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Md_update_input_1byte() {
        // 创建SHA256消息摘要实例
        let md: Md = createMd("SHA256")
        // 创建1字节的输入数据
        let inputData: DataBlob = DataBlob(Array<UInt8>(1, repeat: 0x00))
        
        // 更新消息摘要
        md.update(inputData)

        @Expect(true)
    }
    
    /**
     * 测试Md.digest API - 有效等价类：生成SHA256摘要
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Md_digest_return_datablob() {
        // 创建SHA256消息摘要实例
        let md: Md = createMd("SHA256")
        // 创建测试输入数据
        let inputData: DataBlob = DataBlob("test data".toArray())
        // 更新消息摘要
        md.update(inputData)
        
        // 生成消息摘要
        let result: DataBlob = md.digest()
        // 验证摘要长度是否为32字节（SHA256标准长度）
        @Expect(result.data.size == 32) // SHA256摘要长度为32字节
    }
    
    /**
     * 测试Md.getMdLength API - 有效等价类：获取SHA256摘要长度
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Md_getMdLength_return_uint32() {
        // 创建SHA256消息摘要实例
        let md: Md = createMd("SHA256")
        // 获取消息摘要长度
        let length: UInt32 = md.getMdLength()
        
        // 验证摘要长度是否为32字节（SHA256标准长度）
        @Expect(length == 32) // SHA256摘要长度为32字节
    }
    
}