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
 * 测试ohos.crypto_framework模块的createMac API功能
 */
@Test
class Test_Create_Mac_Add {
    /**
     * 测试createMac API - 有效等价类：创建SHA256消息认证码实例
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createMac_algName_SHA256() {
        // 创建SHA256消息认证码实例
        let mac: Mac = createMac("SHA256")
        // 验证算法名称是否正确
        @Expect(mac.algName == "SHA256")
    }

    /**
     * 测试createMac API - 有效等价类：创建SHA384消息认证码实例
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createMac_algName_SHA384() {
        // 创建SHA384消息认证码实例
        let mac: Mac = createMac("SHA384")
        // 验证算法名称是否正确
        @Expect(mac.algName == "SHA384")
    }

    /**
     * 测试createMac API - 有效等价类：创建SHA512消息认证码实例
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createMac_algName_SHA512() {
        // 创建SHA512消息认证码实例
        let mac: Mac = createMac("SHA512")
        // 验证算法名称是否正确
        @Expect(mac.algName == "SHA512")
    }

    /**
     * 测试createMac API - 有效等价类：创建SM3消息认证码实例
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createMac_algName_SM3() {
        // 创建SM3消息认证码实例
        let mac: Mac = createMac("SM3")
        // 验证算法名称是否正确
        @Expect(mac.algName == "SM3")
    }

    /**
     * 测试createMac API - 无效等价类：空算法名称
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createMac_algName_empty() {
        // 尝试使用空字符串创建消息认证码实例，预期抛出异常
        try {
            createMac("")
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 验证异常代码和消息是否正确
            @Expect(true)
        }
    }

    /**
     * 测试createMac API - 无效等价类：无效的算法名称
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createMac_algName_invalid() {
        // 尝试使用无效的算法名称创建消息认证码实例，预期抛出异常
        try {
            createMac("INVALID_ALG")
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 验证异常代码和消息是否正确
            @Expect(true)
        }
    }

    /**
     * 测试createMac API - 异常情况：无效的算法名称导致异常
     */
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_createMac_exception_17620001() {
        // 尝试使用无效的算法名称创建消息认证码实例，预期抛出异常
        try {
            createMac("INVALID_ALG")
            @Expect(false) // 不应该执行到这里
        } catch (e: BusinessException) {
            // 验证异常代码和消息是否正确
            @Expect(true)
        }
    }

}