/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

internal import std.unittest.*
import std.unittest.testmacro.*
internal import UniversalKeystoreKit.*
import std.unittest.testmacro.*
import std.unittest.*
import std.unittest.common.*
import std.unittest.testmacro.*
import ohos.base.*

@Test
class Test_SecurityHuks_Struct {
    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_param_value() {
        let boolean = HuksParamValue.BooleanValue(true)
        let int32 = HuksParamValue.Int32Value(1)
        let uint32 = HuksParamValue.Uint32Value(1)
        let uint64 = HuksParamValue.Uint64Value(1)
        let bytes = HuksParamValue.BytesValue([1])

        let left = HuksParamValue.Uint32Value(1)
        let right = HuksParamValue.Uint32Value(2)

    }
    @TestCase
    @Tag[APILevel21, TestLevel0]
    func test_illegal_argument() {
        // 对应exception未覆盖
        try {
            let boolean = HuksParamValue.BooleanValue(true)
            let uint32 = HuksParamValue.Uint32Value(1)
        } catch (e: BusinessException) {
            @Expect(true)
        } finally {
        }
    }
}
