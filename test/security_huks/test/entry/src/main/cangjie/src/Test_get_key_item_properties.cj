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
internal import kit.UniversalKeystoreKit.*
import std.unittest.testmacro.*
import std.unittest.*
import std.unittest.common.*
import std.unittest.testmacro.*
import ohos.base.*

@Test
class Test_SecurityHuks_GetKeyItemProperties {
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_get_key_item_properties() {
        let keyAlias = "test_get_key_item_properties"
        //clean(keyAlias)
        try {
             generateSimpleKey(keyAlias)
            //get properties
             let properties = getKeyItemProperties(keyAlias, HuksOptions())

            // 校验properties是否为空
            @Expect(!properties.isEmpty())
        } finally {
            clean(keyAlias)
        }
    }
   @TestCase
   @Tag[APILevel22, TestLevel0]
   func test_get_key_item_properties_empty_alias() {
       let keyAlias = ""
       var flag = false
       try {
           let properties = getKeyItemProperties(keyAlias, HuksOptions())
       } catch (e: BusinessException) {
           flag = true
       } finally {
           @Expect(flag)
       }
   }
}
