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
class Test_SecurityHuks_DeleteKey {
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_delete_key() {
        let keyAlias = "test_delete_key"
        clean(keyAlias)
        try {
            generateSimpleKey(keyAlias)
            @Expect(isKeyItemExist(keyAlias, HuksOptions()))

            deleteKeyItem(keyAlias, HuksOptions())
            @Expect(!isKeyItemExist(keyAlias, HuksOptions()))
        } finally {
            clean(keyAlias)
        }
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_delete_key_not_exist() {
        let keyAlias = "test_delete_key"
        clean(keyAlias)
        var flag = false
        try {
            @Expect(!isKeyItemExist(keyAlias, HuksOptions()))
            deleteKeyItem(keyAlias, HuksOptions())
        } catch (e: BusinessException) {
            flag = true
        } finally {
            @Expect(flag)
            clean(keyAlias)
        }
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_delete_key_empty_alias() {
        let keyAlias = ""
        var flag = false
        try {
            deleteKeyItem(keyAlias, HuksOptions())
        } catch (e: BusinessException) {
            flag = true
        } finally {
            @Expect(flag)
        }
    }
}
