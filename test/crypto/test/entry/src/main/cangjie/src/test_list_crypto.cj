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

let _ = testsuite()

func testsuite(): Unit {
    registerTestSuite("Test_crypto", {=> Test_crypto()})
    registerTestSuite("Test_Cipher_Missing_Add", {=> Test_Cipher_Missing_Add()})
    registerTestSuite("Test_Cipher_Operations_Add", {=> Test_Cipher_Operations_Add()})
    registerTestSuite("Test_Create_Cipher_Add", {=> Test_Create_Cipher_Add()})
    registerTestSuite("Test_Create_Mac_Add", {=> Test_Create_Mac_Add()})
    registerTestSuite("Test_Create_Md_Add", {=> Test_Create_Md_Add()})
    registerTestSuite("Test_Create_Random_Add", {=> Test_Create_Random_Add()})
    registerTestSuite("Test_Create_SymKey_Generator_Add", {=> Test_Create_SymKey_Generator_Add()})
    registerTestSuite("Test_Mac_Missing_Add", {=> Test_Mac_Missing_Add()})
    registerTestSuite("Test_Mac_Operations_Add", {=> Test_Mac_Operations_Add()})
    registerTestSuite("Test_Md_Missing_Add", {=> Test_Md_Missing_Add()})
    registerTestSuite("Test_Md_Operations_Add", {=> Test_Md_Operations_Add()})
    registerTestSuite("Test_Random_Operations_Add", {=> Test_Random_Operations_Add()})
}
