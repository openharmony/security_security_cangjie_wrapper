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
import std.runtime.GC
import std.unittest.*
import std.unittest.common.*
import std.unittest.testmacro.*
import ohos.base.*

@Test
class Test_SecurityHuks_Struct_ffi {
    let HUKS_TAG_ALGORITHM = HuksTag.HUKS_TAG_ALGORITHM// HUKS_TAG_TYPE_UINT
    let HUKS_TAG_IV = HuksTag.HUKS_TAG_IV // HUKS_TAG_TYPE_BYTES
    let HUKS_TAG_IS_KEY_ALIAS = HuksTag.HUKS_TAG_IS_KEY_ALIAS // HUKS_TAG_TYPE_BOOL

    let boolean = HuksParamValue.BooleanValue(true)
    let int32 = HuksParamValue.Int32Value(1)
    let booleanNone = int32
    let int32None = boolean
    let uint32 = HuksParamValue.Uint32Value(1)
    let uint32None = boolean
    let uint64 = HuksParamValue.Uint64Value(1)
    let uint64None = boolean
    let bytes = HuksParamValue.BytesValue([])
    static const HKS_PARAM_SET_MAX_SIZE: Int64 = 4 * 1024 * 1024
    let bytesTooBig = HuksParamValue.BytesValue(Array<Byte>(HKS_PARAM_SET_MAX_SIZE, repeat: 0))
    let bytesNone = boolean

    let huksParamUint32 = HuksParam(HUKS_TAG_ALGORITHM, uint32)
    let huksParamBool = HuksParam(HUKS_TAG_IS_KEY_ALIAS, boolean)
    let huksParamBytes = HuksParam(HUKS_TAG_IV, bytes)
    let huksParamBytesTooBig = HuksParam(HUKS_TAG_IV, bytesTooBig)
    let huksParamUint32None = HuksParam(HUKS_TAG_ALGORITHM, boolean)
    let huksParamBoolNone = HuksParam(HUKS_TAG_IS_KEY_ALIAS, booleanNone)
    let huksParamBytesNone = HuksParam(HUKS_TAG_IV, boolean)

    let properties: Array<HuksParam> = [huksParamUint32, huksParamBool, huksParamBytes]
    let propertiesUint32None = [huksParamUint32None]
    let propertiesBoolNone = [huksParamBoolNone]
    let propertiesBytesNone = [huksParamBytesNone]

    let propertiesTooBig = [huksParamBytesTooBig]
    let propertiesCountTooBig = Array<HuksParam>(100, repeat: huksParamBool)

    let options = HuksOptions(properties: properties, inData: Bytes())
    let optionsUint32None = HuksOptions(properties: propertiesUint32None, inData: Bytes())
    let optionsBoolNone = HuksOptions(properties:propertiesBoolNone, inData: Bytes())
    let optionsBytesNone = HuksOptions(properties:propertiesBytesNone, inData: Bytes())
    let optionsTooBig = HuksOptions(properties:propertiesTooBig,inData: Bytes())
    let optionsCountTooBig = HuksOptions(properties:propertiesCountTooBig, inData: Bytes())
    let optionsNone = HuksOptions()

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_hks_param_set_uint32_none() {
        let keyAlias = "123"
        clean(keyAlias)
        var flag = false
        try {
            generateSimpleKey(keyAlias)
            let res = hasKeyItem(keyAlias, optionsUint32None)
        } catch (e: BusinessException) {
            flag = true
        } finally {
            clean(keyAlias)
            GC()
            @Expect(flag)
        }
    }
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_hks_param_set_bool_none() {
        let keyAlias = "123"
        clean(keyAlias)
        var flag = false
        try {
            let res = hasKeyItem(keyAlias, optionsBoolNone)
        } catch (e: BusinessException) {
            flag = true
        } finally {
            clean(keyAlias)
            GC()
            @Expect(flag)
        }
    }
    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_hks_param_set_bytes_none() {
        let keyAlias = "123"
        clean(keyAlias)
        var flag = false
        try {
            let res = hasKeyItem(keyAlias, optionsBytesNone)
        } catch (e: BusinessException) {
            flag = true
        } finally {
            clean(keyAlias)
            GC()
            @Expect(flag)
        }
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_hks_param_set_too_big() {
        let keyAlias = "123";
        var flag = false
        try {
            generateKeyItem(keyAlias, optionsTooBig)
        } catch (e: BusinessException) {
            flag = true
        }
        @Expect(flag)
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_hks_param_set_count_too_big() {
        let keyAlias = "123";
        var flag = false
        try {
            generateKeyItem(keyAlias, optionsCountTooBig)
        } catch (e: BusinessException) {
            flag = true
        }
        @Expect(flag)
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_hks_param_set_matches() {
        let keyAlias = "123"
        try {
            hasKeyItem(keyAlias,
                HuksOptions(properties: [HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(0))], inData: Bytes()))
        } catch (e: Exception) {
            // ignore
        }
        try {
            hasKeyItem(keyAlias,
                HuksOptions(properties: [HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.BytesValue("123".toArray()))], inData: Bytes())
            )
        } catch (e: Exception) {
            // ignore
        }
//        try {
//            hasKeyItem(keyAlias,
//                HuksOptions([HuksParam(HuksTag.HUKS_TAG_ACTIVE_DATETIME, HuksParamValue.uint64(0))], inData: Bytes()))
//        } catch (e: Exception) {
//            // ignore
//        }
//        try {
//            hasKeyItem(keyAlias,
//                HuksOptions([HuksParam(HuksTag.HUKS_TAG_ACTIVE_DATETIME, HuksParamValue.bytes("123".toArray()))],
//                    inData: Bytes()))
//        } catch (e: Exception) {
//            // ignore
//        }
//        try {
//            hasKeyItem(keyAlias,
//                HuksOptions([HuksParam(HuksTag.HUKS_TAG_SECURE_KEY_ALIAS, HuksParamValue.boolean(true))], inData: Bytes()))
//        } catch (e: Exception) {
//            // ignore
//        }
//        try {
//            hasKeyItem(keyAlias,
//                HuksOptions([HuksParam(HuksTag.HUKS_TAG_SECURE_KEY_ALIAS, HuksParamValue.bytes("123".toArray()))],
//                    inData: Bytes()))
//        } catch (e: Exception) {
//            // ignore
//        }
        return
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_hks_param_set_int32_none() {
        let keyAlias = "test_int32_none"
        clean(keyAlias)
        var flag = false
        try {
            let intTypeTag: UInt32 = UInt32(1) << 28
            let options = HuksOptions(
                properties: [HuksParam(intTypeTag, HuksParamValue.BooleanValue(true))],
                inData: Bytes()
            )
            let res = hasKeyItem(keyAlias, options)
        } catch (e: BusinessException) {
            flag = true
        } finally {
            clean(keyAlias)
            GC()
            @Expect(flag)
        }
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_hks_param_set_uint64_none() {
        let keyAlias = "test_uint64_none"
        clean(keyAlias)
        var flag = false
        try {
            let ulongTypeTag: UInt32 = UInt32(3) << 28
            let options = HuksOptions(
                properties: [HuksParam(ulongTypeTag, HuksParamValue.BooleanValue(true))],
                inData: Bytes()
            )
            let res = hasKeyItem(keyAlias, options)
        } catch (e: BusinessException) {
            flag = true
        } finally {
            clean(keyAlias)
            GC()
            @Expect(flag)
        }
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_hks_param_set_to_pointer_with_bytes() {
        let keyAlias = "test_to_pointer_bytes"
        clean(keyAlias)
        try {
            let options = HuksOptions(
                properties: [
                    HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_AES)),
                    HuksParam(HuksTag.HUKS_TAG_KEY_SIZE, HuksParamValue.Uint32Value(HuksKeySize.HUKS_AES_KEY_SIZE_128)),
                    HuksParam(
                        HuksTag.HUKS_TAG_PURPOSE,
                        HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT)
                    ),
                    HuksParam(HuksTag.HUKS_TAG_IV, HuksParamValue.BytesValue("1122334455667788".toArray())),
                    HuksParam(HuksTag.HUKS_TAG_KEY_AUTH_ID, HuksParamValue.BytesValue("authId_test".toArray()))
                ],
                inData: Bytes()
            )
            generateKeyItem(keyAlias, options)
            @Expect(hasKeyItem(keyAlias, options))
        } finally {
            clean(keyAlias)
            GC()
        }
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_hks_param_set_invalid_tag_type() {
        let keyAlias = "test_invalid_tag_type"
        clean(keyAlias)
        var flag = false
        try {
            let invalidTag: UInt32 = UInt32(0)
            let options = HuksOptions(
                properties: [HuksParam(invalidTag, HuksParamValue.Uint32Value(1))],
                inData: Bytes()
            )
            let res = hasKeyItem(keyAlias, options)
        } catch (e: BusinessException) {
            flag = true
        } finally {
            clean(keyAlias)
            GC()
            @Expect(flag)
        }
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_hks_param_set_unknown_tag_type() {
        let keyAlias = "test_unknown_tag_type"
        clean(keyAlias)
        var flag = false
        try {
            let unknownTypeTag: UInt32 = UInt32(6) << 28
            let options = HuksOptions(
                properties: [HuksParam(unknownTypeTag, HuksParamValue.Uint32Value(1))],
                inData: Bytes()
            )
            let res = hasKeyItem(keyAlias, options)
        } catch (e: BusinessException) {
            flag = true
        } finally {
            clean(keyAlias)
            GC()
            @Expect(flag)
        }
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_hks_param_set_int32_some() {
        let keyAlias = "test_int32_some"
        clean(keyAlias)
        var flag = false
        try {
            let intTypeTag: UInt32 = UInt32(1) << 28
            let options = HuksOptions(
                properties: [HuksParam(intTypeTag, HuksParamValue.Int32Value(1))],
                inData: Bytes()
            )
            let res = hasKeyItem(keyAlias, options)
        } catch (e: BusinessException) {
            flag = true
        } finally {
            clean(keyAlias)
            GC()
            @Expect(flag)
        }
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_hks_param_set_uint32_too_many() {
        let keyAlias = "test_uint32_too_many"
        clean(keyAlias)
        var flag = false
        try {
            let uint32Param = HuksParam(HuksTag.HUKS_TAG_ALGORITHM, HuksParamValue.Uint32Value(1))
            let tooManyUint32 = Array<HuksParam>(100, repeat: uint32Param)
            let options = HuksOptions(properties: tooManyUint32, inData: Bytes())
            let res = hasKeyItem(keyAlias, options)
        } catch (e: BusinessException) {
            flag = true
        } finally {
            clean(keyAlias)
            GC()
            @Expect(flag)
        }
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_hks_param_set_uint64_some() {
        let keyAlias = "test_uint64_some"
        clean(keyAlias)
        var flag = false
        try {
            let ulongTypeTag: UInt32 = UInt32(3) << 28
            let options = HuksOptions(
                properties: [HuksParam(ulongTypeTag, HuksParamValue.Uint64Value(UInt64(1)))],
                inData: Bytes()
            )
            let res = hasKeyItem(keyAlias, options)
        } catch (e: BusinessException) {
            flag = true
        } finally {
            clean(keyAlias)
            GC()
            @Expect(flag)
        }
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_hks_generateKey_error() {
        let keyAlias = "keyAlias1"
        try {
          
            let options = HuksOptions(
                properties: [HuksParam(HuksTag.Huks_TAG_IS_ALLOWED_WRAP, HuksParamValue.BooleanValue(true))],
                inData: Bytes()
            )
            generateKeyItem(keyAlias, options)
        } catch (e: BusinessException) {
           Expect(e.code, 12000002)
        } 
    }
}
