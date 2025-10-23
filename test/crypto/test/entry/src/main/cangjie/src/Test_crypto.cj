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

import kit.CryptoArchitectureKit.*
import ohos.base.*
import std.unittest.testmacro.*
import std.math.numeric.*
import std.runtime.*
import std.sync.*
import std.time.*
import std.unittest.*
import std.unittest.common.*
import std.unittest.testmacro.*
import ohos.business_exception.*

@Test
class Test_crypto {
    override func afterAll(): Unit {
        GC()
        sleep(Duration.second)
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Random(): Unit {
        let random = createRandom()
        @Expect(random.algName, "CTR_DRBG")
        var len = random.generateRandom(1).data[0]
        if (len == 0) {
            len = 1
        }
        random.setSeed(DataBlob([1, 2, 3, 4, 5]))
        @Expect(Int64(len), random.generateRandom(Int32(len)).data.size)
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Mac(): Unit {
        let mac = createMac("SHA256")
        @Expect(mac.algName, "SHA256")
        let skg = createSymKeyGenerator("AES128")
        let sk = skg.generateSymKey()
        mac.initialize(sk)
        let blob = DataBlob("this is test!".toArray())
        mac.update(blob)
        let res = mac.doFinal()
        @Expect(res.data.size, Int64(mac.getMacLength()))
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Md(): Unit {
        let md = createMd("SHA256")
        @Expect(md.algName, "SHA256")
        let message = "mdTestMessgae"
        md.update(DataBlob(message.toArray()))
        let blob = md.digest()
        @Expect(blob.data.size, Int64(md.getMdLength()))
    }


    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_SymKey(): Unit {
        let syg = createSymKeyGenerator("AES128")
        @Expect(syg.algName, "AES128")
        let sk = syg.generateSymKey()
        @Expect(sk.algName, "AES128")
        @Expect(sk.format, "PKCS#8")
        let blob = sk.getEncoded()
        @Expect(blob.data.size, 16)
        sk.clearMem()
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_AES_ECB(): Unit {
        let skg = createSymKeyGenerator("AES128")
        let sk = skg.convertKey(DataBlob([83, 217, 231, 76, 28, 113, 23, 219, 250, 71, 209, 210, 205, 97, 32, 159]))
        let encoder = createCipher("AES128|ECB|PKCS7")
        @Expect(encoder.algName, "AES128|ECB|PKCS7")
        encoder.initialize(CryptoMode.EncryptMode, sk, Option<ParamsSpec>.None)
        let message = "This is a test"
        let blob = DataBlob(message.toArray())
        let encryptText = encoder.doFinal(blob)
        let decoder = createCipher("AES128|ECB|PKCS7")
        decoder.initialize(CryptoMode.DecryptMode, sk, Option<ParamsSpec>.None)
        let decryptData = decoder.doFinal(encryptText)
        @Expect(message, String.fromUtf8(decryptData.data))
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_AES_GCM(): Unit {
        let skg = createSymKeyGenerator("AES128")
        let sk = skg.convertKey(DataBlob([83, 217, 231, 76, 28, 113, 23, 219, 250, 71, 209, 210, 205, 97, 32, 159]))
        let encoder = createCipher("AES128|GCM|PKCS7")
        let ivBlob = DataBlob([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        let aadBlob = DataBlob([0, 0, 0, 0, 0, 0, 0, 0])
        let tagBlob = DataBlob([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        var gcmParamsSpec = GcmParamsSpec("GcmParamsSpec", ivBlob, aadBlob, tagBlob)
        @Expect(gcmParamsSpec.algName, "GcmParamsSpec")
        gcmParamsSpec.algName = "GcmParamsSpec"
        gcmParamsSpec.iv = ivBlob
        gcmParamsSpec.aad = aadBlob
        encoder.initialize(CryptoMode.EncryptMode, sk, gcmParamsSpec)
        let message = "This is a test"
        let blob = DataBlob(message.toArray())
        let encryptText = encoder.update(blob)
        gcmParamsSpec.authTag = encoder.doFinal(Option<DataBlob>.None)
        let decoder = createCipher("AES128|GCM|PKCS7")
        decoder.initialize(CryptoMode.DecryptMode, sk, gcmParamsSpec)
        let decryptData = decoder.update(encryptText)
        decoder.doFinal(Option<DataBlob>.None)
        @Expect(message, String.fromUtf8(decryptData.data))
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_AES_CBC(): Unit {
        let skg = createSymKeyGenerator("AES128")
        let sk = skg.convertKey(DataBlob([83, 217, 231, 76, 28, 113, 23, 219, 250, 71, 209, 210, 205, 97, 32, 159]))
        let encoder = createCipher("AES128|CBC|PKCS7")
        let ivBlob = DataBlob([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        var ivParamsSpec = IvParamsSpec("IvParamsSpec", ivBlob)
        @Expect(ivParamsSpec.algName, "IvParamsSpec")
        ivParamsSpec.algName = "IvParamsSpec"
        ivParamsSpec.iv = ivBlob
        encoder.initialize(CryptoMode.EncryptMode, sk, ivParamsSpec)
        let message = "This is a test"
        let blob = DataBlob(message.toArray())
        let encryptText = encoder.doFinal(blob)
        let decoder = createCipher("AES128|CBC|PKCS7")
        decoder.initialize(CryptoMode.DecryptMode, sk, ivParamsSpec)
        let decryptData = decoder.doFinal(encryptText)
        @Expect(message, String.fromUtf8(decryptData.data))
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_3DES_ECB(): Unit {
        let skg = createSymKeyGenerator("3DES192")
        let sk = skg.convertKey(
            DataBlob([238, 249, 61, 55, 128, 220, 183, 224, 139, 253, 248, 239, 239, 41, 71, 25, 235, 206, 230, 162, 249,
                27, 234, 114]))
        let encoder = createCipher("3DES192|ECB|PKCS7")
        encoder.initialize(CryptoMode.EncryptMode, sk, Option<ParamsSpec>.None)
        let message = "This is a test"
        let blob = DataBlob(message.toArray())
        let encryptText = encoder.doFinal(blob)
        let decoder = createCipher("3DES192|ECB|PKCS7")
        decoder.initialize(CryptoMode.DecryptMode, sk, Option<ParamsSpec>.None)
        let decryptData = decoder.doFinal(encryptText)
        @Expect(message, String.fromUtf8(decryptData.data))
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_SM4_ECB(): Unit {
        let skg = createSymKeyGenerator("SM4_128")
        let sk = skg.convertKey(DataBlob([7, 154, 52, 176, 4, 236, 150, 43, 237, 9, 145, 166, 141, 174, 224, 131]))
        let encoder = createCipher("SM4_128|ECB|PKCS7")
        encoder.initialize(CryptoMode.EncryptMode, sk, Option<ParamsSpec>.None)
        let message = "This is a test"
        let blob = DataBlob(message.toArray())
        let encryptText = encoder.doFinal(blob)
        let decoder = createCipher("SM4_128|ECB|PKCS7")
        decoder.initialize(CryptoMode.DecryptMode, sk, Option<ParamsSpec>.None)
        let decryptData = decoder.doFinal(encryptText)
        @Expect(message, String.fromUtf8(decryptData.data))
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_SM4_CBC(): Unit {
        let skg = createSymKeyGenerator("SM4_128")
        let sk = skg.convertKey(DataBlob([7, 154, 52, 176, 4, 236, 150, 43, 237, 9, 145, 166, 141, 174, 224, 131]))
        let encoder = createCipher("SM4_128|CBC|PKCS7")
        let ivBlob = DataBlob([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        var ivParamsSpec = IvParamsSpec("IvParamsSpec", ivBlob)
        encoder.initialize(CryptoMode.EncryptMode, sk, ivParamsSpec)
        let message = "This is a test"
        let blob = DataBlob(message.toArray())
        let encryptText = encoder.doFinal(blob)
        let decoder = createCipher("SM4_128|CBC|PKCS7")
        decoder.initialize(CryptoMode.DecryptMode, sk, ivParamsSpec)
        let decryptData = decoder.doFinal(encryptText)
        @Expect(message, String.fromUtf8(decryptData.data))
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_SM4_GCM(): Unit {
        let skg = createSymKeyGenerator("SM4_128")
        let sk = skg.convertKey(DataBlob([83, 217, 231, 76, 28, 113, 23, 219, 250, 71, 209, 210, 205, 97, 32, 159]))
        let encoder = createCipher("SM4_128|GCM|PKCS7")
        let ivBlob = DataBlob([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        let aadBlob = DataBlob([0, 0, 0, 0, 0, 0, 0, 0])
        let tagBlob = DataBlob([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        var gcmParamsSpec = GcmParamsSpec("GcmParamsSpec", ivBlob, aadBlob, tagBlob)
        encoder.initialize(CryptoMode.EncryptMode, sk, gcmParamsSpec)
        let message = "This is a test"
        let blob = DataBlob(message.toArray())
        let encryptText = encoder.update(blob)
        gcmParamsSpec.authTag = encoder.doFinal(Option<DataBlob>.None)
        let decoder = createCipher("SM4_128|GCM|PKCS7")
        decoder.initialize(CryptoMode.DecryptMode, sk, gcmParamsSpec)
        let decryptData = decoder.update(encryptText)
        decoder.doFinal(Option<DataBlob>.None)
        @Expect(message, String.fromUtf8(decryptData.data))
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Cipher_AES_CCM(): Unit {
        let skg = createSymKeyGenerator("AES128")
        let sk = skg.convertKey(DataBlob([83, 217, 231, 76, 28, 113, 23, 219, 250, 71, 209, 210, 205, 97, 32, 159]))
        let encoder = createCipher("AES128|CCM|PKCS7")
        let ivBlob = DataBlob([0, 0, 0, 0, 0, 0, 0])
        let aadBlob = DataBlob([0, 0, 0, 0, 0, 0, 0, 0])
        let tagBlob = DataBlob([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        var ccmParamsSpec = CcmParamsSpec("CcmParamsSpec", ivBlob, aadBlob, tagBlob)
        @Expect(ccmParamsSpec.algName, "CcmParamsSpec")
        ccmParamsSpec.algName = "CcmParamsSpec"
        ccmParamsSpec.iv = ivBlob
        ccmParamsSpec.aad = aadBlob
        encoder.initialize(CryptoMode.EncryptMode, sk, ccmParamsSpec)
        let message = "This is a test"
        let blob = DataBlob(message.toArray())
        let encryptText = encoder.update(blob)
        ccmParamsSpec.authTag = encoder.doFinal(Option<DataBlob>.None)
        let decoder = createCipher("AES128|CCM|PKCS7")
        decoder.initialize(CryptoMode.DecryptMode, sk, ccmParamsSpec)
        let decryptData = decoder.update(encryptText)
        decoder.doFinal(Option<DataBlob>.None)
        @Expect(message, String.fromUtf8(decryptData.data))
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_Exception_01(): Unit {
        try {
            createSymKeyGenerator("AES128")
        } catch (e: BusinessException) {
            @Expect(e.code, 801)
            @Expect(e.message, "Capability not supported")
        }
    }

    @TestCase
    @Tag[APILevel22, TestLevel0]
    func test_EnumResult() {
        let enumArray: Array<Result> = [
            InvalidParams,
            NotSupport,
            ErrOutOfMemory,
            ErrRuntimeError,
            ErrCryptoOperation
        ]
        let valArray: Array<Int32> = [
            401,
            801,
            17620001,
            17620002,
            17630001
        ]
        let strArray: Array<String> = [
            "Parameter error.",
            "Capability not supported.",
            "Memory error.",
            "Runtime error.",
            "Crypto operation error."
        ]
        for (i in 0..enumArray.size) {
            @Expect(enumArray[i].getValue() == valArray[i])
            @Expect(enumArray[i].toString() == strArray[i])
        }
    }
}
