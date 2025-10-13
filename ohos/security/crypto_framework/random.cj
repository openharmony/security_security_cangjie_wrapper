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

// The Cangjie API is in Beta. For details on its capabilities and limitations, please refer to the README file.

package ohos.security.crypto_framework

import ohos.ffi.*
import ohos.labels.*

foreign {
    func FfiOHOSCreateRandom(errCode: CPointer<Int32>): Int64

    func FfiOHOSRandomGetAlgName(id: Int64, errCode: CPointer<Int32>): CString

    func FfiOHOSGenerateRandom(id: Int64, numBytes: Int32, errCode: CPointer<Int32>): HcfBlob

    func FfiOHOSSetSeed(id: Int64, seed: CPointer<HcfBlob>, errCode: CPointer<Int32>): Unit
}

/**
 * Create a random generator instance.
 *
 * @returns { Random } returns the created rand instance.
 * @throws { BusinessException } 17620001 - memory operation failed.
 */
@!APILevel[
    22,
    syscap: "SystemCapability.Security.CryptoFramework.Rand"
]
public func createRandom(): Random {
    unsafe {
        var errCode: Int32 = 0
        let id = FfiOHOSCreateRandom(inout errCode)
        checkAndThrow(errCode)
        return Random(id)
    }
}

/**
 * Provides APIs for computing random numbers and setting seeds.
 *
 */
@!APILevel[
    22,
    syscap: "SystemCapability.Security.CryptoFramework.Rand"
]
public class Random <: RemoteDataLite {
    init(id: Int64) {
        super(id)
    }

    ~init() {
        releaseFFIData(myDataId)
    }

    /**
     * Indicates the random generation algorithm name. Currently, only CTR_DRBG is supported.
     *
     */
    @!APILevel[
        22,
        syscap: "SystemCapability.Security.CryptoFramework.Rand"
    ]
    public prop algName: String {
        get() {
            unsafe {
                var errCode: Int32 = 0
                let cstr = FfiOHOSRandomGetAlgName(getID(), inout errCode)
                checkAndThrow(errCode)
                // if free cstr, maybe double free. Please modify after testing.
                return cstr.toString()
            }
        }
    }

    /**
     * Generate random DataBlob by given length synchronously.
     *
     * @param { Int32 } len - indicates the length of random DataBlob.
     * @returns { DataBlob } return the generated random blob.
     * @throws { BusinessException } 401 - Parameter error.
     * @throws { BusinessException } 17620001 - memory operation failed.
     * @throws { BusinessException } 17630001 - crypto operation error.
     */
    @!APILevel[
        22,
        syscap: "SystemCapability.Security.CryptoFramework.Rand"
    ]
    public func generateRandom(len: Int32): DataBlob {
        unsafe {
            var errCode: Int32 = 0
            let returnBlob: HcfBlob = FfiOHOSGenerateRandom(getID(), len, inout errCode)
            checkAndThrow(errCode)
            let blob = returnBlob.toDataBlob()
            returnBlob.free()
            return blob
        }
    }

    /**
     * Set seed by given DataBlob.
     *
     * @param { DataBlob } seed - indicates the seed DataBlob.
     * @throws { BusinessException } 17620001 - memory operation failed.
     */
    @!APILevel[
        22,
        syscap: "SystemCapability.Security.CryptoFramework.Rand"
    ]
    public func setSeed(seed: DataBlob): Unit {
        unsafe {
            let cp = safeMalloc<HcfBlob>(count: 1)
            let chb: HcfBlob
            try {
                chb = HcfBlob(seed)
            } catch (e: Exception) {
                LibC.free(cp)
                throw e
            }
            cp.write(chb)
            var errCode: Int32 = 0
            FfiOHOSSetSeed(getID(), cp, inout errCode)
            chb.free()
            LibC.free(cp)
            checkAndThrow(errCode)
        }
    }
}
