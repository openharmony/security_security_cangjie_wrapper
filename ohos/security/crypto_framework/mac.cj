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

import ohos.ffi.{RemoteDataLite, releaseFFIData, safeMalloc}
import ohos.labels.APILevel

foreign {
    func FFiOHOSCryptoMacConstructor(algName: CString, errCode: CPointer<Int32>): Int64

    func FfiOHOSCryptoMacInit(id: Int64, symKeyId: Int64): Int32

    func FfiOHOSCryptoMacUpdate(id: Int64, input: CPointer<HcfBlob>): Int32

    func FfiOHOSCryptoMacDoFinal(id: Int64, errCode: CPointer<Int32>): HcfBlob

    func FfiOHOSCryptoGetMacLength(id: Int64): UInt32
}

/**
 * Creates a Mac instance for MAC operations.
 *
 * @param { string } algName - indicates the mac algorithm name.
 * @returns { Mac } returns the created mac instance.
 * @throws { BusinessException } 401 - invalid parameters. Possible causes: 1. Mandatory parameters are left unspecified;
 * <br>2. Incorrect parameter types; 3. Parameter verification failed.
 * @throws { BusinessException } 17620001 - memory operation failed.
 */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.Mac"
]
public func createMac(algName: String): Mac {
    unsafe {
        let cstr = LibC.mallocCString(algName)
        var errCode: Int32 = 0
        let id = FFiOHOSCryptoMacConstructor(cstr, inout errCode)
        LibC.free(cstr)
        checkAndThrow(errCode)
        return Mac(id, algName)
    }
}

/**
 * Provides the Mac type, which is used for Mac generation.
 * Before using any API of the Mac class, you must create a Mac instance by using createMac.
 *
 */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.Mac"
]
public class Mac <: RemoteDataLite {
    private let _algName: String

    init(id: Int64, algName: String) {
        super(id)
        _algName = algName
    }

    ~init() {
        releaseFFIData(myDataId)
    }

    /**
     * Indicates the algorithm name.
     *
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Mac"
    ]
    public prop algName: String {
        get() {
            return _algName
        }
    }

    /**
     * Init mac with given SymKey.
     * This API uses an asynchronous callback to return the result. init, update, and doFinal must be used together.
     * init and doFinal are mandatory, and update is optional.
     *
     * @param { SymKey } key - indicates the SymKey.
     * @throws { BusinessException } 401 - invalid parameters. Possible causes: 1. Mandatory parameters are left unspecified;	
     * <br>2. Incorrect parameter types; 3. Parameter verification failed.
     * @throws { BusinessException } 17620001 - memory operation failed.
     * @throws { BusinessException } 17630001 - crypto operation error.
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Mac"
    ]
    public func initialize(key: SymKey): Unit {
        unsafe {
            let errCode = FfiOHOSCryptoMacInit(getID(), key.getID())
            checkAndThrow(errCode)
        }
    }

    /**
     * Update mac with DataBlob.
     *
     * @param { DataBlob } input - indicates the DataBlob.
     * @throws { BusinessException } 401 - invalid parameters. Possible causes: 1. Mandatory parameters are left unspecified;	
     * <br>2. Incorrect parameter types; 3. Parameter verification failed.
     * @throws { BusinessException } 17620001 - memory operation failed.
     * @throws { BusinessException } 17630001 - crypto operation error.
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Mac"
    ]
    public func update(input: DataBlob): Unit {
        unsafe {
            let cp = safeMalloc<HcfBlob>()
            let chb: HcfBlob
            try {
                chb = HcfBlob(input)
            } catch (e: Exception) {
                LibC.free(cp)
                throw e
            }
            cp.write(chb)
            let errCode = FfiOHOSCryptoMacUpdate(getID(), cp)
            chb.free()
            LibC.free(cp)
            checkAndThrow(errCode)
        }
    }

    /**
     * Output the result of mac calculation.
     *
     * @throws { BusinessException } 401 - invalid parameters. Possible causes: 1. Mandatory parameters are left unspecified;
     * <br>2. Incorrect parameter types; 3. Parameter verification failed.
     * @throws { BusinessException } 17620001 - memory operation failed.
     * @throws { BusinessException } 17620002 - failed to convert parameters between cj and c.
     * @throws { BusinessException } 17630001 - crypto operation error.
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Mac"
    ]
    public func doFinal(): DataBlob {
        unsafe {
            var errCode: Int32 = 0
            let returnBlob: HcfBlob = FfiOHOSCryptoMacDoFinal(getID(), inout errCode)
            checkAndThrow(errCode)
            let blob = returnBlob.toDataBlob()
            returnBlob.free()
            return blob
        }
    }

    /**
     * Output the length of hmac result.
     *
     * @returns { UInt32 } returns the length of the mac result.
     * @throws { BusinessException } 17630001 - crypto operation error.
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Mac"
    ]
    public func getMacLength(): UInt32 {
        unsafe {
            return FfiOHOSCryptoGetMacLength(getID())
        }
    }
}
