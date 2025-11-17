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

package ohos.security.huks

import ohos.labels.APILevel
import std.collection.{ collectArray, forEach, map}
import ohos.business_exception.BusinessException

/**
 * Checks whether a key exists.
 *
 * @param { String } keyAlias - Alias of the key to check.
 * @param { HuksOptions } options - Options for checking the key. For example, you can pass in HuksAuthStorageLevel to
 * specify the security level of the key to check. HuksAuthStorageLevel can be left empty, which means the default
 * value HUKS_AUTH_STORAGE_LEVEL_DE is used.
 * @returns { Bool } Used to return the result. If the key exists, then() performs subsequent
 * @throws { BusinessException } 801 - api is not supported
 * @throws { BusinessException } 12000004 - operating file failed
 * @throws { BusinessException } 12000005 - IPC communication failed
 * @throws { BusinessException } 12000006 - error occurred in crypto engine
 * @throws { BusinessException } 12000011 - queried entity does not exist
 * @throws { BusinessException } 12000012 - Device environment or input parameter abnormal
 * @throws { BusinessException } 12000014 - memory is insufficient
 */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension",
    throwexception: true,
    workerthread: true
]
public func hasKeyItem(keyAlias: String, options: HuksOptions): Bool {
    if (keyAlias.isEmpty()) {
        throw BusinessException(HuksExceptionErrCode.HuksErrCodeIllegalArgument.getValue(), "key alias is empty")
    }

    let paramSet: Option<HksParamSet> = if (!options.properties.isEmpty()) {
        // may throw exception
        HksParamSet(options.properties)
    } else {
        None
    }

    let keyAliasCstr = unsafe { LibC.mallocCString(keyAlias) }

    let retCode: Int32 = if (let Some(_paramSet) <- paramSet) {
        unsafe { FfiOHOSIsKeyExist(keyAliasCstr, _paramSet.toPointer()) }
    } else {
        unsafe { FfiOHOSIsKeyExist(keyAliasCstr, CPointer()) }
    }

    try {
        if (retCode == HKS_SUCCESS) {
            return true
        } else if (retCode == HKS_ERROR_NOT_EXIST) {
            return false
        } else {
            throw hksCodeToException(retCode)
        }
    } finally {
        unsafe {
            LibC.free(keyAliasCstr)
        }
    }
}

/**
 * Obtains key properties.
 *
 * @param { String } keyAlias - Key alias, which must be the same as the alias used when the key was generated.
 * @param { HuksOptions } _ - Empty object (leave this parameter empty).
 * @returns { Array<HuksParam> } Used to return the result. If the operation is successful,
 * properties in Array<HuksParam> holds the parameters required for generating the key.
 * @throws { BusinessException } 801 - api is not supported
 * @throws { BusinessException } 12000001 - algorithm mode is not supported
 * @throws { BusinessException } 12000004 - operating file failed
 * @throws { BusinessException } 12000005 - IPC communication failed
 * @throws { BusinessException } 12000006 - error occurred in crypto engine
 * @throws { BusinessException } 12000011 - queried entity does not exist
 * @throws { BusinessException } 12000012 - Device environment or input parameter abnormal
 * @throws { BusinessException } 12000014 - memory is insufficient
 */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension",
    throwexception: true,
    workerthread: true
]
public func getKeyItemProperties(keyAlias: String, _: HuksOptions): Array<HuksParam> {
    // options is a reserved parameter and does not need to be processed currently.
    if (keyAlias.isEmpty()) {
        throw BusinessException(HuksExceptionErrCode.HuksErrCodeIllegalArgument.getValue(), "key alias is empty")
    }

    let outParamSet = ReadOnlyHksParamSet(HKS_DEFAULT_OUTPARAMSET_SIZE)

    let keyAliasCstr = unsafe { LibC.mallocCString(keyAlias) }

    let retCode = unsafe {
        FfiOHOSGetKeyItemProperties(keyAliasCstr, CPointer(), outParamSet.toPointer())
    }

    try {
        if (retCode == HKS_SUCCESS) {
            let retParamArray: Array<HuksParam> = outParamSet.collectData()
            retParamArray
        } else {
            throw hksCodeToException(retCode)
        }
    } finally {
        unsafe {
            LibC.free(keyAliasCstr)
        }
    }
}

/**
 * Obtains the certificate for anonymous attestation. This
 * operation requires Internet access and takes time. If error code 12000012 is returned, the network is abnormal. If
 * the device is not connected to the network, display a message, indicating that the network is not connected. If the
 * network is connected, the failure may be caused by network jitter. Try again later.
 *
 * @param { String } keyAlias - Alias of the key. The certificate to be obtained stores the key.
 * @param { HuksOptions } options - Parameters and data required for obtaining the certificate.
 * @returns { Array<String> } Used to return the result. If the operation is successful,
 * certChains in Array<String> is the certificate chain obtained.
 * @throws { BusinessException } 201 - check permission failed
 * @throws { BusinessException } 801 - api is not supported
 * @throws { BusinessException } 12000001 - algorithm mode is not supported
 * @throws { BusinessException } 12000004 - operating file failed
 * @throws { BusinessException } 12000005 - IPC communication failed
 * @throws { BusinessException } 12000006 - error occurred in crypto engine
 * @throws { BusinessException } 12000011 - queried entity does not exist
 * @throws { BusinessException } 12000012 - Device environment or input parameter abnormal
 * @throws { BusinessException } 12000014 - memory is insufficient
 */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension",
    throwexception: true,
    workerthread: true
]
public func anonAttestKeyItem(keyAlias: String, options: HuksOptions): Array<String> {
    if (keyAlias.isEmpty()) {
        throw BusinessException(HuksExceptionErrCode.HuksErrCodeIllegalArgument.getValue(), "key alias is empty")
    }

    if (options.properties.isEmpty()) {
       throw BusinessException(HuksExceptionErrCode.HuksErrCodeIllegalArgument.getValue(), "properties is None")
    } 
    let properties = options.properties

    let propertiesPlus = Array<HuksParam>(
        properties.size + 1,
        {
            i => if (i < properties.size) {
                properties[i]
            } else {
                HuksParam(HuksTag.HUKS_ATTESTATION_BASE64, HuksParamValue.BooleanValue(true))
            }
        }
    )

    let paramSet: HksParamSet = HksParamSet(propertiesPlus)

    let keyAliasCstr = unsafe { LibC.mallocCString(keyAlias) }

    const HKS_CERT_COUNT: UInt32 = 3
    const HKS_CERT_SIZE: UInt32 = 4096

    let certBlobArray = unsafe {
        [
            OhosHksBlob.malloc(HKS_CERT_SIZE),
            OhosHksBlob.malloc(HKS_CERT_SIZE),
            OhosHksBlob.malloc(HKS_CERT_SIZE)
        ]
    }
    let certBlobPtr = unsafe { acquireArrayRawData(certBlobArray) }
    var certChain = OhosHksCertChain(certBlobPtr.pointer, HKS_CERT_COUNT)

    let retCode = unsafe { FfiOHOSHAnonAttestKey(keyAliasCstr, paramSet.toPointer(), inout certChain) }
    unsafe { releaseArrayRawData(certBlobPtr) }

    try {
        if (retCode == HKS_SUCCESS) {
            let ret: Array<String> = certBlobArray |> map({blob: OhosHksBlob => blob.toString()}) |> collectArray
            ret
        } else {
            throw hksCodeToException(retCode)
        }
    } finally {
        unsafe {
            LibC.free(keyAliasCstr)
            certBlobArray |> forEach({blob: OhosHksBlob => blob.free()})
        }
    }
}

/**
 * Exports a key. This API uses a Array<UInt8> to return the result.
 *
 * @param { String } keyAlias - Key alias, which must be the same as the alias used when the key was generated.
 * @param { HuksOptions } _ - Empty object (leave this parameter empty).
 * @returns { Bytes } Used to return the result. If the operation is successful, outData
 * in Bytes is the public key exported.
 * @throws { BusinessException } 801 - api is not supported
 * @throws { BusinessException } 12000001 - algorithm mode is not supported
 * @throws { BusinessException } 12000004 - operating file failed
 * @throws { BusinessException } 12000005 - IPC communication failed
 * @throws { BusinessException } 12000006 - error occurred in crypto engine
 * @throws { BusinessException } 12000011 - queried entity does not exist
 * @throws { BusinessException } 12000012 - Device environment or input parameter abnormal
 * @throws { BusinessException } 12000014 - memory is insufficient
 */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension",
    throwexception: true,
    workerthread: true
]
public func exportKeyItem(keyAlias: String, _: HuksOptions): Bytes {
    if (keyAlias.isEmpty()) {
        throw BusinessException(HuksExceptionErrCode.HuksErrCodeIllegalArgument.getValue(), "key alias is empty")
    }

    let keyAliasCstr = unsafe { LibC.mallocCString(keyAlias) }

    var outData: OhosHksBlob
    try {
        outData = unsafe { OhosHksBlob.malloc(MAX_KEY_SIZE) }
    } catch (e: Exception) {
        unsafe { LibC.free(keyAliasCstr) }
        throw e
    }

    let retCode = unsafe {
        FfiOHOSExportKey(keyAliasCstr, CPointer(), inout outData)
    }

    try {
        if (retCode == HKS_SUCCESS) {
            let ret = outData.copyToBytes()
            ret
        } else {
            throw hksCodeToException(retCode)
        }
    } finally {
        unsafe {
            LibC.free(keyAliasCstr)
            outData.free()
        }
    }
}

/**
 * Imports a wrapped key.
 *
 * @param { String } keyAlias - Alias of the wrapped key to import.
 * @param { String } wrappingKeyAlias - Alias of the data used to unwrap the key imported.
 * @param { HuksOptions } options - Tags required for the import and the wrapped key to import. The algorithm, key
 * purpose, and key length are mandatory.
 * @throws { BusinessException } 201 - check permission failed
 * @throws { BusinessException } 801 - api is not supported
 * @throws { BusinessException } 12000001 - algorithm mode is not supported
 * @throws { BusinessException } 12000002 - algorithm param is missing
 * @throws { BusinessException } 12000003 - algorithm param is invalid
 * @throws { BusinessException } 12000004 - operating file failed
 * @throws { BusinessException } 12000005 - IPC communication failed
 * @throws { BusinessException } 12000006 - error occurred in crypto engine
 * @throws { BusinessException } 12000011 - queried entity does not exist
 * @throws { BusinessException } 12000012 - Device environment or input parameter abnormal
 * @throws { BusinessException } 12000013 - queried credential does not exist
 * @throws { BusinessException } 12000014 - memory is insufficient
 * @throws { BusinessException } 12000015 - Failed to obtain the security information via UserIAM
 * @throws { BusinessException } 12000017 - The key with same alias is already exist
 */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension",
    throwexception: true,
    workerthread: true
]
public func importWrappedKeyItem(keyAlias: String, wrappingKeyAlias: String, options: HuksOptions): Unit {
    if (keyAlias.isEmpty()) {
        throw BusinessException(HuksExceptionErrCode.HuksErrCodeIllegalArgument.getValue(), "key alias is empty")
    }

    if (options.properties.isEmpty()) {
        throw BusinessException(HuksExceptionErrCode.HuksErrCodeIllegalArgument.getValue(), "properties is None")
    } 
    let properties = options.properties
    
    let paramSet: HksParamSet = HksParamSet(properties)

     if (options.inData.isEmpty()) {
        throw BusinessException(HuksExceptionErrCode.HuksErrCodeIllegalArgument.getValue(), "properties is None")
    } 
    let inData = options.inData

    try (
        keyAliasCstr = unsafe { LibC.mallocCString(keyAlias).asResource() },
        wrappingKeyAliasCstr = unsafe { LibC.mallocCString(wrappingKeyAlias).asResource() }
    ) {
        var wrappedData: OhosHksBlob = unsafe { OhosHksBlob.mallocFromBytes(inData) }

        let retCode = unsafe {
            FfiOHOSImportWrappedKey(keyAliasCstr.value, wrappingKeyAliasCstr.value, paramSet.toPointer(),
                inout wrappedData)
        }

        try {
            if (retCode != HKS_SUCCESS) {
                throw hksCodeToException(retCode)
            }
        } finally {
            unsafe {
                wrappedData.free()
            }
        }
    }
}

/**
 * Generates a key. Because the key is always
 * protected in a trusted environment (such as a TEE), the result does not return the key content.
 * It returns only the information indicating whether the API is successfully called.
 *
 * @param { String } keyAlias - keyAlias indicates the key's name.
 * @param { HuksOptions } options - Tags required for generating the key. The algorithm, key purpose,
 * and key length are mandatory.
 * @throws { BusinessException } 801 - api is not supported
 * @throws { BusinessException } 12000001 - algorithm mode is not supported
 * @throws { BusinessException } 12000002 - algorithm param is missing
 * @throws { BusinessException } 12000003 - algorithm param is invalid
 * @throws { BusinessException } 12000004 - operating file failed
 * @throws { BusinessException } 12000005 - IPC communication failed
 * @throws { BusinessException } 12000006 - error occured in crypto engine
 * @throws { BusinessException } 12000012 - Device environment or input parameter abnormal
 * @throws { BusinessException } 12000013 - queried credential does not exist
 * @throws { BusinessException } 12000014 - memory is insufficient
 * @throws { BusinessException } 12000015 - Failed to obtain the security information via UserIAM
 * @throws { BusinessException } 12000017 - The key with same alias is already exist
 */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension",
    throwexception: true,
    workerthread: true
]
public func generateKeyItem(keyAlias: String, options: HuksOptions): Unit {
    if (keyAlias.isEmpty()) {
        throw BusinessException(HuksExceptionErrCode.HuksErrCodeIllegalArgument.getValue(), "key alias is empty")
    }

    if (options.properties.isEmpty()) {
        throw BusinessException(HuksExceptionErrCode.HuksErrCodeIllegalArgument.getValue(), "properties is None")
    }
    let properties = options.properties

    var paramSetIn: HksParamSet = HksParamSet(properties)

    let keyAliasCstr: CString = unsafe { LibC.mallocCString(keyAlias) }

    let retCode = unsafe {
        FfiOHOSGenerateKey(keyAliasCstr, paramSetIn.toPointer(), CPointer())
    }

    try {
        if (retCode != HKS_SUCCESS) {
            throw hksCodeToException(retCode)
        }
    } finally {
        unsafe {
            LibC.free(keyAliasCstr)
        }
    }
}

/**
 * Deletes a key.
 *
 * @param { String } keyAlias - Alias of the key to delete. It must be the key alias passed in when the key
 * was generated.
 * @param { HuksOptions } options - Options for deleting the key. For example, you can pass in HuksAuthStorageLevel to
 * specify the security level of the key to delete. HuksAuthStorageLevel can be left empty, which means the default
 * value HUKS_AUTH_STORAGE_LEVEL_DE is used.
 * @throws { BusinessException } 801 - api is not supported
 * @throws { BusinessException } 12000004 - operating file failed
 * @throws { BusinessException } 12000005 - IPC communication failed
 * @throws { BusinessException } 12000011 - queried entity does not exist
 * @throws { BusinessException } 12000012 - Device environment or input parameter abnormal
 * @throws { BusinessException } 12000014 - memory is insufficient
 */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension",
    throwexception: true,
    workerthread: true
]
public func deleteKeyItem(keyAlias: String, options: HuksOptions): Unit {
    if (keyAlias.isEmpty()) {
        throw BusinessException(HuksExceptionErrCode.HuksErrCodeIllegalArgument.getValue(), "key alias is empty")
    }

    let paramSet: Option<HksParamSet> = if (!options.properties.isEmpty()) {
        // may throw exception
        HksParamSet(options.properties)
    } else {
        None
    }

    let keyAliasCstr: CString = unsafe { LibC.mallocCString(keyAlias) }

    let retCode: Int32 = if (let Some(_paramSet) <- paramSet) {
        unsafe { FfiOHOSDeleteKey(keyAliasCstr, _paramSet.toPointer()) }
    } else {
        unsafe { FfiOHOSDeleteKey(keyAliasCstr, CPointer()) }
    }

    try {
        if (retCode != HKS_SUCCESS) {
            throw hksCodeToException(retCode)
        }
    } finally {
        unsafe {
            LibC.free(keyAliasCstr)
        }
    }
}

/**
 * Imports a key in plaintext.
 *
 * @param { String } keyAlias - keyAlias indicates the key's name.
 * @param { HuksOptions } options - Tags required for the import and key to import. The algorithm, key purpose, and
 * key length are mandatory.
 * @throws { BusinessException } 801 - api is not supported
 * @throws { BusinessException } 12000001 - algorithm mode is not supported
 * @throws { BusinessException } 12000002 - algorithm param is missing
 * @throws { BusinessException } 12000003 - algorithm param is invalid
 * @throws { BusinessException } 12000004 - operating file failed
 * @throws { BusinessException } 12000005 - IPC communication failed
 * @throws { BusinessException } 12000006 - error occured in crypto engine
 * @throws { BusinessException } 12000011 - queried entity does not exist
 * @throws { BusinessException } 12000012 - Device environment or input parameter abnormal
 * @throws { BusinessException } 12000013 - queried credential does not exist
 * @throws { BusinessException } 12000014 - memory is insufficient
 * @throws { BusinessException } 12000015 - Failed to obtain the security information via UserIAM
 * @throws { BusinessException } 12000017 - The key with same alias is already exist
 */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension",
    throwexception: true,
    workerthread: true
]
public func importKeyItem(keyAlias: String, options: HuksOptions): Unit {
    if (keyAlias.isEmpty()) {
        throw BusinessException(HuksExceptionErrCode.HuksErrCodeIllegalArgument.getValue(), "key alias is empty")
    }

    if (options.properties.isEmpty()) {
        throw BusinessException(HuksExceptionErrCode.HuksErrCodeIllegalArgument.getValue(), "properties is None")
    }
    let properties = options.properties
    
    if (options.inData.isEmpty()) {
        throw BusinessException(HuksExceptionErrCode.HuksErrCodeIllegalArgument.getValue(), "properties is None")
    } 
    let inData = options.inData

    var paramSet: HksParamSet = HksParamSet(properties)

    let keyAliasCstr: CString = unsafe { LibC.mallocCString(keyAlias) }

    var keyBlob: OhosHksBlob
    try {
        keyBlob = unsafe { OhosHksBlob.mallocFromBytes(inData) }
    } catch (e: Exception) {
        unsafe { LibC.free(keyAliasCstr) }
        throw e
    }

    let retCode = unsafe {
        FfiOHOSImportKey(keyAliasCstr, paramSet.toPointer(), inout keyBlob)
    }

    try {
        if (retCode != HKS_SUCCESS) {
            throw hksCodeToException(retCode)
        }
    } finally {
        unsafe {
            LibC.free(keyAliasCstr)
            keyBlob.free()
        }
    }
}
