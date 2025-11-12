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
import ohos.business_exception.BusinessException

/**
 * Init Operation.
 *
 * @param { string } keyAlias - Alias of the key involved in the initSession operation.
 * @param { HuksOptions } options - Parameter set used for the initSession operation.
 * @returns { HuksSessionHandle } Promise used to return a session handle for subsequent operations.
 * @throws { BusinessException } 401 - argument is invalid
 * @throws { BusinessException } 801 - api is not supported
 * @throws { BusinessException } 12000001 - algorithm mode is not supported
 * @throws { BusinessException } 12000002 - algorithm param is missing
 * @throws { BusinessException } 12000003 - algorithm param is invalid
 * @throws { BusinessException } 12000004 - operating file failed
 * @throws { BusinessException } 12000005 - IPC communication failed
 * @throws { BusinessException } 12000006 - error occured in crypto engine
 * @throws { BusinessException } 12000010 - the number of sessions has reached limit
 * @throws { BusinessException } 12000011 - queried entity does not exist
 * @throws { BusinessException } 12000012 - external error
 * @throws { BusinessException } 12000014 - memory is insufficient
 * @throws { BusinessException } 12000018 - the input parameter is invalid
 */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension"
]
public func initSession(keyAlias: String, options: HuksOptions): HuksSessionHandle {
    if (keyAlias.isEmpty()) {
        throw BusinessException(HuksExceptionErrCode.HuksErrCodeIllegalArgument.getValue(), "key alias is empty")
    }

    if (options.properties.isEmpty()) {
        throw BusinessException(HuksExceptionErrCode.HuksErrCodeIllegalArgument.getValue(), "properties is None")
    } 
    let properties = options.properties

    let paramSet: HksParamSet = HksParamSet(properties)
    let keyAliasCstr = unsafe { LibC.mallocCString(keyAlias) }
    var handle: OhosHksBlob
    try {
        handle = unsafe { OhosHksBlob.malloc(HANDLE_SIZE) }
    } catch (e: Exception) {
        unsafe { LibC.free(keyAliasCstr) }
        throw e
    }
    var token: OhosHksBlob
    try {
        token = unsafe { OhosHksBlob.malloc(TOKEN_SIZE) }
    } catch (e: Exception) {
        unsafe { LibC.free(keyAliasCstr) }
        unsafe { handle.free() }
        throw e
    }
    let retCode = unsafe {
        FfiOHOSInitSession(keyAliasCstr, paramSet.toPointer(), inout handle, inout token)
    }
    try {
        if (retCode == HKS_SUCCESS) {
            let retHandle = getHuksHandle(handle)
            let retToken = if (token.size > 0) {
                token.copyToBytes()
            } else {
                Bytes()
            }
            return HuksSessionHandle(retHandle, challenge: retToken)
        } else {
            throw hksCodeToException(retCode)
        }
    } finally {
        unsafe {
            LibC.free(keyAliasCstr)
            handle.free()
            token.free()
        }
    }
}

func getHuksHandle(handle: OhosHksBlob): HuksHandleId {
    if (handle.size == HANDLE_SIZE) {
        HuksHandleId(handle.copyToBytes())
    } else {
        HuksHandleId(Array())
    }
}

 /**
   * Updates the key operation by segment. This API uses an asynchronous callback to return the result.
   * huks.initSession, huks.updateSession, and huks.finishSession must be used together.
   *
   * @param { long } handle - Handle for the updateSession operation.
   * @param { HuksOptions } options - Parameter set used for the updateSession operation.
   * @param { Array<UInt8> }[Option] token - Authentication token for refined key access control. If this parameter is left blank,
   * refined key access control is not performed.
   * @returns { Option<Bytes> } Promise used to return the updateSession operation result.
   * @throws { BusinessException } 401 - Parameter error. Possible causes:
   *                                 1. Mandatory parameters are left unspecified.
   *                                 2. Incorrect parameter types.
   *                                 3. Parameter verification failed.
   * @throws { BusinessException } 801 - api is not supported
   * @throws { BusinessException } 12000001 - algorithm mode is not supported
   * @throws { BusinessException } 12000002 - algorithm param is missing
   * @throws { BusinessException } 12000003 - algorithm param is invalid
   * @throws { BusinessException } 12000004 - operating file failed
   * @throws { BusinessException } 12000005 - IPC communication failed
   * @throws { BusinessException } 12000006 - error occurred in crypto engine
   * @throws { BusinessException } 12000007 - this credential is already invalidated permanently
   * @throws { BusinessException } 12000008 - verify auth token failed
   * @throws { BusinessException } 12000009 - auth token is already timeout
   * @throws { BusinessException } 12000011 - queried entity does not exist
   * @throws { BusinessException } 12000012 - Device environment or input parameter abnormal
   * @throws { BusinessException } 12000014 - memory is insufficient
   */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension"
]
public func updateSession(handle: HuksHandleId, options: HuksOptions, token!: Bytes = Bytes()): Option<Bytes> {
    return updateOrFinish(handle, options, token, true)
}

/**
   * Finishes the key operation. This API uses an asynchronous callback to return the result.
   * huks.initSession, huks.updateSession, and huks.finishSession must be used together.
   * @throws { BusinessException } 401 - Parameter error. Possible causes:
   *                                 1. Mandatory parameters are left unspecified.
   *                                 2. Incorrect parameter types.
   *                                 3. Parameter verification failed.
   * @throws { BusinessException } 801 - api is not supported
   * @throws { BusinessException } 12000001 - algorithm mode is not supported
   * @throws { BusinessException } 12000002 - algorithm param is missing
   * @throws { BusinessException } 12000003 - algorithm param is invalid
   * @throws { BusinessException } 12000004 - operating file failed
   * @throws { BusinessException } 12000005 - IPC communication failed
   * @throws { BusinessException } 12000006 - error occurred in crypto engine
   * @throws { BusinessException } 12000007 - this credential is already invalidated permanently
   * @throws { BusinessException } 12000008 - verify auth token failed
   * @throws { BusinessException } 12000009 - auth token is already timeout
   * @throws { BusinessException } 12000011 - queried entity does not exist
   * @throws { BusinessException } 12000012 - Device environment or input parameter abnormal
   * @throws { BusinessException } 12000014 - memory is insufficient
   */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension"
]
public func finishSession(handle: HuksHandleId, options: HuksOptions, token!: Bytes = Bytes()): Option<Bytes> {
    return updateOrFinish(handle, options, token, false)
}

func updateOrFinish(handle: HuksHandleId, options: HuksOptions, token: Bytes, isUpdate: Bool): Option<Bytes> {
    if (options.properties.isEmpty()) {
        throw BusinessException(HuksExceptionErrCode.HuksErrCodeIllegalArgument.getValue(), "properties is None")
    } 
    let properties = options.properties

    let inData = if (options.inData.isEmpty()) {
        Bytes()
    } else {
       options.inData
    }

    var inBlob: OhosHksBlob = unsafe { OhosHksBlob.mallocFromBytes(inData) }	
    var outBlob: OhosHksBlob	

    try {	
        let outBlobSize = getOutBlogSize(inData)	
        outBlob = unsafe { OhosHksBlob.malloc(outBlobSize) }	
    } catch (e: Exception) {
        unsafe { inBlob.free() }
        throw e
    }
    
    let sessionParams = SessionParams(inBlob,outBlob)
    try {
        return updateOrFinishSession(sessionParams, properties, handle, token, isUpdate)
    } finally {	
        unsafe { outBlob.free() }	
        unsafe { inBlob.free() }	
    }
}

struct SessionParams {
    SessionParams(
        let inBlob: OhosHksBlob,
        let outBlob: OhosHksBlob
    ) {}
}

func updateOrFinishSession(params: SessionParams, properties: Array<HuksParam>,
    handle: HuksHandleId, token: Bytes, isUpdate: Bool) {
    let paramSet: HksParamSet
    try {
        paramSet = HksParamSet(properties)	
    } catch (e: Exception) {		
        throw e	
    }	

    if (!token.isEmpty()) {	
        if (!paramSet.write(HuksTag.HUKS_TAG_AUTH_TOKEN, token)) {	
            throw BusinessException(	
                HuksExceptionErrCode.HuksErrCodeIllegalArgument.getValue(),	
                "properties too big"	
            )	
        }	
    }	
    // create OhosHksBlob for user ffi from handle 	
    var handleBlob: OhosHksBlob
    try {
        handleBlob = unsafe { OhosHksBlob.mallocFromBytes(handle.data) }
    } catch (e: Exception) {
        throw e
    }
    var cinBlob = params.inBlob
    var coutBlob = params.outBlob
    let retCode = unsafe {
        if (isUpdate) {
            FfiOHOSUpdateSession(inout handleBlob, paramSet.toPointer(), inout cinBlob, inout coutBlob)
        } else {
            FfiOHOSFinishSession(inout handleBlob, paramSet.toPointer(), inout cinBlob, inout coutBlob)
        }
    }
    processRet(retCode, params.outBlob, handleBlob)
}

func getOutBlogSize(inData: Array<UInt8>) {
    if (UInt32(inData.size) > MAX_KEY_SIZE) {
        UInt32(inData.size)
    } else {
        MAX_KEY_SIZE
    }
}

/**
 * @throws { BusinessException } 12000012 - external error
 */
func processRet(retCode: Int32, outBlob: OhosHksBlob, handleBlob: OhosHksBlob) {
    try {
        if (retCode == HKS_SUCCESS) {
            let retOutData = outBlob.copyToBytes()
            retOutData
        } else {
            throw hksCodeToException(retCode)
        }
    } finally {
        unsafe {
            handleBlob.free()
        }
    }
}

/**
 * Aborts a key operation. This API uses an asynchronous callback to return the result.
 *
 * @param { HuksHandleId } handle - Handle for the abortSession operation.
 * @param { HuksOptions } options - Parameter set used for the abortSession operation.
 * @throws { BusinessException } 401 - argument is invalid
 * @throws { BusinessException } 801 - api is not supported
 * @throws { BusinessException } 12000004 - operating file failed
 * @throws { BusinessException } 12000005 - IPC communication failed
 * @throws { BusinessException } 12000006 - error occured in crypto engine
 * @throws { BusinessException } 12000012 - external error
 * @throws { BusinessException } 12000014 - memory is insufficient
 */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension"
]
public func abortSession(handle: HuksHandleId, options: HuksOptions): Unit {
    if (options.properties.isEmpty()) {
        throw BusinessException(HuksExceptionErrCode.HuksErrCodeIllegalArgument.getValue(), "properties is None")
    } 
    let properties =  options.properties

    let paramSet: HksParamSet = HksParamSet(properties)

    var handleBlob = unsafe { OhosHksBlob.mallocFromBytes(handle.data) }

    let retCode = unsafe {
        FfiOHOSAbortSession(inout handleBlob, paramSet.toPointer())
    }

    try {
        if (retCode != HKS_SUCCESS) {
            throw hksCodeToException(retCode)
        }
    } finally {
        unsafe {
            handleBlob.free()
        }
    }
}
