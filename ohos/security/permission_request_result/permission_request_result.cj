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

protected package ohos.security.permission_request_result

import ohos.base.BusinessException
import ohos.ffi.{ CArrString, CArrI32, CArrBool }
import ohos.labels.APILevel

const INVALID_PARA: Int32 = 12100001
const OUT_MEMORY_ERR: Int32 = 12100008

@!APILevel[
    21,
    atomicservice: true,
    crossplatform: true,
    stagemodelonly: true,
    syscap: "SystemCapability.Security.AccessToken"
]
public class PermissionRequestResult {
    @!APILevel[
        21,
        atomicservice: true,
        crossplatform: true,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.AccessToken"
    ]
    public var permissions: Array<String>

    @!APILevel[
        21,
        atomicservice: true,
        crossplatform: true,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.AccessToken"
    ]
    public var authResults: Array<Int32>

    @!APILevel[
        21,
        atomicservice: true,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.AccessToken"
    ]
    public var dialogShownResults: ?Array<Bool> = None

    @!APILevel[
        21,
        atomicservice: true,
        crossplatform: true,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.AccessToken"
    ]
    public init(
        permissions: Array<String>,
        authResults: Array<Int32>
    ) {
        this.permissions = permissions
        this.authResults = authResults
    }

    static func fromCPermissionRequestResult(cRet: CPermissionRequestResult): PermissionRequestResult {
        let pSize = cRet.permissions.size
        let pPtr = cRet.permissions.head
        if (pPtr.isNull()) {
            throw BusinessException(OUT_MEMORY_ERR, "malloc failed!")
        }
        let permissionsArr = unsafe {
            Array<String>(
                pSize,
                {
                    i =>
                    let cString = pPtr.read(i)
                    let permission = cString.toString()
                    LibC.free(cString)
                    permission
                }
            )
        }
        unsafe { LibC.free<CString>(pPtr) }

        let cSize = cRet.authResults.size
        let cPtr = cRet.authResults.head
        if (cPtr.isNull()) {
            throw BusinessException(OUT_MEMORY_ERR, "malloc failed!")
        }
        let autuResultsArr = unsafe { Array<Int32>(cSize, {i => cPtr.read(i)}) }
        unsafe { LibC.free<Int32>(cPtr) }

        let dSize = cRet.dialogShownResults.size
        let dPtr = cRet.dialogShownResults.head
        if (dPtr.isNull()) {
            return PermissionRequestResult(permissionsArr, autuResultsArr)
        }
        let dialogShownResultsArr = unsafe { Array<Bool>(dSize, {i => dPtr.read(i)}) }
        unsafe { LibC.free<Bool>(dPtr) }
        let result = PermissionRequestResult(permissionsArr, autuResultsArr)
        result.dialogShownResults = dialogShownResultsArr
        return result
    }
}

@C
struct CPermissionRequestResult {
    CPermissionRequestResult(
        let permissions: CArrString,
        let authResults: CArrI32,
        let dialogShownResults: CArrBool
    ) {}
}

@C
struct RetDataCPermissionRequestResult {
    RetDataCPermissionRequestResult(
        let code: Int32,
        let data: CPermissionRequestResult
    ) {}
}