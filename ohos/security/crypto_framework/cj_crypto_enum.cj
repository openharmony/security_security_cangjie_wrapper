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

import ohos.business_exception.BusinessException
import ohos.labels.{APILevel, Hide}

import std.deriving.Derive

/**
 * Enum for result code.
 *
 */
enum Result {
    /**
     * Indicates that input parameters is invalid.
     *
     */
    InvalidParams
    |
    /**
     * Indicates that function or algorithm is not supported.
     *
     */
    NotSupport
    |
    /**
     * Indicates the memory operation failed.
     *
     */
    ErrOutOfMemory
    |
    /**
     * Indicates that failed to convert parameters between cj and c.
     *
     */
    ErrRuntimeError
    |
    @!Hide[isChecked: true]
    ErrParameterCheckFailed
    |
    /**
     * Indicates that crypto operation error.
     *
     */
    ErrCryptoOperation
    | ...

    /**
     * Get the corresponding mapping value.
     *
     */
    func getValue(): Int32 {
        return match (this) {
            case InvalidParams => 401
            case NotSupport => 801
            case ErrOutOfMemory => 17620001
            case ErrRuntimeError => 17620002
            case ErrCryptoOperation => 17630001
            case _ => throw BusinessException(17620003, "Parameter check failed.")
        }
    }

    /**
     * Return the string of the enumeration value.
     *
     */
    public func toString(): String {
        return match (this) {
            case InvalidParams => "Parameter error."
            case NotSupport => "Capability not supported."
            case ErrOutOfMemory => "Memory error."
            case ErrRuntimeError => "Runtime error."
            case ErrCryptoOperation => "Crypto operation error."
            case _ => throw BusinessException(17620003, "Parameter check failed.")
        }
    }
}

/**
 * @throws { BusinessException } 176200003 - Parameter check failed.
 */
func getError(errCode: Int32): Result {
    match {
        case errCode == -10001 => return InvalidParams
        case errCode == -10002 => return NotSupport
        case errCode == -20001 => return ErrOutOfMemory
        case errCode == -20002 => return ErrRuntimeError
        case errCode == -30001 => return ErrCryptoOperation
        case _ => throw BusinessException(17620003, "Parameter check failed.")
    }
}

func checkAndThrow(errCode: Int32) {
    if (errCode == -10001) {
        throw BusinessException(401, "Parameter error.")
    }
    if (errCode != 0) {
        let msg = getError(errCode).toString()
        throw BusinessException(getError(errCode).getValue(), msg)
    }
}

/**
 * Enum for obtain the crypto operation.
 *
 */
@Derive[ToString, Equatable]
/**
 * Enumerates the cryptographic operations.
 */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.Cipher"
]
public enum CryptoMode {
    /**
     * The value of encryption operation for AES, 3DES and RSA.
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    EncryptMode
    |
    /**
     * The value of decryption operation for AES, 3DES and RSA.
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    DecryptMode
    | ...

    func getValue(): Int32 {
        return match (this) {
            case EncryptMode => 0
            case DecryptMode => 1
            case _ => throw BusinessException(17620003, "Parameter check failed.")
        }
    }
}

/**
 * Enum for encryption specified parameters.
 *
 */
@Derive[ToString, Equatable]
/**
 * Enum for encryption specified parameters.
 * You can use setCipherSpec to set cipher parameters, and use getCipherSpec to obtain cipher parameters.
 */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.Cipher"
]
public enum CipherSpecItem {
    /**
     * Indicates the algorithm name of the message digest function. It is used during RSA encryption.
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    OaepMdNameStr
    |
    /**
     * Indicates the algorithm name for the mask generation function. It is used during RSA encryption.
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    OaepMgfNameStr
    |
    /**
     * Indicates the message digest parameter for the MGF1 mask generation function. It is used during RSA encryption.
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    OaepMgf1MdStr
    |
    /**
     * Indicates the source of the encoding input P. It is used during RSA encryption.
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    OaepMgf1PsrcUint8Arr
    |
    @!Hide[isChecked: true]
    Sm2MdNameStr
    | ...

    prop value: Int32 {
        get() {
            match (this) {
                case OaepMdNameStr => 100
                case OaepMgfNameStr => 101
                case OaepMgf1MdStr => 102
                case OaepMgf1PsrcUint8Arr => 103
                case _ => throw BusinessException(17620003, "Parameter check failed.")
            }
        }
    }
}
