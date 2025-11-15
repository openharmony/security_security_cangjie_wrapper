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

import ohos.labels.APILevel

foreign func memcpy_s(dest: CPointer<UInt8>, destMax: UIntNative, src: CPointer<UInt8>, count: UIntNative): Int32

/**
 * Defines a buffer array of the Binary Large Object (BLOB) type.
 */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework"
]
public class DataBlob {
    /**
     * Indicates the content of data blob.
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework"
    ]
    public var data: Array<UInt8>

    /**
     * DataBlob constructor.
     *
     * @param { Array<UInt8> } data - indicates the  data blob.
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework"
    ]
    public init(data: Array<UInt8>) {
        this.data = data
    }
}

/**
 * Defines the child class of ParamsSpec. It is a parameter of init for symmetric encryption or decryption.
 * IvParamsSpec applies to the cipher modes such as CBC, CTR, OFB, and CFB, which use only the IV.
 */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.Cipher"
]
public class IvParamsSpec <: ParamsSpec {
    /**
     * IV for encryption or decryption.
     * Options:
     * - AES CBC, CTR, OFB, or CFB mode: 16-byte IV
     * - 3DES CBC, OFB, or CFB mode: 8-byte IV
     * - SM4 CBC, CTR, OFB, or CFB mode: 16-byte IV
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public var iv: DataBlob

    /**
     * IvParamsSpec constructor.
     *
     * @param { String } algName - Indicates the algorithm name.
     * @param { DataBlob } iv - indicates the data blob.
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public init(algName: String, iv: DataBlob) {
        super(algName)
        this.iv = iv
    }
}

/**
 * Provides the GcmParamsSpec type, including the parameter iv, aad and authTag.
 */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.Cipher"
]
public class GcmParamsSpec <: ParamsSpec {
    /**
     * Indicates the GCM algorithm parameters such as iv.
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public var iv: DataBlob

    /**
     * Indicates the additional Authenticated Data in GCM mode.
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public var aad: DataBlob

    /**
     * Indicates the output tag from the encryption operation. The tag is used for integrity check.
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public var authTag: DataBlob

    /**
     * GcmParamsSpec constructor.
     *
     * @param { String } algName - Indicates the algorithm name.
     * @param { DataBlob } iv - Indicates the GCM algorithm parameters such as iv.
     * @param { DataBlob } aad - Indicates the additional Authenticated Data in GCM mode.
     * @param { DataBlob } authTag - Indicates the output tag from the encryption operation. The tag is used for integrity check.
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public init(algName: String, iv: DataBlob, aad: DataBlob, authTag: DataBlob) {
        super(algName)
        this.iv = iv
        this.aad = aad
        this.authTag = authTag
    }
}

/**
 * Provides the CcmParamsSpec type, including the parameter iv, aad and authTag.
 */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.Cipher"
]
public class CcmParamsSpec <: ParamsSpec {
    /**
     * Indicates the GCM algorithm parameters such as IV.
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public var iv: DataBlob

    /**
     * Indicates the Additional Authenticated Data in CCM mode.
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public var aad: DataBlob

    /**
     * Indicates the output tag from the encryption operation. The tag is used for integrity check.
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public var authTag: DataBlob

    /**
     * CcmParamsSpec constructor.
     *
     * @param { String } algName - Indicates the algorithm name.
     * @param { DataBlob } iv - Indicates the GCM algorithm parameters such as IV.
     * @param { DataBlob } aad - Indicates the Additional Authenticated Data in CCM mode.
     * @param { DataBlob } authTag - Indicates the output tag from the encryption operation. The tag is used for integrity check.
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public init(algName: String, iv: DataBlob, aad: DataBlob, authTag: DataBlob) {
        super(algName)
        this.iv = iv
        this.aad = aad
        this.authTag = authTag
    }
}
