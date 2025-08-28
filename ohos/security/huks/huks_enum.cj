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

package ohos.security.huks

import ohos.labels.*

/**
 * Enum for huks exception error code.
 *
 * @relation export enum HuksExceptionErrCode
 */
@!APILevel[
    21,
    stagemodelonly: true,
    syscap: "SystemCapability.Security.Huks.Core"
]
enum HuksExceptionErrCode {
    /**
     * Permission verification failed.
     *
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
   HuksErrCodePermissionFail
   |
        /**
         * Invalid parameters are detected. Possible causes:
         * 1. Mandatory parameters are left unspecified.
         * 2. Incorrect parameter types.
         * 3. Parameter verification failed.
         *
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksErrCodeIllegalArgument
    |
        /**
         * The API is not supported.
         *
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksErrCodeNotSupportedApi
    |
        /**
         * The feature is not supported.
         *
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksErrCodeFeatureNotSupported
    |
        /**
         * Key algorithm parameters are missing.
         *
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksErrCodeMissingCryptoAlgArgument
    |
        /**
         * Invalid key algorithm parameters are detected.
         *
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksErrCodeInvalidCryptoAlgArgument
    |
        /**
         * The file operation failed.
         *
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksErrCodeFileOperationFail
    |
        /**
         * The communication failed.
         *
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksErrCodeCommunicationFail
    |
        /**
         * Failed to operate the algorithm library.
         *
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksErrCodeCryptoFail
    |
        /**
         * Failed to access the key because the key has expired.
         *
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksErrCodeKeyAuthPermanentlyInvalidated
    |
        /**
         * Failed to access the key because the authentication has failed.
         *
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksErrCodeKeyAuthVerifyFailed
    |
        /**
         * Key access timed out.
         *
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksErrCodeKeyAuthTimeOut
    |
        /**
         * The number of key operation sessions has reached the limit.
         *
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksErrCodeSessionLimit
    |
        /**
         * The target object does not exist.
         *
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksErrCodeItemNotExist
    |
        /**
         * An external error occurs.
         *
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksErrCodeExternalError
    |
        /**
         * The credential does not exist.
         *
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksErrCodeCredentialNotExist
    |
        /**
         * The memory is insufficient.
         *
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksErrCodeInsufficientMemory
    |
        /**
         * Failed to call other system services.
         *
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksErrCodeCallServiceFailed
    | ...

    /**
     * get the corresponding mapping value
     *
     */
    func getValue(): Int32 {
        match(this) {
            case HuksErrCodePermissionFail => 201
            case HuksErrCodeIllegalArgument => 401
            case HuksErrCodeNotSupportedApi => 801
            case HuksErrCodeFeatureNotSupported => 12000001
            case HuksErrCodeMissingCryptoAlgArgument => 12000002
            case HuksErrCodeInvalidCryptoAlgArgument => 12000003
            case HuksErrCodeFileOperationFail => 12000004
            case HuksErrCodeCommunicationFail => 12000005
            case HuksErrCodeCryptoFail => 12000006
            case HuksErrCodeKeyAuthPermanentlyInvalidated => 12000007
            case HuksErrCodeKeyAuthVerifyFailed => 12000008
            case HuksErrCodeKeyAuthTimeOut => 12000009
            case HuksErrCodeSessionLimit => 12000010
            case HuksErrCodeItemNotExist => 12000011
            case HuksErrCodeExternalError => 12000012
            case HuksErrCodeCredentialNotExist => 12000013
            case HuksErrCodeInsufficientMemory => 12000014
            case HuksErrCodeCallServiceFailed => 12000015
            case _ => throw IllegalArgumentException("The type is not supported.")
        }
    }
}

/**
 * Enum for huks key purpose.
 *
 * @relation export enum HuksKeyPurpose
 */
@!APILevel[
    21,
    stagemodelonly: true,
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksKeyPurpose {
    /**
     * Used to encrypt the plaintext.
     *
     * @relation HUKS_KEY_PURPOSE_ENCRYPT = 1
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_PURPOSE_ENCRYPT: HuksParamValue = HuksParamValue.Uint32Value(1)
    /**
     * Used to decrypt the cipher text.
     *
     * @relation HUKS_KEY_PURPOSE_DECRYPT = 2
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_PURPOSE_DECRYPT: HuksParamValue = HuksParamValue.Uint32Value(2)
    /**
     * Used for signing.
     *
     * @relation HUKS_KEY_PURPOSE_SIGN = 4
     */    
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_PURPOSE_SIGN: HuksParamValue = HuksParamValue.Uint32Value(4)
    /**
     * Used to verify the signature.
     *
     * @relation HUKS_KEY_PURPOSE_VERIFY = 8
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_PURPOSE_VERIFY: HuksParamValue = HuksParamValue.Uint32Value(8)
    /**
     * Used to derive a key.
     *
     * @relation HUKS_KEY_PURPOSE_DERIVE = 16
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_PURPOSE_DERIVE: HuksParamValue = HuksParamValue.Uint32Value(16)
    /**
     * Used for an encrypted export.
     *
     * @relation HUKS_KEY_PURPOSE_WRAP = 32
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_PURPOSE_WRAP: HuksParamValue = HuksParamValue.Uint32Value(32)
    /**
     * Used for an encrypted import.
     *
     * @relation HUKS_KEY_PURPOSE_UNWRAP = 64
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_PURPOSE_UNWRAP: HuksParamValue = HuksParamValue.Uint32Value(64)
    /**
     * Used to generate a message authentication code (MAC).
     *
     * @relation HUKS_KEY_PURPOSE_MAC = 128
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_PURPOSE_MAC: HuksParamValue = HuksParamValue.Uint32Value(128)
    /**
     * Used for key agreement.
     *
     * @relation HUKS_KEY_PURPOSE_AGREE = 256
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_PURPOSE_AGREE: HuksParamValue = HuksParamValue.Uint32Value(256)
}

/**
 * Enum for huks key digest.
 *
 * @relation export enum HuksKeyDigest
 */
@!APILevel[
    21,
    stagemodelonly: true,
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksKeyDigest {
    /**
     * No digest algorithm.
     *
     * @relation HUKS_DIGEST_NONE = 0
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_DIGEST_NONE: HuksParamValue = HuksParamValue.Uint32Value(0)
    /**
     * MD5.
     *
     * @relation HUKS_DIGEST_MD5 = 1
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_DIGEST_MD5: HuksParamValue = HuksParamValue.Uint32Value(1)
    /**
     * SM3.
     *
     * @relation HUKS_DIGEST_SM3 = 2
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_DIGEST_SM3: HuksParamValue = HuksParamValue.Uint32Value(2)
    /**
     * SHA-1.
     *
     * @relation HUKS_DIGEST_SHA1 = 10
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_DIGEST_SHA1: HuksParamValue = HuksParamValue.Uint32Value(10)
    /**
     * SHA-224.
     *
     * @relation HUKS_DIGEST_SHA224 = 11
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_DIGEST_SHA224: HuksParamValue = HuksParamValue.Uint32Value(11)
    /**
     * SHA-256.
     *
     * @relation HUKS_DIGEST_SHA256 = 12
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_DIGEST_SHA256: HuksParamValue = HuksParamValue.Uint32Value(12)
    /**
     * SHA-384.
     *
     * @relation HUKS_DIGEST_SHA384 = 13
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_DIGEST_SHA384: HuksParamValue = HuksParamValue.Uint32Value(13)
    /**
     * SHA-512.
     *
     * @relation HUKS_DIGEST_SHA512 = 14
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_DIGEST_SHA512: HuksParamValue = HuksParamValue.Uint32Value(14)
}

/**
 * Enumerates the padding algorithms.
 *
 * @relation export enum HuksKeyPadding
 */
@!APILevel[
    21,
    stagemodelonly: true,
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksKeyPadding {
    /**
     * No padding algorithm is used.
     *
     * @relation HUKS_PADDING_NONE = 0
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_PADDING_NONE: HuksParamValue = HuksParamValue.Uint32Value(0)
    /**
     * Optimal Asymmetric Encryption Padding (OAEP).
     *
     * @relation HUKS_PADDING_OAEP = 1
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_PADDING_OAEP: HuksParamValue = HuksParamValue.Uint32Value(1)
    /**
     * Probabilistic Signature Scheme (PSS).
     *
     * @relation HUKS_PADDING_PSS = 2
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_PADDING_PSS: HuksParamValue = HuksParamValue.Uint32Value(2)
    /**
     * Public Key Cryptography Standards (PKCS) #1 v1.5.
     *
     * @relation HUKS_PADDING_PKCS1_V1_5 = 3
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_PADDING_PKCS1_V1_5: HuksParamValue = HuksParamValue.Uint32Value(3)
    /**
     * PKCS #5.
     *
     * @relation HUKS_PADDING_PKCS5 = 4
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_PADDING_PKCS5: HuksParamValue = HuksParamValue.Uint32Value(4)
    /**
     * PKCS #7.
     *
     * @relation HUKS_PADDING_PKCS7 = 5
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_PADDING_PKCS7: HuksParamValue = HuksParamValue.Uint32Value(5)
}

/**
 * Enumerates the cipher modes.
 *
 * @relation export enum HuksCipherMode
 */
@!APILevel[
    21,
    stagemodelonly: true,
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksCipherMode {
    /**
     * Electronic Code Block (ECB) mode.
     *
     * @relation HUKS_MODE_ECB = 1
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_MODE_ECB: HuksParamValue = HuksParamValue.Uint32Value(1)
    /**
     * Cipher Block Chaining (CBC) mode.
     *
     * @relation HUKS_MODE_CBC = 2
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_MODE_CBC: HuksParamValue = HuksParamValue.Uint32Value(2)
    /**
     * Counter (CTR) mode.
     *
     * @relation HUKS_MODE_CTR = 3
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_MODE_CTR: HuksParamValue = HuksParamValue.Uint32Value(3)
    /**
     * Output Feedback (OFB) mode.
     *
     * @relation HUKS_MODE_OFB = 4
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_MODE_OFB: HuksParamValue = HuksParamValue.Uint32Value(4)
    /**
     * Counter with CBC-MAC (CCM) mode.
     *
     * @relation HUKS_MODE_CCM = 31
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_MODE_CCM: HuksParamValue = HuksParamValue.Uint32Value(31)
    /**
     * Galois/Counter (GCM) mode.
     *
     * @relation HUKS_MODE_GCM = 32
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
   public static const HUKS_MODE_GCM: HuksParamValue = HuksParamValue.Uint32Value(32)
}

/**
 * Enumerates the key sizes.
 *
 * @relation export enum HuksKeySize
 */
@!APILevel[
    21,
    stagemodelonly: true,
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksKeySize {
    /**
     * Rivest-Shamir-Adleman (RSA) key of 512 bits.
     *
     * @relation HUKS_RSA_KEY_SIZE_512 = 512
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_RSA_KEY_SIZE_512: HuksParamValue = HuksParamValue.Uint32Value(512)
    /**
     * RSA key of 768 bits.
     *
     * @relation HUKS_RSA_KEY_SIZE_768 = 768
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_RSA_KEY_SIZE_768: HuksParamValue = HuksParamValue.Uint32Value(768)
    /**
     * RSA key of 1024 bits.
     *
     * @relation HUKS_RSA_KEY_SIZE_1024 = 1024
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_RSA_KEY_SIZE_1024: HuksParamValue = HuksParamValue.Uint32Value(1024)
    /**
     * RSA key of 2048 bits.
     *
     * @relation HUKS_RSA_KEY_SIZE_2048 = 2048
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_RSA_KEY_SIZE_2048: HuksParamValue = HuksParamValue.Uint32Value(2048)
    /**
     * RSA key of 3072 bits.
     *
     * @relation HUKS_RSA_KEY_SIZE_3072 = 3072
     */
     @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_RSA_KEY_SIZE_3072: HuksParamValue = HuksParamValue.Uint32Value(3072)
    /**
     * RSA key of 4096 bits.
     *
     * @relation HUKS_RSA_KEY_SIZE_4096 = 4096
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_RSA_KEY_SIZE_4096: HuksParamValue = HuksParamValue.Uint32Value(4096)
    /**
     * Elliptic Curve Cryptography (ECC) key of 224 bits.
     *
     * @relation HUKS_ECC_KEY_SIZE_224 = 224
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ECC_KEY_SIZE_224: HuksParamValue = HuksParamValue.Uint32Value(224)
    /**
     * ECC key of 256 bits.
     *
     * @relation HUKS_ECC_KEY_SIZE_256 = 256
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ECC_KEY_SIZE_256: HuksParamValue = HuksParamValue.Uint32Value(256)
    /**
     * ECC key of 384 bits.
     *
     * @relation HUKS_ECC_KEY_SIZE_384 = 384
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ECC_KEY_SIZE_384: HuksParamValue = HuksParamValue.Uint32Value(384)
    /**
     * ECC key of 521 bits.
     *
     * @relation HUKS_ECC_KEY_SIZE_521 = 521
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ECC_KEY_SIZE_521: HuksParamValue = HuksParamValue.Uint32Value(521)
    /**
     * Advanced Encryption Standard (AES) key of 128 bits.
     *
     * @relation HUKS_AES_KEY_SIZE_128 = 128
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_AES_KEY_SIZE_128: HuksParamValue = HuksParamValue.Uint32Value(128)

        /**
         * AES key of 192 bits.
         *
         * @relation HUKS_AES_KEY_SIZE_192 = 192
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_AES_KEY_SIZE_192: HuksParamValue = HuksParamValue.Uint32Value(192)
    /**
     * AES key of 256 bits.
     *
     * @relation HUKS_AES_KEY_SIZE_256 = 256
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_AES_KEY_SIZE_256: HuksParamValue = HuksParamValue.Uint32Value(256)
    /**
     * AES key of 512 bits.
     *
     * @relation HUKS_AES_KEY_SIZE_512 = 512
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_AES_KEY_SIZE_512: HuksParamValue = HuksParamValue.Uint32Value(512)
    /**
     * Curve25519 key of 256 bits.
     *
     * @relation HUKS_CURVE25519_KEY_SIZE_256 = 256
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_CURVE25519_KEY_SIZE_256: HuksParamValue = HuksParamValue.Uint32Value(256)
    /**
     * Diffie-Hellman (DH) key of 2048 bits.
     *
     * @relation HUKS_DH_KEY_SIZE_2048 = 2048
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_DH_KEY_SIZE_2048: HuksParamValue = HuksParamValue.Uint32Value(2048)
    /**
     * DH key of 3072 bits.
     *
     * @relation HUKS_DH_KEY_SIZE_3072 = 3072
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_DH_KEY_SIZE_3072: HuksParamValue = HuksParamValue.Uint32Value(3072)
    /**
     * DH key of 4096 bits.
     *
     * @relation HUKS_DH_KEY_SIZE_4096 = 4096
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_DH_KEY_SIZE_4096: HuksParamValue = HuksParamValue.Uint32Value(4096)
    /**
     * ShangMi2 (SM2) key of 256 bits.
     *
     * @relation HUKS_SM2_KEY_SIZE_256 = 256
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_SM2_KEY_SIZE_256: HuksParamValue = HuksParamValue.Uint32Value(256)
    /**
     * ShangMi4 (SM4) key of 128 bits.
     *
     * @relation  HUKS_SM4_KEY_SIZE_128 = 128
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_SM4_KEY_SIZE_128: HuksParamValue = HuksParamValue.Uint32Value(128)
}

/**
 * Enumerates the key algorithms.
 *
 * @relation  export enum HuksKeyAlg
 */
@!APILevel[
    21,
    stagemodelonly: true,
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksKeyAlg {
    /**
     * RSA.
     *
     * @relation HUKS_ALG_RSA = 1
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_RSA: HuksParamValue = HuksParamValue.Uint32Value(1)
    /**
     * ECC.
     *
     * @relation HUKS_ALG_ECC = 2
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_ECC: HuksParamValue = HuksParamValue.Uint32Value(2)
    /**
     * DSA.
     *
     * @relation HUKS_ALG_DSA = 3
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_DSA: HuksParamValue = HuksParamValue.Uint32Value(3)
    /**
     * AES.
     *
     * @relation HUKS_ALG_AES = 20
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_AES: HuksParamValue = HuksParamValue.Uint32Value(20)
    /**
     * HMAC.
     *
     * @relation HUKS_ALG_HMAC = 50
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_HMAC: HuksParamValue = HuksParamValue.Uint32Value(50)
    /**
     * HKDF.
     *
     * @relation HUKS_ALG_HKDF = 51
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_HKDF: HuksParamValue = HuksParamValue.Uint32Value(51)
    /**
     * PBKDF2.
     *
     * @relation HUKS_ALG_PBKDF2 = 52
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_PBKDF2: HuksParamValue = HuksParamValue.Uint32Value(52)
    /**
     * ECDH.
     *
     * @relation HUKS_ALG_ECDH = 100
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_ECDH: HuksParamValue = HuksParamValue.Uint32Value(100)
    /**
     * X25519.
     *
     * @relation HUKS_ALG_X25519 = 101
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_X25519: HuksParamValue = HuksParamValue.Uint32Value(101)
    /**
     * Ed25519.
     *
     * @relation HUKS_ALG_ED25519 = 102
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_ED25519: HuksParamValue = HuksParamValue.Uint32Value(102)
    /**
     * DH.
     *
     * @relation HUKS_ALG_DH = 103
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_DH: HuksParamValue = HuksParamValue.Uint32Value(103)
    /**
     * SM2.
     *
     * @relation HUKS_ALG_SM2 = 150
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_SM2: HuksParamValue = HuksParamValue.Uint32Value(150)
    /**
     * SM3.
     *
     * @relation HUKS_ALG_SM3 = 151
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_SM3: HuksParamValue = HuksParamValue.Uint32Value(151)
    /**
     * SM4.
     *
     * @relation HUKS_ALG_SM4 = 152
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_SM4: HuksParamValue = HuksParamValue.Uint32Value(152)
}

/**
 * Enumerates the algorithm suites that can be used for importing a key in ciphertext.
 *
 * @relation export enum HuksUnwrapSuite
 */
@!APILevel[
    21,
    stagemodelonly: true,
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksUnwrapSuite {
    /**
     * Use X25519 for key agreement and then use AES-256 GCM to encrypt the key.
     *
     * @relation HUKS_UNWRAP_SUITE_X25519_AES_256_GCM_NOPADDING = 1
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_UNWRAP_SUITE_X25519_AES_256_GCM_NOPADDING: HuksParamValue = HuksParamValue.Uint32Value(1)
    /**
     * Use ECDH for key agreement and then use AES-256 GCM to encrypt the key.
     *
     * @relation HUKS_UNWRAP_SUITE_ECDH_AES_256_GCM_NOPADDING = 2
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_UNWRAP_SUITE_ECDH_AES_256_GCM_NOPADDING: HuksParamValue = HuksParamValue.Uint32Value(2)
}

/**
 * Enum for huks auth storage level.
 *
 * @relation export enum HuksAuthStorageLevel
 */
@!APILevel[
    21,
    stagemodelonly: true,
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksAuthStorageLevel {
    /**
     * The key can be accessed only after the device is started.
     *
     * @relation HUKS_AUTH_STORAGE_LEVEL_DE = 0
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_AUTH_STORAGE_LEVEL_DE: HuksParamValue = HuksParamValue.Uint32Value(0)
    /**
     * The key can be accessed only after the first unlock of the device.
     *
     * @relation HUKS_AUTH_STORAGE_LEVEL_CE = 1
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_AUTH_STORAGE_LEVEL_CE: HuksParamValue = HuksParamValue.Uint32Value(1)
    /**
     * The key can be accessed only when the device is unlocked.
     *
     * @relation HUKS_AUTH_STORAGE_LEVEL_ECE = 2
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_AUTH_STORAGE_LEVEL_ECE: HuksParamValue = HuksParamValue.Uint32Value(2)
}

/**
 * Enumerates the key generation types.
 *
 * @relation export enum HuksKeyGenerateType
 */
@!APILevel[
    21,
    stagemodelonly: true,
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksKeyGenerateType {
    /**
    * Key generated by default.
    *
    * @relation HUKS_KEY_GENERATE_TYPE_DEFAULT = 0
    */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_GENERATE_TYPE_DEFAULT: HuksParamValue = HuksParamValue.Uint32Value(0)
    /**
     * Derived key.
     *
     * @relation HUKS_KEY_GENERATE_TYPE_DERIVE = 1
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_GENERATE_TYPE_DERIVE: HuksParamValue = HuksParamValue.Uint32Value(1)
    /**
     * Key generated by agreement.
     *
     * @relation HUKS_KEY_GENERATE_TYPE_AGREE = 2
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_GENERATE_TYPE_AGREE: HuksParamValue = HuksParamValue.Uint32Value(2)
}

/**
 * Enumerates the key generation modes.
 *
 * @relation export enum HuksKeyFlag
 */
@!APILevel[
    21,
    stagemodelonly: true,
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksKeyFlag {
    /**
    * Import a key using an API.
    *
    * @relation HUKS_KEY_FLAG_IMPORT_KEY = 1
    */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_FLAG_IMPORT_KEY: HuksParamValue = HuksParamValue.Uint32Value(1)
    /**
     * Generate a key by using an API.
     *
     * @relation HUKS_KEY_FLAG_GENERATE_KEY = 2
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_FLAG_GENERATE_KEY: HuksParamValue = HuksParamValue.Uint32Value(2)
    /**
     * Generate a key by using a key agreement API.
     *
     * @relation HUKS_KEY_FLAG_AGREE_KEY = 3
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_FLAG_AGREE_KEY: HuksParamValue = HuksParamValue.Uint32Value(3)
    /**
     * Derive a key by using an API.
     *
     * @relation HUKS_KEY_FLAG_DERIVE_KEY = 4
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_FLAG_DERIVE_KEY: HuksParamValue = HuksParamValue.Uint32Value(4)
}

/**
 * Enum for huks key storage type.
 *
 * @relation export enum HuksKeyStorageType
 */
@!APILevel[
    21,
    stagemodelonly: true,
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksKeyStorageType {
    /**
     * The key is stored and used only in HUKS. It is mutually exclusive with HUKS_STORAGE_KEY_EXPORT_ALLOWED.
     *
     * @relation HUKS_STORAGE_ONLY_USED_IN_HUKS = 2
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_STORAGE_ONLY_USED_IN_HUKS: HuksParamValue = HuksParamValue.Uint32Value(2)
    /**
     * The key can be exported. It is mutually exclusive with HUKS_STORAGE_ONLY_USED_IN_HUKS.
     *
     * @relation HUKS_STORAGE_KEY_EXPORT_ALLOWED = 3
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_STORAGE_KEY_EXPORT_ALLOWED: HuksParamValue = HuksParamValue.Uint32Value(3)
}

/**
 * Enumerates the types of keys to import. By default, a public key is imported. This field is not
 * required when a symmetric key is imported.
 *
 * @relation export enum HuksImportKeyType
 */
@!APILevel[
    21,
    stagemodelonly: true,
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksImportKeyType {
    /**
     * Public key.
     *
     * @relation HUKS_KEY_TYPE_PUBLIC_KEY = 0
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_TYPE_PUBLIC_KEY: HuksParamValue = HuksParamValue.Uint32Value(0)
    /**
     * Private key.
     *
     * @relation HUKS_KEY_TYPE_PRIVATE_KEY = 1
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
   public static const HUKS_KEY_TYPE_PRIVATE_KEY: HuksParamValue = HuksParamValue.Uint32Value(1)
   /**
    * Public and private key pair.
    *
    * @relation HUKS_KEY_TYPE_KEY_PAIR = 2
    */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
   public static const HUKS_KEY_TYPE_KEY_PAIR: HuksParamValue = HuksParamValue.Uint32Value(2)
}

/**
 * Enumerates the salt_len types to set when PSS padding is used in RSA signing or signature
 * verification.
 *
 * @relation export enum HuksRsaPssSaltLenType
 */
@!APILevel[
    21,
    stagemodelonly: true,
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksRsaPssSaltLenType {
    /**
     * salt_len is set to the digest length.
     *
     * @relation HUKS_RSA_PSS_SALT_LEN_DIGEST = 0
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_RSA_PSS_SALT_LEN_DIGEST: HuksParamValue = HuksParamValue.Uint32Value(0)
    /**
     * salt_len is set to the maximum length.
     *
     * @relation HUKS_RSA_PSS_SALT_LEN_MAX = 1
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_RSA_PSS_SALT_LEN_MAX: HuksParamValue = HuksParamValue.Uint32Value(1)
}

/**
 * Enumerates the user authentication types.
 *
 * @relation export enum HuksUserAuthType
 */
@!APILevel[
    21,
    stagemodelonly: true,
    syscap: "SystemCapability.Security.Huks.Extension"
]
public class HuksUserAuthType {
    /**
     * Fingerprint authentication.
     *
     * @relation HUKS_USER_AUTH_TYPE_FINGERPRINT = 1 << 0
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_USER_AUTH_TYPE_FINGERPRINT: HuksParamValue = HuksParamValue.Uint32Value(1 << 0)
    /**
     * Facial authentication.
     *
     * @relation HUKS_USER_AUTH_TYPE_FACE = 1 << 1
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_USER_AUTH_TYPE_FACE: HuksParamValue = HuksParamValue.Uint32Value(1 << 1)
    /**
     * PIN authentication.
     *
     * @relation HUKS_USER_AUTH_TYPE_PIN = 1 << 2
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_USER_AUTH_TYPE_PIN: HuksParamValue = HuksParamValue.Uint32Value(1 << 2)
}

/**
 * Enumerates the access control types.
 *
 * @relation export enum HuksAuthAccessType
 */
@!APILevel[
    21,
    stagemodelonly: true,
    syscap: "SystemCapability.Security.Huks.Extension"
]
public class HuksAuthAccessType {
    /**
     * The key becomes invalid after the password is cleared.
     *
     * @relation HUKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD = 1 << 0
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD: HuksParamValue = HuksParamValue.Uint32Value(1 << 0)
    /**
     * The key becomes invalid after a new biometric feature is added.
     *
     * @relation HUKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL = 1 << 1
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL: HuksParamValue = HuksParamValue.Uint32Value(1 << 1)
}

/**
 * Enumerates the types of the challenges generated when a key is used.
 *
 * @relation export enum HuksChallengeType
 */
@!APILevel[
    21,
    stagemodelonly: true,
    syscap: "SystemCapability.Security.Huks.Extension"
]
public class HuksChallengeType {
    /**
     * Normal challenge, which is of 32 bytes by default.
     *
     * @relation HUKS_CHALLENGE_TYPE_NORMAL = 0
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_CHALLENGE_TYPE_NORMAL: HuksParamValue = HuksParamValue.Uint32Value(0)
    /**
     * Custom challenge, which supports only one authentication for multiple keys.
     *
     * @relation HUKS_CHALLENGE_TYPE_CUSTOM = 1
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_CHALLENGE_TYPE_CUSTOM: HuksParamValue = HuksParamValue.Uint32Value(1)
    /**
     * Challenge is not required.
     *
     * @relation HUKS_CHALLENGE_TYPE_NONE = 2
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_CHALLENGE_TYPE_NONE: HuksParamValue = HuksParamValue.Uint32Value(2)
}

/**
 * Enumerates the positions of the 8-byte valid value in a custom challenge generated.
 *
 * @relation export enum HuksChallengePosition
 */
@!APILevel[
    21,
    stagemodelonly: true,
    syscap: "SystemCapability.Security.Huks.Extension"
]
public class HuksChallengePosition {
    /**
     * Bytes 0 to 7.
     *
     * @relation HUKS_CHALLENGE_POS_0 = 0
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_CHALLENGE_POS_0: HuksParamValue = HuksParamValue.Uint32Value(0)
    /**
     * Bytes 8 to 15.
     *
     * @relation HUKS_CHALLENGE_POS_1 = 1
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_CHALLENGE_POS_1: HuksParamValue = HuksParamValue.Uint32Value(1)
    /**
     * Bytes 16 to 23.
     *
     * @relation HUKS_CHALLENGE_POS_2 = 2
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_CHALLENGE_POS_2: HuksParamValue = HuksParamValue.Uint32Value(2)
    /**
     * Bytes 24 to 31.
     *
     * @relation HUKS_CHALLENGE_POS_3 = 3
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_CHALLENGE_POS_3: HuksParamValue = HuksParamValue.Uint32Value(3)
}
/**
 * Enumerates the signature types of the key generated or imported. 
 *
 * @relation export enum HuksSecureSignType
 */
@!APILevel[
    21,
    stagemodelonly: true,
    syscap: "SystemCapability.Security.Huks.Extension"
]
public class HuksSecureSignType {
    /**
     * The signature carries authentication information. This field is specified when a key is generated or
     * imported. When the key is used for signing, the data will be added with the authentication information and then
     * be signed.
     *
     * @relation HUKS_SECURE_SIGN_WITH_AUTHINFO = 1
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_SECURE_SIGN_WITH_AUTHINFO: HuksParamValue = HuksParamValue.Uint32Value(1)
}
/**
 * Enumerates the tag transfer modes.
 *
 * @relation export enum HuksSendType
 */
@!APILevel[
    21,
    stagemodelonly: true,
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksSendType {
    /**
     * The tag is sent asynchronously.
     *
     * @relation HUKS_SEND_TYPE_ASYNC = 0
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_SEND_TYPE_ASYNC: HuksParamValue = HuksParamValue.Uint32Value(0)
    /**
     * The tag is sent synchronously.
     *
     * @relation HUKS_SEND_TYPE_SYNC = 1
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_SEND_TYPE_SYNC: HuksParamValue = HuksParamValue.Uint32Value(1)
}
/**
 * Enumerates the tag data types.
 *
 * @relation export enum HuksTagType
 */
@!APILevel[
    21,
    stagemodelonly: true,
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksTagType {
    /**
     * Invalid tag type.
     *
     * @relation HUKS_TAG_TYPE_INVALID = 0 << 28
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_TYPE_INVALID: UInt32 = 0 << 28
    /**
     * Number of the int type.
     *
     * @relation HUKS_TAG_TYPE_INT = 1 << 28
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_TYPE_INT: UInt32 = 1 << 28
    /**
     * Number of the uint type.
     *
     * @relation HUKS_TAG_TYPE_UINT = 2 << 28
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_TYPE_UINT: UInt32 = 2 << 28
    /**
     * BigInt.
     *
     * @relation HUKS_TAG_TYPE_ULONG = 3 << 28
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_TYPE_ULONG: UInt32 = 3 << 28
    /**
     * Boolean.
     *
     * @relation HUKS_TAG_TYPE_BOOL = 4 << 28
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_TYPE_BOOL: UInt32 = 4 << 28
    /**
     * Uint8Array.
     *
     * @relation HUKS_TAG_TYPE_BYTES = 5 << 28
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_TYPE_BYTES: UInt32 = 5 << 28
}
/**
 * Enum for huks tag.
 *
 * @relation export enum HuksTag 
 */
@!APILevel[
    21,
    stagemodelonly: true,
    syscap: "SystemCapability.Security.Huks.Core"
]
public enum HuksTag {
    /**		
     * Invalid TAG.		
     *		
     * @relation HUKS_TAG_INVALID = HuksTagType.HUKS_TAG_TYPE_INVALID | 0	
     	
     */		
    @!APILevel[	

        21,	
        stagemodelonly: true,	
        syscap: "SystemCapability.Security.Huks.Core"	
    ]	
    HuksTagInvalid
    |
        /**
         * Algorithm.
         *
         * @relation HUKS_TAG_ALGORITHM = HuksTagType.HUKS_TAG_TYPE_UINT | 1
         */
        @!APILevel[
        21,	
        stagemodelonly: true,	
        syscap: "SystemCapability.Security.Huks.Core"	
    ]
    HuksTagAlgorithm
    | 
        /**
         * Purpose of the key.
         *
         * @relation HUKS_TAG_PURPOSE = HuksTagType.HUKS_TAG_TYPE_UINT | 2
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagPurpose
    |
        /**
         * Key size.
         *
         * @relation HUKS_TAG_KEY_SIZE = HuksTagType.HUKS_TAG_TYPE_UINT | 3
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagKeySize
    |
        /**
         * Digest algorithm.
         *
         * @relation HUKS_TAG_DIGEST = HuksTagType.HUKS_TAG_TYPE_UINT | 4
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagDigest
    |
        /**
         * Padding mode.
         *
         * @relation HUKS_TAG_PADDING = HuksTagType.HUKS_TAG_TYPE_UINT | 5
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagPadding
    | 
        /**
         * Cipher mode.
         *
         * @relation HUKS_TAG_BLOCK_MODE = HuksTagType.HUKS_TAG_TYPE_UINT | 6
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagBlockMode
    | 
        /**
         * Key type.
         *
         * @relation HUKS_TAG_KEY_TYPE = HuksTagType.HUKS_TAG_TYPE_UINT | 7
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagKeyType
    |
        /**
         * Associated authentication data.
         *
         * @relation HUKS_TAG_ASSOCIATED_DATA = HuksTagType.HUKS_TAG_TYPE_BYTES | 8
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagAssociatedData
    | 
        /**
         * Nonce for key encryption and decryption.
         *
         * @relation HUKS_TAG_NONCE = HuksTagType.HUKS_TAG_TYPE_BYTES | 9
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagNonce
    | 
        /**
         * IV.
         *
         * @relation HUKS_TAG_IV = HuksTagType.HUKS_TAG_TYPE_BYTES | 10
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagIv
    |
        /**
         * Information generated during key derivation.
         *
         * @relation HUKS_TAG_INFO = HuksTagType.HUKS_TAG_TYPE_BYTES | 11
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagInfo
    |
        /**
         * Salt value used for key derivation.
         *
         * @relation HUKS_TAG_SALT = HuksTagType.HUKS_TAG_TYPE_BYTES | 12   
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagSalt
    |
        /**
         * Number of iterations for key derivation.
         *
         * @relation HUKS_TAG_ITERATION = HuksTagType.HUKS_TAG_TYPE_UINT | 14
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagIteration
    |
        /**
         * Key generation type.
         *
         * @relation HUKS_TAG_KEY_GENERATE_TYPE = HuksTagType.HUKS_TAG_TYPE_UINT | 15
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagKeyGenerationType
    |
        /**
         * Type of the algorithm used for key agreement.
         *
         * @relation HUKS_TAG_AGREE_ALG = HuksTagType.HUKS_TAG_TYPE_UINT | 19
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagAlgForAgreement
    |
        /**
         * Public key alias used in key agreement.
         *
         * @relation HUKS_TAG_AGREE_PUBLIC_KEY_IS_KEY_ALIAS = HuksTagType.HUKS_TAG_TYPE_BOOL | 20
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagPublicKeyAliasForAgreement
    |
        /**
         * Private key alias used in key agreement.
         *
         * @relation HUKS_TAG_AGREE_PRIVATE_KEY_ALIAS = HuksTagType.HUKS_TAG_TYPE_BYTES | 21
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
<<<<<<< HEAD
    HuksTagPrivateKeyAliasForAgreement
=======
    HuksTagAgreePrivateKeyAliasForAgreement
>>>>>>> 1726459bfb625301ae080b33e113cf0cdb3e29af
    |
        /**
         * Public key used in key agreement.
         *
         * @relation HUKS_TAG_AGREE_PUBLIC_KEY = HuksTagType.HUKS_TAG_TYPE_BYTES | 22
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
<<<<<<< HEAD
    HuksTagPublicKeyForAgreement
=======
    HuksTagAgreePublicKeyForAgreement
>>>>>>> 1726459bfb625301ae080b33e113cf0cdb3e29af
    | 
        /**
         * Key alias.
         *
         * @relation HUKS_TAG_KEY_ALIAS = HuksTagType.HUKS_TAG_TYPE_BYTES | 23
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagKeyAlias
    |
        /**
         * Size of the derived key.
         *
         * @relation HUKS_TAG_DERIVE_KEY_SIZE = HuksTagType.HUKS_TAG_TYPE_UINT | 24
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagDeriveKeySize
    |
        /**
         * Type of the imported key.
         *
         * @relation HUKS_TAG_IMPORT_KEY_TYPE = HuksTagType.HUKS_TAG_TYPE_UINT | 25
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagImportKeyType
    |
        /**
         * Algorithm suite required for encrypted imports.
         *
         * @relation HUKS_TAG_UNWRAP_ALGORITHM_SUITE = HuksTagType.HUKS_TAG_TYPE_UINT | 26
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagUnwrapAlgorithmSuite
    |
        /**
         * Storage type of the derived key or agreed key.
         *
         * @relation HUKS_TAG_DERIVED_AGREED_KEY_STORAGE_FLAG = HuksTagType.HUKS_TAG_TYPE_UINT | 29
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagDerivedAgreedKeyStorageFlag
    |
        /**
         * Type of the rsa_pss_salt_length.
         *
         * @relation HUKS_TAG_RSA_PSS_SALT_LEN_TYPE = HuksTagType.HUKS_TAG_TYPE_UINT | 30
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagRsaPssSaltLenType
    |
        /**
         * Reserved.
         *
         * @relation HUKS_TAG_ALL_USERS = HuksTagType.HUKS_TAG_TYPE_BOOL | 301
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagAllUsers
    |
        /**
         * ID of the user to which the key belongs.
         *
         * @relation HUKS_TAG_USER_ID = HuksTagType.HUKS_TAG_TYPE_UINT | 302
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagUserId
    |
        /**
         * Reserved.
         *
         * @relation HUKS_TAG_NO_AUTH_REQUIRED = HuksTagType.HUKS_TAG_TYPE_BOOL | 303
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagNoAuthRequired
    |
        /**
         * User authentication type. For details, see HuksUserAuthType. This parameter must be set together with
         * HuksAuthAccessType. You can set a maximum of two user authentication types at a time. For example, if
         * HuksAuthAccessType is HUKS_SECURE_ACCESS_INVALID_NEW_BIO_ENROLL, you can set the user authentication type to
         * HUKS_USER_AUTH_TYPE_FACE, HUKS_USER_AUTH_TYPE_FINGERPRINT or
         * HUKS_USER_AUTH_TYPE_FACE | HUKS_USER_AUTH_TYPE_FINGERPRINT.
         *
         * @relation HUKS_TAG_USER_AUTH_TYPE = HuksTagType.HUKS_TAG_TYPE_UINT | 304
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    HuksTagUserAuthType
    |
        /**
         * One-time validity period of the authentication token.
         *
         * @relation HUKS_TAG_AUTH_TIMEOUT = HuksTagType.HUKS_TAG_TYPE_UINT | 305
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    HuksTagAuthTimeout
    |
        /**
         * Authentication token.
         *
         * @relation HUKS_TAG_AUTH_TOKEN = HuksTagType.HUKS_TAG_TYPE_BYTES | 306
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    HuksTagAuthToken
    |
        /**
         * Access control type. For details, see HuksAuthAccessType. This parameter must be set together with
         * HuksUserAuthType.
         *
         * @relation HUKS_TAG_KEY_AUTH_ACCESS_TYPE = HuksTagType.HUKS_TAG_TYPE_UINT | 307
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    HuksTagKeyAuthAccessType
    |
        /**
         * Signature type of the key generated or imported.
         *
         * @relation HUKS_TAG_KEY_SECURE_SIGN_TYPE = HuksTagType.HUKS_TAG_TYPE_UINT | 308
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    HuksTagKeySecureSignType
    |
        /**
         * Type of the challenge generated for a key. For details, see HuksChallengeType.
         *
         * @relation HUKS_TAG_CHALLENGE_TYPE = HuksTagType.HUKS_TAG_TYPE_UINT | 309
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    HuksTagChallengeType
    |
        /**
         * Position of the 8-byte valid value in a custom challenge. For details, see HuksChallengePosition.
         *
         * @relation HUKS_TAG_CHALLENGE_POS = HuksTagType.HUKS_TAG_TYPE_UINT | 310
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    HuksTagChallengePos
    |
        /**
         * Key authentication purpose.
         *
         * @relation HUKS_TAG_KEY_AUTH_PURPOSE = HuksTagType.HUKS_TAG_TYPE_UINT | 311
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    HuksTagKeyAuthPurpose
    |
        /**
         * Key authentication purpose.
         *   
         * @relation HUKS_TAG_KEY_AUTH_Storage_Level = HuksTagType.HUKS_TAG_TYPE_UINT | 316
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    HuksTagAuthStorageLevel
    |
        /**
         * Challenge value used in the attestation.
         *
         * @relation HUKS_TAG_ATTESTATION_CHALLENGE = HuksTagType.HUKS_TAG_TYPE_BYTES | 501
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    HuksTagAttestationChallenge
    |
        /**
         * Application ID used in the attestation.
         *
         * @relation HUKS_TAG_ATTESTATION_APPLICATION_ID = HuksTagType.HUKS_TAG_TYPE_BYTES | 502
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    HuksTagAttestationApplicationId
    |
        /**
         * Security level used in the attestation.
         *
         * @relation HUKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO = HuksTagType.HUKS_TAG_TYPE_BYTES | 514
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    HuksTagAttestationIdSecLevelInfo
    |
        /**
         * Version information used in the attestation.
         *
         * @relation HUKS_TAG_ATTESTATION_ID_VERSION_INFO = HuksTagType.HUKS_TAG_TYPE_BYTES | 515
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    HuksTagAttestationIdVersionInfo
    | 
        /**
         * Huks Tag Attestation Base64
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    HuksTagAttestationBase64
    | 
        /**
         * Huks Tag Attestation Mode
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    HuksTagAttestationMode
    | 
        /**
         * Huks Tag Attestation Application Id Type
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    HuksTagAttestationApplicationIdType
    |
        /*
         * Whether to use the alias passed in during key generation.
         *
         * @relation HUKS_TAG_IS_KEY_ALIAS = HuksTagType.HUKS_TAG_TYPE_BOOL | 1001
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagIsKeyAlias
    |
        /*
         * Key storage mode.
         *
         * @relation HUKS_TAG_KEY_STORAGE_FLAG = HuksTagType.HUKS_TAG_TYPE_UINT | 1002
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagKeyStorageFlag
    |
        /*
         * Reserved.
         *
         * @relation HUKS_TAG_IS_ALLOWED_WRAP = HuksTagType.HUKS_TAG_TYPE_BOOL | 1003
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagIsWrapAllowed
    |
        /*
         * Reserved.
         *
         * @relation HUKS_TAG_KEY_WRAP_TYPE = HuksTagType.HUKS_TAG_TYPE_UINT | 1004
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagKeyWrapType
    |
        /*
         * Reserved.
         *
         * @relation HUKS_TAG_KEY_AUTH_ID = HuksTagType.HUKS_TAG_TYPE_BYTES | 1005
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    HuksTagKeyAuthId
    |
        /*
         * Reserved.
         *
         * @relation HUKS_TAG_KEY_ROLE = HuksTagType.HUKS_TAG_TYPE_UINT | 1006
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagKeyRole
    |
        /*
         * Flag of the key.
         *
         * @relation HUKS_TAG_KEY_FLAG = HuksTagType.HUKS_TAG_TYPE_UINT | 1007
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagKeyFlag
    |
        /*
         * Reserved.
         *
         * @relation HUKS_TAG_IS_ASYNCHRONIZED = HuksTagType.HUKS_TAG_TYPE_UINT | 1008
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagIsAsync
    |
        /*
         * Reserved.
         *
         * @relation HUKS_TAG_KEY_DOMAIN = HuksTagType.HUKS_TAG_TYPE_UINT | 1011
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagKeyDomain
    |
        /**
         * Inner-use TAG: 10001 - 10999
         *
         * @relation HUKS_TAG_PROCESS_NAME = HuksTagType.HUKS_TAG_TYPE_BYTES | 10001
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagProcessName
    |   
        /*
         * Reserved.
         *
         * @relation HUKS_TAG_KEY = HuksTagType.HUKS_TAG_TYPE_BYTES | 10006
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagKey
    |
        /**
         * Key version.
         *
         * @relation HUKS_TAG_KEY_VERSION = HuksTagType.HUKS_TAG_TYPE_UINT | 10007
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    HuksTagKeyVersion
    | 
        /*
         * Used to pass in the AEAD in GCM mode.
         *
         * @relation HUKS_TAG_AE_TAG = HuksTagType.HUKS_TAG_TYPE_BYTES | 10009
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagAeTag
    |
        /**
         * Reserved field.
         *
         * @relation HUKS_TAG_IS_KEY_HANDLE = HuksTagType.HUKS_TAG_TYPE_ULONG | 10010
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagIsKeyHandle
    |
        /**
         * Os version related TAG.
         *
         * @relation HUKS_TAG_OS_VERSION = HuksTagType.HUKS_TAG_TYPE_UINT | 10101
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagOsVersion
    |
        /**
         * OS patch level.
         *
         * @relation HUKS_TAG_OS_PATCHLEVEL = HuksTagType.HUKS_TAG_TYPE_UINT | 10102
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagOsPatchLevel
    |
        /*
         * Used to pass in the AEAD in GCM mode.
         *
         * @relation HUKS_TAG_SYMMETRIC_KEY_DATA = HuksTagType.HUKS_TAG_TYPE_BYTES | 20001
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagSymmetricKeyData
    |
        /*
         * Reserved.
         *
         * @relation HUKS_TAG_ASYMMETRIC_PUBLIC_KEY_DATA = HuksTagType.HUKS_TAG_TYPE_BYTES | 20002
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagAsymmetricPublicKeyData
    |
        /*
         * Reserved.
         *
         * @relation HUKS_TAG_ASYMMETRIC_PRIVATE_KEY_DATA = HuksTagType.HUKS_TAG_TYPE_BYTES | 20003
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagAsymmetricPrivateKeyData
    |
        /*
         * Huks Tag Screen State
         *
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagScreenState
    |
        /*
         * Huks Tag Derive Main Key Mode.
         * 
         */
        @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    HuksTagDeriveMainKeyMode
    | ...

    /**
     * get the corresponding mapping value
     *
     * @throws IllegalArgumentException - The type is not supported.
     */
    func getValue(): UInt32 {
        match (this) {
            case HuksTagInvalid => HuksTagType.HUKS_TAG_TYPE_INVALID | 0
            case HuksTagAlgorithm => HuksTagType.HUKS_TAG_TYPE_UINT | 1
            case HuksTagPurpose => HuksTagType.HUKS_TAG_TYPE_UINT | 2
            case HuksTagKeySize => HuksTagType.HUKS_TAG_TYPE_UINT | 3
            case HuksTagDigest => HuksTagType.HUKS_TAG_TYPE_UINT | 4
            case HuksTagPadding => HuksTagType.HUKS_TAG_TYPE_UINT | 5
            case HuksTagBlockMode => HuksTagType.HUKS_TAG_TYPE_UINT | 6
            case HuksTagKeyType => HuksTagType.HUKS_TAG_TYPE_UINT | 7
            case HuksTagAssociatedData => HuksTagType.HUKS_TAG_TYPE_BYTES | 8
            case HuksTagNonce => HuksTagType.HUKS_TAG_TYPE_BYTES | 9
            case HuksTagIv => HuksTagType.HUKS_TAG_TYPE_BYTES | 10
            case HuksTagInfo => HuksTagType.HUKS_TAG_TYPE_BYTES | 11
            case HuksTagSalt => HuksTagType.HUKS_TAG_TYPE_BYTES | 12
            case HuksTagIteration => HuksTagType.HUKS_TAG_TYPE_UINT | 14
            case HuksTagKeyGenerationType => HuksTagType.HUKS_TAG_TYPE_UINT | 15
            case HuksTagAlgForAgreement => HuksTagType.HUKS_TAG_TYPE_UINT | 19
            case HuksTagPublicKeyAliasForAgreement => HuksTagType.HUKS_TAG_TYPE_BOOL | 20
<<<<<<< HEAD
            case HuksTagPrivateKeyAliasForAgreement => HuksTagType.HUKS_TAG_TYPE_BYTES | 21
            case HuksTagPublicKeyForAgreement => HuksTagType.HUKS_TAG_TYPE_BYTES | 22
=======
            case HuksTagAgreePrivateKeyAliasForAgreement => HuksTagType.HUKS_TAG_TYPE_BYTES | 21
            case HuksTagAgreePublicKeyForAgreement => HuksTagType.HUKS_TAG_TYPE_BYTES | 22
>>>>>>> 1726459bfb625301ae080b33e113cf0cdb3e29af
            case HuksTagKeyAlias => HuksTagType.HUKS_TAG_TYPE_BYTES | 23
            case HuksTagDeriveKeySize => HuksTagType.HUKS_TAG_TYPE_UINT | 24
            case HuksTagImportKeyType => HuksTagType.HUKS_TAG_TYPE_UINT | 25
            case HuksTagUnwrapAlgorithmSuite => HuksTagType.HUKS_TAG_TYPE_UINT | 26
            case HuksTagDerivedAgreedKeyStorageFlag => HuksTagType.HUKS_TAG_TYPE_UINT | 29
            case HuksTagRsaPssSaltLenType => HuksTagType.HUKS_TAG_TYPE_UINT | 30
            case HuksTagAllUsers => HuksTagType.HUKS_TAG_TYPE_BOOL | 301
            case HuksTagUserId => HuksTagType.HUKS_TAG_TYPE_UINT | 302
            case HuksTagNoAuthRequired => HuksTagType.HUKS_TAG_TYPE_BOOL | 303
            case HuksTagUserAuthType => HuksTagType.HUKS_TAG_TYPE_UINT | 304
            case HuksTagAuthTimeout => HuksTagType.HUKS_TAG_TYPE_UINT | 305
            case HuksTagAuthToken => HuksTagType.HUKS_TAG_TYPE_BYTES | 306
            case HuksTagKeyAuthAccessType => HuksTagType.HUKS_TAG_TYPE_UINT | 307
            case HuksTagKeySecureSignType => HuksTagType.HUKS_TAG_TYPE_UINT | 308
            case HuksTagChallengeType => HuksTagType.HUKS_TAG_TYPE_UINT | 309
            case HuksTagChallengePos => HuksTagType.HUKS_TAG_TYPE_UINT | 310
            case HuksTagKeyAuthPurpose => HuksTagType.HUKS_TAG_TYPE_UINT | 311
            case HuksTagAuthStorageLevel => HuksTagType.HUKS_TAG_TYPE_UINT | 316
            case HuksTagAttestationChallenge => HuksTagType.HUKS_TAG_TYPE_BYTES | 501
            case HuksTagAttestationApplicationId => HuksTagType.HUKS_TAG_TYPE_BYTES | 502
            case HuksTagAttestationIdSecLevelInfo => HuksTagType.HUKS_TAG_TYPE_BYTES | 514
            case HuksTagAttestationIdVersionInfo => HuksTagType.HUKS_TAG_TYPE_BYTES | 515
            case HuksTagAttestationBase64 => HuksTagType.HUKS_TAG_TYPE_BOOL | 516
            case HuksTagAttestationMode => HuksTagType.HUKS_TAG_TYPE_UINT | 517	
            case HuksTagAttestationApplicationIdType => HuksTagType.HUKS_TAG_TYPE_UINT | 518
            case HuksTagIsKeyAlias => HuksTagType.HUKS_TAG_TYPE_BOOL | 1001
            case HuksTagKeyStorageFlag => HuksTagType.HUKS_TAG_TYPE_UINT | 1002
            case HuksTagIsWrapAllowed => HuksTagType.HUKS_TAG_TYPE_BOOL | 1003
            case HuksTagKeyWrapType => HuksTagType.HUKS_TAG_TYPE_UINT | 1004
            case HuksTagKeyAuthId => HuksTagType.HUKS_TAG_TYPE_BYTES | 1005
            case HuksTagKeyRole => HuksTagType.HUKS_TAG_TYPE_UINT | 1006
            case HuksTagKeyFlag => HuksTagType.HUKS_TAG_TYPE_UINT | 1007
            case HuksTagIsAsync => HuksTagType.HUKS_TAG_TYPE_UINT | 1008
            case HuksTagKeyDomain => HuksTagType.HUKS_TAG_TYPE_UINT | 1011
            case HuksTagProcessName => HuksTagType.HUKS_TAG_TYPE_BYTES | 10001
            case HuksTagKey => HuksTagType.HUKS_TAG_TYPE_BYTES | 10006
            case HuksTagKeyVersion => HuksTagType.HUKS_TAG_TYPE_UINT | 10007
            case HuksTagAeTag => HuksTagType.HUKS_TAG_TYPE_BYTES | 10009
            case HuksTagIsKeyHandle => HuksTagType.HUKS_TAG_TYPE_ULONG | 10010
            case HuksTagOsVersion => HuksTagType.HUKS_TAG_TYPE_UINT | 10101
            case HuksTagOsPatchLevel => HuksTagType.HUKS_TAG_TYPE_UINT | 10102
            case HuksTagSymmetricKeyData => HuksTagType.HUKS_TAG_TYPE_BYTES | 20001
            case HuksTagAsymmetricPublicKeyData => HuksTagType.HUKS_TAG_TYPE_BYTES | 20002
            case HuksTagAsymmetricPrivateKeyData => HuksTagType.HUKS_TAG_TYPE_BYTES | 20003
            case HuksTagScreenState => HuksTagType.HUKS_TAG_TYPE_BOOL | 30024
            case HuksTagDeriveMainKeyMode => HuksTagType.HUKS_TAG_TYPE_UINT | 10026
            case _ => throw IllegalArgumentException("The type is not supported.")
        }
    }

    static func parse(val: UInt32): HuksTag {
        match (val) {
            case 0x20000001 => HuksTagAlgorithm
            case 0x20000002 => HuksTagPurpose
            case 0x20000003 => HuksTagKeySize
            case 0x20000004 => HuksTagDigest
            case 0x20000005 => HuksTagPadding
            case 0x20000006 => HuksTagBlockMode
            case 0x20000007 => HuksTagKeyType
            case 0x50000008 => HuksTagAssociatedData
            case 0x50000009 => HuksTagNonce
            case 0x5000000a => HuksTagIv
            case 0x5000000b => HuksTagInfo
            case 0x5000000c => HuksTagSalt
            case 0x2000000e => HuksTagIteration
            case 0x2000000f => HuksTagKeyGenerationType
            case 0x20000013 => HuksTagAlgForAgreement
            case 0x40000014 => HuksTagPublicKeyAliasForAgreement
<<<<<<< HEAD
            case 0x50000015 => HuksTagPrivateKeyAliasForAgreement
            case 0x50000016 => HuksTagPublicKeyForAgreement
=======
            case 0x50000015 => HuksTagAgreePrivateKeyAliasForAgreement
            case 0x50000016 => HuksTagAgreePublicKeyForAgreement
>>>>>>> 1726459bfb625301ae080b33e113cf0cdb3e29af
            case 0x50000017 => HuksTagKeyAlias
            case 0x20000018 => HuksTagDeriveKeySize
            case 0x20000019 => HuksTagImportKeyType
            case 0x2000001a => HuksTagUnwrapAlgorithmSuite
            case 0x2000001d => HuksTagDerivedAgreedKeyStorageFlag
            case 0x2000001e => HuksTagRsaPssSaltLenType
            case 0x4000012d => HuksTagAllUsers
            case 0x2000012e => HuksTagUserId
            case 0x4000012f => HuksTagNoAuthRequired
            case 0x20000130 => HuksTagUserAuthType
            case 0x20000131 => HuksTagAuthTimeout
            case 0x50000132 => HuksTagAuthToken
            case 0x20000133 => HuksTagKeyAuthAccessType
            case 0x20000134 => HuksTagKeySecureSignType
            case 0x20000135 => HuksTagChallengeType
            case 0x20000136 => HuksTagChallengePos
            case 0x20000137 => HuksTagKeyAuthPurpose
            case 0x2000013c => HuksTagAuthStorageLevel
            case 0x500001f5 => HuksTagAttestationChallenge
            case 0x500001f6 => HuksTagAttestationApplicationId
            case 0x50000202 => HuksTagAttestationIdSecLevelInfo
            case 0x50000203 => HuksTagAttestationIdVersionInfo
            case 0x40000204 => HuksTagAttestationBase64
            case 0x20000205 => HuksTagAttestationMode
            case 0x20000206 => HuksTagAttestationApplicationIdType
            case 0x400003e9 => HuksTagIsKeyAlias
            case 0x200003ea => HuksTagKeyStorageFlag
            case 0x400003eb => HuksTagIsWrapAllowed
            case 0x200003ec => HuksTagKeyWrapType
            case 0x500003ed => HuksTagKeyAuthId
            case 0x200003ee => HuksTagKeyRole
            case 0x200003ef => HuksTagKeyFlag
            case 0x200003f0 => HuksTagIsAsync           
            case 0x200003f3 => HuksTagKeyDomain
            case 0x50002711 => HuksTagProcessName
            case 0x50002716 => HuksTagKey
            case 0x20002717 => HuksTagKeyVersion
            case 0x50002719 => HuksTagAeTag
            case 0x3000271a => HuksTagIsKeyHandle
            case 0x20002775 => HuksTagOsVersion
            case 0x20002776 => HuksTagOsPatchLevel
            case 0x50004e21 => HuksTagSymmetricKeyData
            case 0x50004e22 => HuksTagAsymmetricPublicKeyData
            case 0x50004e23 => HuksTagAsymmetricPrivateKeyData
            case 0x40007548 => HuksTagScreenState
            case 0x2000272a => HuksTagDeriveMainKeyMode
            case _ => throw IllegalArgumentException("The type is not supported.")
        }
    }
}

const HKS_SUCCESS: Int32 = 0
const HKS_ERROR_NOT_EXIST: Int32 = -13
