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
 */
enum HuksExceptionErrCode {
   /**
    * Permission verification failed.
    *
    */
   HuksErrCodePermissionFail
   |
    /**
     * Invalid parameters are detected. Possible causes:
     * 1. Mandatory parameters are left unspecified.
     * 2. Incorrect parameter types.
     * 3. Parameter verification failed.
     *
     */
    HuksErrCodeIllegalArgument
    |
    /**
     * The API is not supported.
     *
     */
    HuksErrCodeNotSupportedApi
    |
    /**
     * The feature is not supported.
     *
     */
    HuksErrCodeFeatureNotSupported
    |
    /**
     * Key algorithm parameters are missing.
     *
     */
    HuksErrCodeMissingCryptoAlgArgument
    |
    /**
     * Invalid key algorithm parameters are detected.
     *
     */
    HuksErrCodeInvalidCryptoAlgArgument
    |
    /**
     * The file operation failed.
     *
     */
    HuksErrCodeFileOperationFail
    |
    /**
     * The communication failed.
     *
     */
    HuksErrCodeCommunicationFail
    |
    /**
     * Failed to operate the algorithm library.
     *
     */
    HuksErrCodeCryptoFail
    |
    /**
     * Failed to access the key because the key has expired.
     *
     */
    HuksErrCodeKeyAuthPermanentlyInvalidated
    |
    /**
     * Failed to access the key because the authentication has failed.
     *
     */
    HuksErrCodeKeyAuthVerifyFailed
    |
    /**
     * Key access timed out.
     *
     */
    HuksErrCodeKeyAuthTimeOut
    |
    /**
     * The number of key operation sessions has reached the limit.
     *
     */
    HuksErrCodeSessionLimit
    |
    /**
     * The target object does not exist.
     *
     */
    HuksErrCodeItemNotExist
    |
    /**
     * An external error occurs.
     *
     */
    HuksErrCodeExternalError
    |
    /**
     * The credential does not exist.
     *
     */
    HuksErrCodeCredentialNotExist
    |
    /**
     * The memory is insufficient.
     *
     */
    HuksErrCodeInsufficientMemory
    |
    /**
     * Failed to call other system services.
     *
     */
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
    public static const HUKS_KEY_PURPOSE_ENCRYPT: UInt32 = 1
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
    public static const HUKS_KEY_PURPOSE_DECRYPT: UInt32 = 2
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
    public static const HUKS_KEY_PURPOSE_SIGN: UInt32 = 4
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
    public static const HUKS_KEY_PURPOSE_VERIFY: UInt32 = 8
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
    public static const HUKS_KEY_PURPOSE_DERIVE: UInt32 = 16
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
    public static const HUKS_KEY_PURPOSE_WRAP: UInt32 = 32
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
    public static const HUKS_KEY_PURPOSE_UNWRAP: UInt32 = 64
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
    public static const HUKS_KEY_PURPOSE_MAC: UInt32 = 128
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
    public static const HUKS_KEY_PURPOSE_AGREE: UInt32 = 256
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
    public static const HUKS_DIGEST_NONE: UInt32 = 0
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
    public static const HUKS_DIGEST_MD5: UInt32 = 1
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
    public static const HUKS_DIGEST_SM3: UInt32 = 2
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
    public static const HUKS_DIGEST_SHA1: UInt32 = 10
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
    public static const HUKS_DIGEST_SHA224: UInt32 = 11
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
    public static const HUKS_DIGEST_SHA256: UInt32 = 12
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
    public static const HUKS_DIGEST_SHA384: UInt32 = 13
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
    public static const HUKS_DIGEST_SHA512: UInt32 = 14
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
    public static const HUKS_PADDING_NONE: UInt32 = 0
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
    public static const HUKS_PADDING_OAEP: UInt32 = 1
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
    public static const HUKS_PADDING_PSS: UInt32 = 2
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
    public static const HUKS_PADDING_PKCS1_V1_5: UInt32 = 3
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
    public static const HUKS_PADDING_PKCS5: UInt32 = 4
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
    public static const HUKS_PADDING_PKCS7: UInt32 = 5
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
    public static const HUKS_MODE_ECB: UInt32 = 1
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
    public static const HUKS_MODE_CBC: UInt32 = 2
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
    public static const HUKS_MODE_CTR: UInt32 = 3
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
    public static const HUKS_MODE_OFB: UInt32 = 4
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
    public static const HUKS_MODE_CCM: UInt32 = 31
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
   public static const HUKS_MODE_GCM: UInt32 = 32
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
    public static const HUKS_RSA_KEY_SIZE_512: UInt32 = 512
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
    public static const HUKS_RSA_KEY_SIZE_768: UInt32 = 768
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
    public static const HUKS_RSA_KEY_SIZE_1024: UInt32 = 1024
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
    public static const HUKS_RSA_KEY_SIZE_2048: UInt32 = 2048
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
    public static const HUKS_RSA_KEY_SIZE_3072: UInt32 = 3072
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
    public static const HUKS_RSA_KEY_SIZE_4096: UInt32 = 4096
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
    public static const HUKS_ECC_KEY_SIZE_224: UInt32 = 224
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
    public static const HUKS_ECC_KEY_SIZE_256: UInt32 = 256
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
    public static const HUKS_ECC_KEY_SIZE_384: UInt32 = 384
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
    public static const HUKS_ECC_KEY_SIZE_521: UInt32 = 521
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
    public static const HUKS_AES_KEY_SIZE_128: UInt32 = 128

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
    public static const HUKS_AES_KEY_SIZE_192: UInt32 = 192
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
    public static const HUKS_AES_KEY_SIZE_256: UInt32 = 256
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
    public static const HUKS_CURVE25519_KEY_SIZE_256: UInt32 = 256
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
    public static const HUKS_DH_KEY_SIZE_2048: UInt32 = 2048
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
    public static const HUKS_DH_KEY_SIZE_3072: UInt32 = 3072
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
    public static const HUKS_DH_KEY_SIZE_4096: UInt32 = 4096
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
    public static const HUKS_SM2_KEY_SIZE_256: UInt32 = 256
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
    public static const HUKS_SM4_KEY_SIZE_128: UInt32 = 128
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
    public static const HUKS_ALG_RSA: UInt32 = 1
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
    public static const HUKS_ALG_ECC: UInt32 = 2
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
    public static const HUKS_ALG_DSA: UInt32 = 3
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
    public static const HUKS_ALG_AES: UInt32 = 20
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
    public static const HUKS_ALG_HMAC: UInt32 = 50
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
    public static const HUKS_ALG_HKDF: UInt32 = 51
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
    public static const HUKS_ALG_PBKDF2: UInt32 = 52
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
    public static const HUKS_ALG_ECDH: UInt32 = 100
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
    public static const HUKS_ALG_X25519: UInt32 = 101
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
    public static const HUKS_ALG_ED25519: UInt32 = 102
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
    public static const HUKS_ALG_DH: UInt32 = 103
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
    public static const HUKS_ALG_SM2: UInt32 = 150
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
    public static const HUKS_ALG_SM3: UInt32 = 151
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
    public static const HUKS_ALG_SM4: UInt32 = 152
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
    public static const HUKS_UNWRAP_SUITE_X25519_AES_256_GCM_NOPADDING: UInt32 = 1
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
    public static const HUKS_UNWRAP_SUITE_ECDH_AES_256_GCM_NOPADDING: UInt32 = 2
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
    public static const HUKS_AUTH_STORAGE_LEVEL_DE: UInt32 = 0
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
    public static const HUKS_AUTH_STORAGE_LEVEL_CE: UInt32 = 1
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
    public static const HUKS_AUTH_STORAGE_LEVEL_ECE: UInt32 = 2
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
    public static const HUKS_KEY_GENERATE_TYPE_DEFAULT: UInt32 = 0
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
    public static const HUKS_KEY_GENERATE_TYPE_DERIVE: UInt32 = 1
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
    public static const HUKS_KEY_GENERATE_TYPE_AGREE: UInt32 = 2
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
    public static const HUKS_KEY_FLAG_IMPORT_KEY: UInt32 = 1
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
    public static const HUKS_KEY_FLAG_GENERATE_KEY: UInt32 = 2
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
    public static const HUKS_KEY_FLAG_AGREE_KEY: UInt32 = 3
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
    public static const HUKS_KEY_FLAG_DERIVE_KEY: UInt32 = 4
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
    public static const HUKS_STORAGE_ONLY_USED_IN_HUKS: UInt32 = 2
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
    public static const HUKS_STORAGE_KEY_EXPORT_ALLOWED: UInt32 = 3
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
    public static const HUKS_KEY_TYPE_PUBLIC_KEY: UInt32 = 0
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
   public static const HUKS_KEY_TYPE_PRIVATE_KEY: UInt32 = 1
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
   public static const HUKS_KEY_TYPE_KEY_PAIR: UInt32 = 2
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
    public static const HUKS_RSA_PSS_SALT_LEN_DIGEST: UInt32 = 0
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
    public static const HUKS_RSA_PSS_SALT_LEN_MAX: UInt32 = 1
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
    public static const HUKS_USER_AUTH_TYPE_FINGERPRINT: UInt32 = 1 << 0
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
    public static const HUKS_USER_AUTH_TYPE_FACE: UInt32 = 1 << 1
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
    public static const HUKS_USER_AUTH_TYPE_PIN: UInt32 = 1 << 2
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
    public static const HUKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD: UInt32 = 1 << 0
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
    public static const HUKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL: UInt32 = 1 << 1
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
    public static const HUKS_CHALLENGE_TYPE_NORMAL: UInt32 = 0
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
    public static const HUKS_CHALLENGE_TYPE_CUSTOM: UInt32 = 1
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
    public static const HUKS_CHALLENGE_TYPE_NONE: UInt32 = 2
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
    public static const HUKS_CHALLENGE_POS_0: UInt32 = 0
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
    public static const HUKS_CHALLENGE_POS_1: UInt32 = 1
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
    public static const HUKS_CHALLENGE_POS_2: UInt32 = 2
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
    public static const HUKS_CHALLENGE_POS_3: UInt32 = 3
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
    public static const HUKS_SECURE_SIGN_WITH_AUTHINFO: UInt32 = 1
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
public class HuksTag {
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
    public static const HUKS_TAG_ALGORITHM: UInt32 =  HuksTagType.HUKS_TAG_TYPE_UINT | 1
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
    public static const HUKS_TAG_PURPOSE: UInt32 =  HuksTagType.HUKS_TAG_TYPE_UINT | 2
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
    public static const HUKS_TAG_KEY_SIZE: UInt32 =  HuksTagType.HUKS_TAG_TYPE_UINT | 3
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
    public static const HUKS_TAG_DIGEST: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 4
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
    public static const HUKS_TAG_PADDING: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 5
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
    public static const HUKS_TAG_BLOCK_MODE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 6
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
    public static const HUKS_TAG_KEY_TYPE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 7
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
    public static const HUKS_TAG_ASSOCIATED_DATA: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 8
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
    public static const HUKS_TAG_NONCE: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 9
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
    public static const HUKS_TAG_IV: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 10
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
    public static const HUKS_TAG_INFO: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 11
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
    public static const HUKS_TAG_SALT: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 12  
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
    public static const HUKS_TAG_ITERATION: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 14
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
    public static const HUKS_TAG_KEY_GENERATE_TYPE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 15
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
    public static const HUKS_TAG_AGREE_ALG: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 19
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
    public static const HUKS_TAG_AGREE_PUBLIC_KEY_IS_KEY_ALIAS: UInt32 = HuksTagType.HUKS_TAG_TYPE_BOOL | 20
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
    public static const HUKS_TAG_AGREE_PRIVATE_KEY_ALIAS: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 21
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
    public static const HUKS_TAG_AGREE_PUBLIC_KEY: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 22
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
    public static const HUKS_TAG_KEY_ALIAS: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 23
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
    public static const HUKS_TAG_DERIVE_KEY_SIZE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 24
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
    public static const HUKS_TAG_IMPORT_KEY_TYPE: UInt32 =  HuksTagType.HUKS_TAG_TYPE_UINT | 25
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
    public static const HUKS_TAG_UNWRAP_ALGORITHM_SUITE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 26
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
    public static const HUKS_TAG_DERIVED_AGREED_KEY_STORAGE_FLAG: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 29
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
    public static const HUKS_TAG_RSA_PSS_SALT_LEN_TYPE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 30
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
    public static const HUKS_TAG_USER_ID: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 302
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
    public static const HUKS_TAG_NO_AUTH_REQUIRED: UInt32 = HuksTagType.HUKS_TAG_TYPE_BOOL | 303
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
    public static const HUKS_TAG_USER_AUTH_TYPE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 304
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
    public static const HUKS_TAG_AUTH_TIMEOUT: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 305
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
    public static const HUKS_TAG_AUTH_TOKEN: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 306
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
    public static const HUKS_TAG_KEY_AUTH_ACCESS_TYPE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 307
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
    public static const HUKS_TAG_KEY_SECURE_SIGN_TYPE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 308
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
    public static const HUKS_TAG_CHALLENGE_TYPE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 309
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
    public static const HUKS_TAG_CHALLENGE_POS: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 310
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
    public static const HUKS_TAG_KEY_AUTH_PURPOSE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 311
    /**
     * Key authentication purpose.
     *   
     * @relation HUKS_TAG_AUTH_STORAGE_LEVEL = HuksTagType.HUKS_TAG_TYPE_UINT | 316
     */
    @!APILevel[
        21,
        stagemodelonly: true,
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_TAG_AUTH_STORAGE_LEVEL: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 316
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
    public static const HUKS_TAG_ATTESTATION_CHALLENGE: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 501
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
    public static const HUKS_TAG_IS_KEY_ALIAS: UInt32 = HuksTagType.HUKS_TAG_TYPE_BOOL | 1001
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
    public static const HUKS_TAG_KEY_STORAGE_FLAG: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 1002
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
    public static const HUKS_TAG_IS_ALLOWED_WRAP: UInt32 = HuksTagType.HUKS_TAG_TYPE_BOOL | 1003
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
    public static const HUKS_TAG_KEY_WRAP_TYPE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 1004
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
    public static const HUKS_TAG_KEY_AUTH_ID: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 1005
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
    public static const HUKS_TAG_KEY_FLAG: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 1007
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
    public static const HUKS_TAG_KEY: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 10006
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
    public static const HUKS_TAG_AE_TAG: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 10009
    /*
     * Huks Tag Attestation Base64
     *
     */
    static const HUKS_ATTESTATION_BASE64: UInt32 = HuksTagType.HUKS_TAG_TYPE_BOOL | 516 

    /*
     * check value
     *
     */
    static func checkValid(val: UInt32): Bool {
        match (val) {
            case 0x20000001 => true
            case 0x20000002 => true
            case 0x20000003 => true
            case 0x20000004 => true
            case 0x20000005 => true
            case 0x20000006 => true
            case 0x20000007 => true
            case 0x50000008 => true
            case 0x50000009 => true
            case 0x5000000a => true
            case 0x5000000b => true
            case 0x5000000c => true
            case 0x2000000e => true
            case 0x2000000f => true
            case 0x20000013 => true
            case 0x40000014 => true
            case 0x50000015 => true
            case 0x50000016 => true
            case 0x50000017 => true
            case 0x20000018 => true
            case 0x20000019 => true
            case 0x2000001a => true
            case 0x2000001d => true
            case 0x2000001e => true
            case 0x2000012e => true
            case 0x4000012f => true
            case 0x20000130 => true
            case 0x20000131 => true
            case 0x50000132 => true
            case 0x20000133 => true
            case 0x20000134 => true
            case 0x20000135 => true
            case 0x20000136 => true
            case 0x20000137 => true
            case 0x2000013c => true
            case 0x500001f5 => true
            case 0x40000204 => true
            case 0x400003e9 => true
            case 0x200003ea => true
            case 0x400003eb => true
            case 0x200003ec => true
            case 0x500003ed => true
            case 0x200003ef => true
            case 0x50002716 => true
            case 0x50002719 => true
            case _ => false
        }
    }
}

const HKS_SUCCESS: Int32 = 0
const HKS_ERROR_NOT_EXIST: Int32 = -13
