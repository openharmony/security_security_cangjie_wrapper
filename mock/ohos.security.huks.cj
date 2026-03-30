/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

import ohos.labels.APILevel

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksKeyPurpose {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_PURPOSE_ENCRYPT: UInt32 = 1

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_PURPOSE_DECRYPT: UInt32 = 2

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_PURPOSE_SIGN: UInt32 = 4

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_PURPOSE_VERIFY: UInt32 = 8

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_PURPOSE_DERIVE: UInt32 = 16

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_PURPOSE_WRAP: UInt32 = 32

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_PURPOSE_UNWRAP: UInt32 = 64

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_PURPOSE_MAC: UInt32 = 128

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_PURPOSE_AGREE: UInt32 = 256
    
    init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksKeyDigest {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_DIGEST_NONE: UInt32 = 0

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_DIGEST_MD5: UInt32 = 1

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_DIGEST_SM3: UInt32 = 2

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_DIGEST_SHA1: UInt32 = 10

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_DIGEST_SHA224: UInt32 = 11

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_DIGEST_SHA256: UInt32 = 12

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_DIGEST_SHA384: UInt32 = 13

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_DIGEST_SHA512: UInt32 = 14
    
    init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksKeyPadding {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_PADDING_NONE: UInt32 = 0

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_PADDING_OAEP: UInt32 = 1

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_PADDING_PSS: UInt32 = 2

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_PADDING_PKCS1_V1_5: UInt32 = 3

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_PADDING_PKCS5: UInt32 = 4

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_PADDING_PKCS7: UInt32 = 5
    
    init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksCipherMode {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_MODE_ECB: UInt32 = 1

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_MODE_CBC: UInt32 = 2

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_MODE_CTR: UInt32 = 3

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_MODE_OFB: UInt32 = 4

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_MODE_CCM: UInt32 = 31

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_MODE_GCM: UInt32 = 32
    
    init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksKeySize {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_RSA_KEY_SIZE_512: UInt32 = 512

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_RSA_KEY_SIZE_768: UInt32 = 768

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_RSA_KEY_SIZE_1024: UInt32 = 1024

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_RSA_KEY_SIZE_2048: UInt32 = 2048

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_RSA_KEY_SIZE_3072: UInt32 = 3072

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_RSA_KEY_SIZE_4096: UInt32 = 4096

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ECC_KEY_SIZE_224: UInt32 = 224

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ECC_KEY_SIZE_256: UInt32 = 256

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ECC_KEY_SIZE_384: UInt32 = 384

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ECC_KEY_SIZE_521: UInt32 = 521

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_AES_KEY_SIZE_128: UInt32 = 128

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_AES_KEY_SIZE_192: UInt32 = 192

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_AES_KEY_SIZE_256: UInt32 = 256

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_CURVE25519_KEY_SIZE_256: UInt32 = 256

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_DH_KEY_SIZE_2048: UInt32 = 2048

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_DH_KEY_SIZE_3072: UInt32 = 3072

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_DH_KEY_SIZE_4096: UInt32 = 4096

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_SM2_KEY_SIZE_256: UInt32 = 256

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_SM4_KEY_SIZE_128: UInt32 = 128
    
    init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksKeyAlg {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_RSA: UInt32 = 1

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_ECC: UInt32 = 2

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_DSA: UInt32 = 3

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_AES: UInt32 = 20

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_HMAC: UInt32 = 50

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_HKDF: UInt32 = 51

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_PBKDF2: UInt32 = 52

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_ECDH: UInt32 = 100

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_X25519: UInt32 = 101

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_ED25519: UInt32 = 102

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_DH: UInt32 = 103

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_SM2: UInt32 = 150

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_SM3: UInt32 = 151

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_ALG_SM4: UInt32 = 152
    
    init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksUnwrapSuite {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_UNWRAP_SUITE_X25519_AES_256_GCM_NO_PADDING: UInt32 = 1

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_UNWRAP_SUITE_ECDH_AES_256_GCM_NO_PADDING: UInt32 = 2
    
    init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksAuthStorageLevel {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_AUTH_STORAGE_LEVEL_DE: UInt32 = 0

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_AUTH_STORAGE_LEVEL_CE: UInt32 = 1

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_AUTH_STORAGE_LEVEL_ECE: UInt32 = 2
    
    init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksKeyGenerationType {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_GENERATE_TYPE_DEFAULT: UInt32 = 0

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_GENERATE_TYPE_DERIVE: UInt32 = 1

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_GENERATE_TYPE_AGREE: UInt32 = 2
    
    init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksKeyFlag {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_FLAG_IMPORT_KEY: UInt32 = 1

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_FLAG_GENERATE_KEY: UInt32 = 2

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_FLAG_AGREE_KEY: UInt32 = 3

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_FLAG_DERIVE_KEY: UInt32 = 4
    
    init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksKeyStorageType {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_STORAGE_ONLY_USED_IN_HUKS: UInt32 = 2

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_STORAGE_KEY_EXPORT_ALLOWED: UInt32 = 3
    
    init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksImportKeyType {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_TYPE_PUBLIC_KEY: UInt32 = 0

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_TYPE_PRIVATE_KEY: UInt32 = 1

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_KEY_TYPE_KEY_PAIR: UInt32 = 2
    
    init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksRsaPssSaltLenType {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_RSA_PSS_SALT_LEN_DIGEST: UInt32 = 0

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_RSA_PSS_SALT_LEN_MAX: UInt32 = 1
    
    init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension"
]
public class HuksUserAuthType {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_USER_AUTH_TYPE_FINGERPRINT: UInt32 = 1 << 0

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_USER_AUTH_TYPE_FACE: UInt32 = 1 << 1

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_USER_AUTH_TYPE_PIN: UInt32 = 1 << 2
    
    init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension"
]
public class HuksAuthAccessType {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_AUTH_ACCESS_INVALID_CLEAR_PASSWORD: UInt32 = 1 << 0

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_AUTH_ACCESS_INVALID_NEW_BIO_ENROLL: UInt32 = 1 << 1
    
    init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension"
]
public class HuksChallengeType {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_CHALLENGE_TYPE_NORMAL: UInt32 = 0

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_CHALLENGE_TYPE_CUSTOM: UInt32 = 1

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_CHALLENGE_TYPE_NONE: UInt32 = 2
    
    init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension"
]
public class HuksChallengePosition {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_CHALLENGE_POS_0: UInt32 = 0

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_CHALLENGE_POS_1: UInt32 = 1

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_CHALLENGE_POS_2: UInt32 = 2

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_CHALLENGE_POS_3: UInt32 = 3
    
    init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension"
]
public class HuksSecureSignType {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_SECURE_SIGN_WITH_AUTH_INFO: UInt32 = 1
    
    init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksTagType {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_TYPE_INVALID: UInt32 = 0 << 28

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_TYPE_INT: UInt32 = 1 << 28

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_TYPE_UINT: UInt32 = 2 << 28

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_TYPE_ULONG: UInt32 = 3 << 28

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_TYPE_BOOL: UInt32 = 4 << 28

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_TYPE_BYTES: UInt32 = 5 << 28
    
    init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksTag {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_ALGORITHM: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 1

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_PURPOSE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 2

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_KEY_SIZE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 3

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_DIGEST: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 4

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_PADDING: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 5

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_BLOCK_MODE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 6

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_KEY_TYPE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 7

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_ASSOCIATED_DATA: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 8

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_NONCE: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 9

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_IV: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 10

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_INFO: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 11

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_SALT: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 12

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_ITERATION: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 14

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_KEY_GENERATION_TYPE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 15

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_ALG_FOR_AGREEMENT: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 19

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_AGREE_PUBLIC_KEY_IS_KEY_ALIAS: UInt32 = HuksTagType.HUKS_TAG_TYPE_BOOL | 20

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_PRIVATE_KEY_ALIAS_FOR_AGREEMENT: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 21

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_PUBLIC_KEY_FOR_AGREEMENT: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 22

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_KEY_ALIAS: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 23

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_DERIVE_KEY_SIZE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 24

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_IMPORT_KEY_TYPE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 25

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_UNWRAP_ALGORITHM_SUITE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 26

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_DERIVED_AGREED_KEY_STORAGE_FLAG: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 29

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_RSA_PSS_SALT_LEN_TYPE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 30

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_USER_ID: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 302

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_NO_AUTH_REQUIRED: UInt32 = HuksTagType.HUKS_TAG_TYPE_BOOL | 303

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_TAG_USER_AUTH_TYPE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 304

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_TAG_AUTH_TIMEOUT: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 305

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_TAG_AUTH_TOKEN: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 306

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_TAG_KEY_AUTH_ACCESS_TYPE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 307

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_TAG_KEY_SECURE_SIGN_TYPE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 308

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_TAG_CHALLENGE_TYPE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 309

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_TAG_CHALLENGE_POS: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 310

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_TAG_KEY_AUTH_PURPOSE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 311

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_TAG_AUTH_STORAGE_LEVEL: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 316

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_TAG_ATTESTATION_CHALLENGE: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 501

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_IS_KEY_ALIAS: UInt32 = HuksTagType.HUKS_TAG_TYPE_BOOL | 1001

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_KEY_STORAGE_FLAG: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 1002

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_IS_ALLOWED_WRAP: UInt32 = HuksTagType.HUKS_TAG_TYPE_BOOL | 1003

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_KEY_WRAP_TYPE: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 1004

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Extension"
    ]
    public static const HUKS_TAG_KEY_AUTH_ID: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 1005

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_KEY_FLAG: UInt32 = HuksTagType.HUKS_TAG_TYPE_UINT | 1007

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_KEY: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 10006

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public static const HUKS_TAG_AE_TAG: UInt32 = HuksTagType.HUKS_TAG_TYPE_BYTES | 10009
    
    init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension",
    throwexception: true,
    workerthread: true
]
public func hasKeyItem(keyAlias: String, options: HuksOptions): Bool {
    return true
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension",
    throwexception: true,
    workerthread: true
]
public func getKeyItemProperties(keyAlias: String, _: HuksOptions): Array<HuksParam> {
    return Array()
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension",
    throwexception: true,
    workerthread: true
]
public func anonAttestKeyItem(keyAlias: String, options: HuksOptions): Array<String> {
    return Array()
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension",
    throwexception: true,
    workerthread: true
]
public func exportKeyItem(keyAlias: String, _: HuksOptions): Bytes {
    return Array()
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension",
    throwexception: true,
    workerthread: true
]
public func importWrappedKeyItem(keyAlias: String, wrappingKeyAlias: String, options: HuksOptions): Unit {
    return ()
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension",
    throwexception: true,
    workerthread: true
]
public func generateKeyItem(keyAlias: String, options: HuksOptions): Unit {
    return ()
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension",
    throwexception: true,
    workerthread: true
]
public func deleteKeyItem(keyAlias: String, options: HuksOptions): Unit {
    return ()
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension",
    throwexception: true,
    workerthread: true
]
public func importKeyItem(keyAlias: String, options: HuksOptions): Unit {
    return ()
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension",
    throwexception: true,
    workerthread: true
]
public func initSession(keyAlias: String, options: HuksOptions): HuksSessionHandle {
    return HuksSessionHandle()
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension",
    throwexception: true,
    workerthread: true
]
public func updateSession(handle: HuksHandleId, options: HuksOptions, token!: Bytes = Bytes()): Option<Bytes> {
    return None
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension",
    throwexception: true,
    workerthread: true
]
public func finishSession(handle: HuksHandleId, options: HuksOptions, token!: Bytes = Bytes()): Option<Bytes> {
    return None
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension",
    throwexception: true,
    workerthread: true
]
public func abortSession(handle: HuksHandleId, options: HuksOptions): Unit {
    return ()
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksParam {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public var tag: UInt32

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public var value: HuksParamValue

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public init(tag: UInt32, value: HuksParamValue) {
        super()
        this.tag = 0
        this.value = HuksParamValue.BooleanValue(true)
    }
}

public type Bytes = Array<UInt8>

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Core"
]
public enum HuksParamValue {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    BooleanValue(Bool)
    |
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    Int32Value(Int32)
    |
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    Uint32Value(UInt32)
    |
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    Uint64Value(UInt64)
    |
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    BytesValue(Bytes)
    | ...
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksOptions {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public var properties: Array<HuksParam>

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public var inData: Bytes

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public init(properties!: Array<HuksParam> = Array<HuksParam>(), inData!: Bytes = Bytes()) {
        super()
        this.properties = Array()
        this.inData = Array()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksSessionHandle {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public var handle: HuksHandleId

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public var challenge: Bytes
    
    public init() {
        super()
        this.handle = HuksHandleId()
        this.challenge = Array()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension"
]
public class HuksHandleId {
    
    public init() {
        super()
    }
}
