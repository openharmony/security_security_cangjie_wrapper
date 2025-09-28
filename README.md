# security_security_cangjie_wrapper

## Introduction

The security subsystem provides capabilities to protect the system security, data security, and application security of OpenHarmony.

The current supported functions of the security foundation capability Cangjie interface include basic encryption and decryption algorithms, huks management functions, and huks session functions.

The security cangjie interface currently under development only supports standard devices.

## Architecture
**Figure 1** security_cangjie_wrapper architecture

![security_cangjie_wrapper architecture](figures/security_cangjie_wrapper_architecture_en.png "security_cangjie_wrapper architecture")

As shown in the architecture diagram:

interface:

- Crypto Algorithm Interface: The primary purpose of the basic crypto algorithm functionality is to abstract the underlying hardware and algorithm libraries, providing a unified crypto algorithm interface for upper-layer applications. Its key features include crypto operations, key material and generator management, encryption/decryption, signature/verification, secure random number generation, and related functionalities. By leveraging this capability, developers can ignore the differences among various third-party algorithm libraries, enabling rapid development.
- Huks Management Interface: The huks management functionality is designed to offer a complete, unified, and secure key lifecycle management interface for upper-layer applications, shielding them from the implementation differences of underlying hardware security modules (HSMs) and key management services. Its core operations include key generation and derivation, key storage, key import, key destruction, and other critical processes. By utilizing this functionality, developers can bypass the complexities and security policy variations of different key storage mediums, ensuring the confidentiality, integrity, and availability of key materials. This facilitates secure, reliable, and efficient business development.
- Huks Session Interface: The huks session functionality is one of the core security capabilities provided by the HUKS system. Built upon a unified key management foundation, its primary goal is to offer upper-layer applications a secure and efficient mechanism for key negotiation and encrypted data communication. HUKS leverages the key session functionality to perform data operations and providesAPIs for developers.

framework:

- Crypto Algorithm Wrapper: Provides Implementation encapsulation of Cangjie Crypto Algorithm, providing Crypto Algorithm capabilities.
- Huks Management Wrapper: Provides Implementation encapsulation of Cangjie Huks Management, providing Huks Management capabilities.
- Huks Session Wrapper: Provides Implementation encapsulation of Cangjie Huks Session, providing Huks Session capabilities.
- FFI Interface Definition for Cangjie Safebase: Responsible for defining the C Language interoperability Cangjie interface, which is used to realize the Cangjie Safebase capabilities.

- Explanation of Dependencies in the Architecture Diagram:

- Crypto Framework: Responsible for providing functions related to encryption and decryption, signature and verification, message authentication codes, hashing, secure random numbers, etc.
- HUKS: Responsible for providing keystore capabilities, including functions such as key management and cryptographic operations on keys.
- cangjie_ark_interop: Responsible for providing Cangjie APILevel class definitions, which are used to annotate APIs, as well as providing the definition of BusinessException class that is thrown to users.
- hiviewdfx_cangjie_wrapper: Responsible for providing logging interfaces, which are used to print logs at key points in the execution path.

## Directory Structure

```
base/security/security_cangjie_wrapper
├── figures                         # Architecture Pictures
├── kit                             # Cangjie Kit Code
|   ├── CryptoArchitectureKit       # Encryption and Decryption Algorithms Kit
|   ├── UniversalKeystoreKit        # Huks Management And Huks Session Kit
├── ohos                            # Cangjie Security Code
|   ├── crypto_framework           # Encryption And Decryption Algorithms Interface
|   └── huks                       # Huks Management And Huks Seesion Interface
|       ├── huks_key_item.cj        # Huks Management Interface
|       └── huks_session.cj         # Huks Seesion Interface
└── test                            # Cangjie test code
    ├── crypto                      # crypto test code
    └── security_huks               # security_huks test code
```

## Usage

The security_cangjie_wrapper provides the following capabilities:

- Basic Encryption and Decryption Capabilities.
- Huks Management.
- Huks Session.

For security APIs, please refer to[Keystore Capability](https://gitcode.com/openharmony-sig/arkcompiler_cangjie_ark_interop/blob/master/doc/API_Reference/source_en/apis/UniversalKeystoreKit/cj-apis-security_huks.md). [Cryptographic Algorithm Library Framework](https://gitcode.com/openharmony-sig/arkcompiler_cangjie_ark_interop/blob/master/doc/API_Reference/source_en/apis/CryptoArchitectureKit/cj-apis-crypto.md).
For relevation guidance, please refer to [security Development Guide](https://gitcode.com/openharmony-sig/arkcompiler_cangjie_ark_interop/tree/master/doc/Dev_Guide/source_en/security).

## Constraints

Compared to ArkTS, the following features are currently not supporte:

- Program Access Control.
- Certificate Module.
- User Authentication.
- Crypto Plugin Functionality.

## Code Contribution

Developers are welcome to contribute code, documentation, etc. For specific contribution processes and methods, please refer to [Code Contribution](https://gitcode.com/openharmony/docs/blob/master/en/contribute/code-contribution.md).

## Repositories Involved

[arkcompiler_cangjie_ark_interop](https://gitcode.com/openharmony-sig/arkcompiler_cangjie_ark_interop)

[hiviewdfx_hiviewdfx_cangjie_wrapper](https://gitcode.com/openharmony-sig/hiviewdfx_hiviewdfx_cangjie_wrapper)

[security_crypto_framework](https://gitcode.com/openharmony/security_crypto_framework)

[security_huks](https://gitcode.com/openharmony/security_huks)
