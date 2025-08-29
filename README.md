# security_security_cangjie_wrapper

## Introduction

The security_security_cangjie_wrapper is a Cangjie API encapsulated on OpenHarmony based on the capabilities of the security subsystem. The security subsystem provides capabilities to protect the system security, data security, and application security of OpenHarmony.

The open security capabilities include application integrity verification, application permission management, device authentication, universal keystore, and data transfer management.

**Figure 1** security_cangjie_wrapper architecture

![security_cangjie_wrapper architecture](figures/security_cangjie_wrapper_architecture_en.png "security_cangjie_wrapper architecture")

## Directory Structure

```
base/security/security_cangjie_wrapper
├── kit                             # Cangjie kit code
├── figures                         # architecture pictures
├── ohos                            # Cangjie Security code
```

## Constraints

- The security cangjie interface currently under development only supports standard devices.

## Usage

The security_security_cangjie_wrapper provides the following capabilities:

-   Basic Encryption and Decryption Capabilities.
-   Huks Management.
-   Huks Session.

For security APIs, please refer to
1. [ohos.security.huks](https://gitcode.com/openharmony-sig/arkcompiler_cangjie_ark_interop/blob/master/doc/API_Reference/source_zh_cn/apis/UniversalKeystoreKit/cj-apis-security_huks.md).
2. [ohos.security.crypto_framework](https://gitcode.com/openharmony-sig/arkcompiler_cangjie_ark_interop/blob/master/doc/API_Reference/source_zh_cn/apis/CryptoArchitectureKit/cj-apis-crypto.md).


For relevation guidance, please refer to [security Development Guide](https://gitcode.com/openharmony-sig/arkcompiler_cangjie_ark_interop/tree/master/doc/Dev_Guide/source_zh_cn/security).

## Code Contribution

Developers are welcome to contribute code, documentation, etc. For specific contribution processes and methods, please refer to [Code Contribution](https://gitcode.com/openharmony/docs/blob/master/en/contribute/code-contribution.md).

## Repositories Involved

[security_huks](https://gitee.com/openharmony/security_huks/blob/master/README.md)

[security_crypto_framework](https://gitee.com/openharmony/security_crypto_framework)
