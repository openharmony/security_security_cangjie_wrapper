# security_security_cangjie_wrapper

## Introduction

The CangJie is a Cangjie API encapsulated on OpenHarmony based on the capabilities of the security subsystem. The security subsystem provides capabilities to protect the system security, data security, and application security of OpenHarmony.

The current supported functions of the security foundation capability Cangjie interface include basic encryption and decryption algorithms, huks management functions, and huks session functions.

The security cangjie interface currently under development only supports standard devices.

## Architecture
**Figure 1** security_cangjie_wrapper architecture

![security_cangjie_wrapper architecture](figures/security_cangjie_wrapper_architecture_en.png "security_cangjie_wrapper architecture")

## Directory Structure

```
├── figures                         # Architecture Pictures
├── kit                             # Cangjie Kit Code
|   ├── CryptoArchitectureKit       # Encryption and Decryption Algorithms Kit
|   ├── UniversalKeystoreKit        # Huks Management And Huks Session Kit
├── ohos                            # Cangjie Security Code
    ├── crypto_framework            # Encryption And Decryption Algorithms Interface
    ├── huks                        # Huks Management And Huks Seesion Interface
```

## Usage

The security_cangjie_wrapper provides the following capabilities:

-   Basic Encryption and Decryption Capabilities.
-   Huks Management.
-   Huks Session.

Compared to ArkTS, the following features are currently not supporte:

-   Program Access Control.
-   Certificate Module.
-   User Authentication.


For security APIs, please refer to[ohos.security.huks](https://gitcode.com/openharmony-sig/arkcompiler_cangjie_ark_interop/blob/master/doc/API_Reference/source_zh_cn/apis/UniversalKeystoreKit/cj-apis-security_huks.md).[ohos.security.crypto_framework](https://gitcode.com/openharmony-sig/arkcompiler_cangjie_ark_interop/blob/master/doc/API_Reference/source_zh_cn/apis/CryptoArchitectureKit/cj-apis-crypto.md).
For relevation guidance, please refer to [security Development Guide](https://gitcode.com/openharmony-sig/arkcompiler_cangjie_ark_interop/tree/master/doc/Dev_Guide/source_zh_cn/security).

## Code Contribution

Developers are welcome to contribute code, documentation, etc. For specific contribution processes and methods, please refer to [Code Contribution](https://gitcode.com/openharmony/docs/blob/master/en/contribute/code-contribution.md).

## Repositories Involved

[security_huks](https://gitee.com/openharmony/security_huks/blob/master/README.md)

[security_crypto_framework](https://gitee.com/openharmony/security_crypto_framework)
