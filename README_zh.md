# 安全基础能力仓颉接口

## 简介

安全基础能力仓颉接口包括系统安全、数据安全、应用安全等功能，为OpenHarmony提供有效保护应用和用户数据的能力。

安全基础能力仓颉接口当前支持的功能，包括加解密算法基础功能、密钥管理功能、密钥会话功能。

当前开放的安全基础能力仓颉接口仅支持standard设备。

## 系统架构

**图 1**  安全基础能力仓颉架构图

![安全基础能力仓颉架构图](figures/security_cangjie_wrapper_architecture.png "安全基础能力仓颉架构图")

如架构图所示：
- 加解密算法基础功能：加解密算法基础功能主要是为了屏蔽底层硬件和算法库，向上提供统一的密码算法库加解密相关接口。它的主要功能提供密码操作、秘钥材料和生成器、密码加解密、签名验签、安全随机数等相关功能。开发者可以通过使用该功能，忽略底层不同三方算法库的差异，实现迅捷开发。
- 密钥管理功能：密钥管理功能主要是为了向上层应用提供一套完整、统一、安全的密钥生命周期管理接口，屏蔽不同硬件安全模块和底层密钥管理服务的实现差异。它的主要功能包括：密钥生成与派生、密钥存储、密钥导入、销毁等一系列关键操作。开发者通过调用该功能，可以忽略底层不同密钥存储介质的复杂细节和安全策略差异，确保密钥材料的机密性、完整性和可用性，从而实现安全、可靠、高效的业务开发。
- 密钥会话功能：密钥会话功能是HUKS系统提供的核心安全能力之一，它构建在统一的密钥管理基础之上，其主要目的是为上层应用提供一套安全、高效的密钥协商与数据加密通信机制。Huks基于密钥会话功能来操作数据，它提供如下api接口供开发者使用，比如：初始化密钥会话initSession、数据过大需要分段操作密钥数据updateSession、结束此次密钥操作finishSession、取消会话abortSeesion。

## 目录

```
base/security/security_cangjie_wrapper
├── figures                         # 存放README中的架构图
├── kit                             # 仓颉安全kit化代码
|   ├── CryptoArchitectureKit       # 加解密算法库Kit
|   ├── UniversalKeystoreKit        # 设备密钥管理Kit
├── ohos                            # 仓颉安全基础能力接口实现
|   ├── crypto_framework            # 密码算法库加解密相关接口
|   └── huks                        # 密钥管理相关接口
└── test                            # 仓颉测试代码  
```

## 使用说明

当前安全基础能力仓颉接口提供了以下功能：
-  加解密算法基础功能
-  密钥管理功能
-  密钥会话功能

与ArkTS相比，暂不支持以下功能：
-   程序访问控制功能
-   证书模块
-   用户认证
-   密码插件功能

安全基础能力相关API请参见[ohos.security.huks](https://gitcode.com/openharmony-sig/arkcompiler_cangjie_ark_interop/blob/master/doc/API_Reference/source_zh_cn/apis/UniversalKeystoreKit/cj-apis-security_huks.md)，[ohos.security.crypto_framework](https://gitcode.com/openharmony-sig/arkcompiler_cangjie_ark_interop/blob/master/doc/API_Reference/source_zh_cn/apis/CryptoArchitectureKit/cj-apis-crypto.md)，相关指导请参见[安全基础能力开发指南](https://gitcode.com/openharmony-sig/arkcompiler_cangjie_ark_interop/tree/master/doc/Dev_Guide/source_zh_cn/security)。

## 参与贡献

欢迎广大开发者贡献代码、文档等，具体的贡献流程和方式请参见[参与贡献](https://gitcode.com/openharmony/docs/blob/master/zh-cn/contribute/%E5%8F%82%E4%B8%8E%E8%B4%A1%E7%8C%AE.md)。


## 相关仓

[security_huks](https://gitee.com/openharmony/security_huks/blob/master/README_zh.md)

[security_crypto_framework](https://gitee.com/openharmony/security_crypto_framework/blob/master/README_zh.md)
