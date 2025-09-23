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
import ohos.business_exception.BusinessException

/**
 * Defines the param field in the properties array of options used in the APIs.
 *
 * @relation export interface HuksParam
 */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksParam {
    /**
     * tag.
     *
     * @relation tag: HuksTag
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public var tag: UInt32
    /**
     * Value of the tag.
     *
     * @relation value: boolean | int | bigint | Uint8Array
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public var value: HuksParamValue

    /**
     *HuksParam constructor
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public init(tag: UInt32, value: HuksParamValue) {
        this.tag = tag
        this.value = value
    }
}

/**
  * Defines type Bytes.
  *
  */
public type Bytes = Array<UInt8>

/**
  * Defines enum HuksParamValue.
  *
  */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Core"
]
public enum HuksParamValue {
    /**
     * The returned type is Bool.
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    BooleanValue(Bool)
    | 
        /**
         * The returned type is Int32.
         */
        @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    Int32Value(Int32)
    | 
        /**
         * The returned type is UInt32.
         */
        @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    Uint32Value(UInt32)
    | 
        /**
         * The returned type is UInt64.
         */
        @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    Uint64Value(UInt64)
    | 
        /**
         * The returned type is Bytes.
         */
        @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    BytesValue(Bytes)
    | ...

    /**
     * The returned type is Option<Bool>.
     */
    func toBool(): Option<Bool> {
        match (this) {
            case BooleanValue(val) => val
            case _ => None
        }
    }
    /**
     * The returned type is Option<Int32>.
     */
    func toInt32(): Option<Int32> {
        match (this) {
            case Int32Value(val) => val
            case _ => None
        }
    }
    /**
     * The returned type is Option<UInt32>.
     */
    func toUInt32(): Option<UInt32> {
        match (this) {
            case Uint32Value(val) => val
            case _ => None
        }
    }
    /**
     * The returned type is Option<UInt64>.
     */
    func toUInt64(): Option<UInt64> {
        match (this) {
            case Uint64Value(val) => val
            case _ => None
        }
    }
    /**
     * The returned type is Option<Bytes>.
     */
    func toBytes(): Option<Bytes> {
        match (this) {
            case BytesValue(val) => val
            case _ => None
        }
    }
}

/**
 * Defines options used in the APIs.
 *
 * @relation export interface HuksOptions 
 */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksOptions {
    /**
     * Properties used to hold the HuksParam array.
     *
     * @relation properties?: Array<HuksParam>
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public var properties: Array<HuksParam>
    /**
     * Input data.
     *
     * @relation inData?: Uint8Array
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public var inData: Bytes

    /**
     *HuksOptions constructor
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public init(properties!: Array<HuksParam> = Array<HuksParam>(), inData!: Bytes = Bytes()) {
        this.properties = properties
        this.inData = inData
    }
}

/**
 * Defines the struct for a HUKS handle.
 *
 * @relation export interface HuksSessionHandle 

 */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Core"
]
public class HuksSessionHandle {
    /**
     * Value of the handle.
     *
     * @relation handle: long
     */
     @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public var handle: HuksHandleId
    /**
     * Challenge obtained after the initSession operation.
     *
     * @relation challenge?: Uint8Array
     */
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.Huks.Core"
    ]
    public var challenge: Bytes

    /**
     * HuksOptions constructor
     */
    init(handle: HuksHandleId, challenge!: Bytes = Bytes()) {
        this.handle = handle
        this.challenge = challenge
    }
}

/**
 * Interface of huks handle.
 *
 */
@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.Huks.Extension"
]
public class HuksHandleId {
    var data: Bytes
    init(data: Bytes){
        this.data = data
    }
}
