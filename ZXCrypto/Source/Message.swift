//
//  Message.swift
//  ZXCrypto
//
//  Created by wangdu on 2019/4/3.
//  Copyright © 2019 zx. All rights reserved.
//

import Foundation

public protocol Message {
    var data: Data { get }
    var base64String: String { get }
    init(data: Data)
    init(base64Encoded base64String: String) throws
}

public extension Message {
    
    /// Base64-encoded string of the message data
    var base64String: String {
        return data.base64EncodedString()
    }
    
    /// Creates an encrypted message with a base64-encoded string.
    ///
    /// - Parameter base64String: Base64-encoded data of the encrypted message
    /// - Throws: CryptoRSAError
    init(base64Encoded base64String: String) throws {
        guard let data = Data(base64Encoded: base64String) else {
            throw CryptoRSAError.invalidBase64String
        }
        self.init(data: data)
    }
}
