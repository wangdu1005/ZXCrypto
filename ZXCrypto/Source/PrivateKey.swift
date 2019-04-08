//
//  PrivateKey.swift
//  CryptoRSA
//
//  Created by wangdu on 2019/4/3.
//  Copyright © 2019 zx. All rights reserved.
//

import Foundation

public class PrivateKey: Key {
    
    /// Reference to the key within the keychain
    public let reference: SecKey
    
    /// Original data of the private key.
    /// Note that it does not contain PEM headers and holds data as bytes, not as a base 64 string.
    public let originalData: Data?
    
    let tag: String?
    
    /// Returns a PEM representation of the private key.
    ///
    /// - Returns: Data of the key, PEM-encoded
    /// - Throws: CryptoRSAError
    public func pemString() throws -> String {
        let data = try self.data()
        let pem = CryptoRSA.format(keyData: data, withPemType: "RSA PRIVATE KEY")
        return pem
    }
    
    /// Creates a private key with a keychain key reference.
    /// This initializer will throw if the provided key reference is not a private RSA key.
    ///
    /// - Parameter reference: Reference to the key within the keychain.
    /// - Throws: CryptoRSAError
    public required init(reference: SecKey) throws {
        
        guard CryptoRSA.isValidKeyReference(reference, forClass: kSecAttrKeyClassPrivate) else {
//            throw CryptoRSAError.notAPrivateKey
            throw CryptoRSAError.notAPrivateKey
        }
        
        self.reference = reference
        self.tag = nil
        self.originalData = nil
    }
    
    /// Creates a private key with a RSA public key data.
    ///
    /// - Parameter data: Private key data
    /// - Throws: CryptoRSAError
    required public init(data: Data) throws {
        self.originalData = data
        let tag = UUID().uuidString
        self.tag = tag
        let dataWithoutHeader = try CryptoRSA.stripKeyHeader(keyData: data)
        reference = try CryptoRSA.addKey(dataWithoutHeader, isPublic: false, tag: tag)
    }
    
    deinit {
        if let tag = tag {
            CryptoRSA.removeKey(tag: tag)
        }
    }
}
