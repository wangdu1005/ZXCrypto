//
//  NSData_SHA1.h
//  CryptoRSA
//
//  Created by wangdu on 2019/4/3.
//  Copyright © 2019 zx. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>

@implementation NSData (NSData_CryptoRSASHA)

- (nonnull NSData*) CryptoRSASHA1 {
    unsigned int outputLength = CC_SHA1_DIGEST_LENGTH;
    unsigned char output[outputLength];
    
    CC_SHA1(self.bytes, (unsigned int) self.length, output);
    return [NSData dataWithBytes:output length:outputLength];
}

- (nonnull NSData*) CryptoRSASHA224 {
    unsigned int outputLength = CC_SHA224_DIGEST_LENGTH;
    unsigned char output[outputLength];
    
    CC_SHA224(self.bytes, (unsigned int) self.length, output);
    return [NSData dataWithBytes:output length:outputLength];
}

- (nonnull NSData*) CryptoRSASHA256 {
    unsigned int outputLength = CC_SHA256_DIGEST_LENGTH;
    unsigned char output[outputLength];
    
    CC_SHA256(self.bytes, (unsigned int) self.length, output);
    return [NSData dataWithBytes:output length:outputLength];
}

- (nonnull NSData*) CryptoRSASHA384 {
    unsigned int outputLength = CC_SHA384_DIGEST_LENGTH;
    unsigned char output[outputLength];
    
    CC_SHA384(self.bytes, (unsigned int) self.length, output);
    return [NSData dataWithBytes:output length:outputLength];
}

- (nonnull NSData*) CryptoRSASHA512 {
    unsigned int outputLength = CC_SHA512_DIGEST_LENGTH;
    unsigned char output[outputLength];
    
    CC_SHA512(self.bytes, (unsigned int) self.length, output);
    return [NSData dataWithBytes:output length:outputLength];
}

@end
