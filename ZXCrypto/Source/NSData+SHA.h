//
//  NSData_SHA1.h
//  CryptoRSA
//
//  Created by wangdu on 2019/4/3.
//  Copyright © 2019 zx. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSData (NSData_CryptoRSASHA)

- (nonnull NSData*) CryptoRSASHA1;
- (nonnull NSData*) CryptoRSASHA224;
- (nonnull NSData*) CryptoRSASHA256;
- (nonnull NSData*) CryptoRSASHA384;
- (nonnull NSData*) CryptoRSASHA512;

@end
