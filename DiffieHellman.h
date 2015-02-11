//
//  DiffieHellman.h
//  ECDHTest
//
//  Created by David Benko on 2/2/15.
//  Copyright (c) 2015 David Benko. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonKeyDerivation.h>

@protocol DiffieHellmanDelegate <NSObject>

@required
- (NSURLRequest *)keyExchangeRequest:(NSString *)ourPublicKey;
- (NSString *)parseKeyExchangeResponse:(NSData *)data;

@optional
- (void)diffieHellmanHandleError:(NSError *)error;
@end

@interface DiffieHellman : NSObject

FOUNDATION_EXPORT CCPBKDFAlgorithm const KeyDerivationAlgorithm;
FOUNDATION_EXPORT CCPseudoRandomAlgorithm const HmacAlgorithm;
FOUNDATION_EXPORT size_t const KeyDerivationRounds;
FOUNDATION_EXPORT size_t const DHSecretLength;
FOUNDATION_EXPORT size_t const KeyLength;
FOUNDATION_EXPORT size_t const SaltLength;

@property (nonatomic, weak) id<DiffieHellmanDelegate> delegate;

- (void)keyExchange:(void (^)(NSString *ourPubKey, NSString *key, NSString *salt))callback;
@end
