//
//  DiffieHellman.m
//  ECDHTest
//
//  Created by David Benko on 2/2/15.
//  Copyright (c) 2015 David Benko. All rights reserved.
//

#import "DiffieHellman.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#import <openssl/evp.h>
#import <openssl/ec.h>
#include <openssl/pem.h>
#include <sys/mman.h>

struct dh_fmem {
    size_t pos;
    size_t size;
    char *buffer;
};
typedef struct dh_fmem dh_fmem_t;

@implementation DiffieHellman

CCPBKDFAlgorithm const KeyDerivationAlgorithm = kCCPBKDF2;
CCPseudoRandomAlgorithm const HmacAlgorithm = kCCPRFHmacAlgSHA1;
size_t const KeyDerivationRounds = 20000;
size_t const DHSecretLength = 32;
size_t const KeyLength = CC_SHA1_DIGEST_LENGTH;
size_t const SaltLength = CC_SHA256_DIGEST_LENGTH;

#pragma mark - fmemopen() implementation

static int dh_readfn(void *handler, char *buf, int size) {
    dh_fmem_t *mem = handler;
    size_t available = mem->size - mem->pos;
    
    if (size > available) {
        size = (int)available;
    }
    memcpy(buf, mem->buffer + mem->pos, sizeof(char) * size);
    mem->pos += size;
    
    return size;
}

static int dh_writefn(void *handler, const char *buf, int size) {
    dh_fmem_t *mem = handler;
    size_t available = mem->size - mem->pos;
    
    if (size > available) {
        size = (int)available;
    }
    memcpy(mem->buffer + mem->pos, buf, sizeof(char) * size);
    mem->pos += size;
    
    return size;
}

static fpos_t dh_seekfn(void *handler, fpos_t offset, int whence) {
    size_t pos;
    dh_fmem_t *mem = handler;
    
    switch (whence) {
        case SEEK_SET: {
            if (offset >= 0) {
                pos = (size_t)offset;
            } else {
                pos = 0;
            }
            break;
        }
        case SEEK_CUR: {
            if (offset >= 0 || (size_t)(-offset) <= mem->pos) {
                pos = mem->pos + (size_t)offset;
            } else {
                pos = 0;
            }
            break;
        }
        case SEEK_END: pos = mem->size + (size_t)offset; break;
        default: return -1;
    }
    
    if (pos > mem->size) {
        return -1;
    }
    
    mem->pos = pos;
    return (fpos_t)pos;
}

static int dh_closefn(void *handler) {
    free(handler);
    return 0;
}

FILE *dh_fmemopen(void *buf, size_t size, const char *mode) {
    // This data is released on fclose.
    dh_fmem_t* mem = (dh_fmem_t *) malloc(sizeof(dh_fmem_t));
    
    // Zero-out the structure.
    memset(mem, 0, sizeof(dh_fmem_t));
    
    mem->size = size;
    mem->buffer = buf;
    
    // funopen's man page: https://developer.apple.com/library/mac/#documentation/Darwin/Reference/ManPages/man3/funopen.3.html
    return funopen(mem, dh_readfn, dh_writefn, dh_seekfn, dh_closefn);
}

#pragma mark - Error Handling
- (void)throwError:(NSError *)error{
    if ([self.delegate respondsToSelector:@selector(diffieHellmanHandleError:)]) {
        [self.delegate diffieHellmanHandleError:error];
    }
}

#pragma mark - EVP_PKEY Conversions
- (NSString *)pubKeyToString:(EVP_PKEY *)pubkey{
    char *buf[256];
    FILE *pFile;
    NSString *pkey_string;
    
    pFile = dh_fmemopen(buf, sizeof(buf), "w");
    PEM_write_PUBKEY(pFile,pubkey);
    fclose(pFile);
    
    if (buf)
    {
        pkey_string = [NSString stringWithUTF8String:(char *)buf];
    }
    return pkey_string;
}

- (EVP_PKEY *)stringToPubkey:(NSString *)str {
    char *buf[256];
    FILE *pFile;
    EVP_PKEY *key;
    
    pFile = dh_fmemopen(buf, sizeof(buf), "r+");
    fputs([str UTF8String], pFile);
    rewind(pFile);
    key = PEM_read_PUBKEY(pFile, NULL, NULL, NULL);
    fclose(pFile);
    
    return key;
}


#pragma mark - Elliptic Curve Key Generation

- (EVP_PKEY *)generateECKeys {
    // new EVP_PKEY will hold the result once we create the EC_KEY and convert it to an EVP_PKEY
    EVP_PKEY *pkey = EVP_PKEY_new();
    
    // We're going to create a new EC_KEY with specific parameters
    EC_KEY *key;
    
    // Create an Elliptic Curve Key object and set it up to use the ANSI X9.62 Prime 256v1 curve
    if(NULL == (key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1))) [self throwError:nil];
    
    // Generate the private and public key
    if(1 != EC_KEY_generate_key(key)) [self throwError:nil];
    
    // Set the option to output the public key using OpenSSL EC Named Curve only, rather than outputting a key with explicit parameters
    EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);
    
    // Assign the EC_KEY to the EVP_PKEY - this method will also free the EC_KEY memory when EVP_PKEY memory is freed later on
    if(1 != EVP_PKEY_assign_EC_KEY(pkey, key)) [self throwError:nil];
    
    return pkey;
}

#pragma mark - Secret Derivation

- (NSString *)deriveSecretFromOurKey:(EVP_PKEY *)ourKey theirKey:(EVP_PKEY *)theirKey{
    unsigned char *secret;
    EVP_PKEY_CTX *ctx;
    size_t secretLen = DHSecretLength;
    
    /* Create the context for the shared secret derivation */
    if(NULL == (ctx = EVP_PKEY_CTX_new(ourKey, NULL))) [self throwError:nil];
    
    /* Initialise */
    if(1 != EVP_PKEY_derive_init(ctx)) [self throwError:nil];
    
    /* Provide the peer public key */
    if(1 != EVP_PKEY_derive_set_peer(ctx, theirKey)) [self throwError:nil];
    
    /* Create the buffer */
    if(NULL == (secret = OPENSSL_malloc(secretLen))) [self throwError:nil];
    
    /* Derive the shared secret */
    if(1 != (EVP_PKEY_derive(ctx, secret, &secretLen))) [self throwError:nil];
    
    
    NSMutableString *ms = [[NSMutableString alloc]init];
    for(int i = 0; i < secretLen; i++){
        [ms appendString:[NSString stringWithFormat:@"%02x",secret[i]]];
    }
    
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(theirKey);
    EVP_PKEY_free(ourKey);
    
    return ms;
}


- (NSString *)deriveKeyFromSecret:(NSString *)secret salt:(NSData *)salt{
    NSMutableData *finalKey = [NSMutableData dataWithLength:KeyLength];
    NSData *data = [secret dataUsingEncoding:NSUTF8StringEncoding];
    CCKeyDerivationPBKDF(KeyDerivationAlgorithm, data.bytes, data.length, salt.bytes, salt.length, HmacAlgorithm, KeyDerivationRounds, finalKey.mutableBytes, finalKey.length);
    
    return [finalKey base64EncodedStringWithOptions:0];
}

#pragma mark - Key Exchange

- (void)keyExchange:(void (^)(NSString *ourPubKey, NSString *key, NSString *salt))callback{
    EVP_PKEY *ourKey = [self generateECKeys];
    NSString *ourPubKeyAsString = [self pubKeyToString:ourKey];
    NSURLRequest *request = [self.delegate keyExchangeRequest:ourPubKeyAsString];
    
    NSOperationQueue *queue = [[NSOperationQueue alloc] init];
    [NSURLConnection sendAsynchronousRequest:request queue:queue completionHandler:^(NSURLResponse *response, NSData *data, NSError *error){
        
        if (error) {
            NSLog(@"Error: %@",[error localizedDescription]);
        }
        else{
            NSData *salt = [self generateSalt:SaltLength];
            NSString *peerKeyAsString = [self.delegate parseKeyExchangeResponse:data];
            EVP_PKEY *theirKey = [self stringToPubkey:peerKeyAsString];
            NSString *key = [self deriveKeyFromSecret:[self deriveSecretFromOurKey:ourKey theirKey:theirKey] salt:salt];
            NSString *saltString = [salt base64EncodedStringWithOptions:0];
            
            if (callback) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    callback(ourPubKeyAsString,key,saltString);
                });
            }
            
        }
    }];
}

#pragma mark - Generate Salt

- (NSData*)generateSalt:(size_t)length {
    NSMutableData *data = [NSMutableData dataWithLength:length];
    int result = SecRandomCopyBytes(kSecRandomDefault,
                                    length,
                                    data.mutableBytes);
    
    assert(result == 0);
    return data;
}

@end
