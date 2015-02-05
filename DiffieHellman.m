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
CCPseudoRandomAlgorithm const HmacAlgorithm = kCCPRFHmacAlgSHA256;
size_t const KeyDerivationRounds = 20000;
size_t const DHSecretLength = 32;
size_t const KeyLength = CC_SHA256_DIGEST_LENGTH;
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

- (EVP_PKEY *)generateECKeys{
    EVP_PKEY_CTX *pctx, *kctx;
    EVP_PKEY *pkey = NULL, *params = NULL;
    /* NB: assumes pkey, peerkey have been already set up */
    
    /* Create the context for parameter generation */
    if(NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) [self throwError:nil];
    
    /* Initialise the parameter generation */
    if(1 != EVP_PKEY_paramgen_init(pctx)) [self throwError:nil];
    
    /* We're going to use the ANSI X9.62 Prime 256v1 curve */
    if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1)) [self throwError:nil];
    
    /* Create the parameter object params */
    if (!EVP_PKEY_paramgen(pctx, &params)) [self throwError:nil];
    
    /* Create the context for the key generation */
    if(NULL == (kctx = EVP_PKEY_CTX_new(params, NULL))) [self throwError:nil];
    
    /* Generate the key */
    if(1 != EVP_PKEY_keygen_init(kctx)) [self throwError:nil];
    if (1 != EVP_PKEY_keygen(kctx, &pkey)) [self throwError:nil];
    
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(params);
    
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

- (void)keyExchange:(void (^)(NSString *key, NSString *salt))callback{
    EVP_PKEY *ourKey = [self generateECKeys];
    
    NSURLRequest *request = [self.delegate keyExchangeRequest:[self pubKeyToString:ourKey]];
    
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
                    callback(key,saltString);
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
