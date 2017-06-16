// AFSecurityPolicy.m
// Copyright (c) 2011–2016 Alamofire Software Foundation ( http://alamofire.org/ )
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "AFSecurityPolicy.h"

#import <AssertMacros.h>

#if !TARGET_OS_IOS && !TARGET_OS_WATCH && !TARGET_OS_TV
static NSData * AFSecKeyGetData(SecKeyRef key) {
    CFDataRef data = NULL;

    __Require_noErr_Quiet(SecItemExport(key, kSecFormatUnknown, kSecItemPemArmour, NULL, &data), _out);

    return (__bridge_transfer NSData *)data;

_out:
    if (data) {
        CFRelease(data);
    }

    return nil;
}
#endif

//判断两个公钥是否相同。根据不同的运行环境做匹配判断
static BOOL AFSecKeyIsEqualToKey(SecKeyRef key1, SecKeyRef key2) {
#if TARGET_OS_IOS || TARGET_OS_WATCH || TARGET_OS_TV
    //判断两者地址
    return [(__bridge id)key1 isEqual:(__bridge id)key2];
#else
    return [AFSecKeyGetData(key1) isEqual:AFSecKeyGetData(key2)];
#endif
}

//在证书中获取公钥
static id AFPublicKeyForCertificate(NSData *certificate) {
    //1.初始化临时变量
    id allowedPublicKey = nil;
    SecCertificateRef allowedCertificate;//SecCertificateRef包含有关证书的信息
    SecPolicyRef policy = nil;
    SecTrustRef allowedTrust = nil;
    SecTrustResultType result;

    //2.创建SecCertificateRef对象，判断返回值是否为null
    //通过DER格式的证书（NSData）生成SecCertificateRef类型的证书引用。 如果传入的数据不是有效的DER编码的X.509证书，则返回NULL。
    //传入的第二个参数是CFDataRef类型，要用__bridge把oc对象转Core Foundation对象
    allowedCertificate = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certificate);
    //__Require_Quiet这个宏，判断allowedCertificate != NULL表达式是否为假，如果allowedCertificate=NULL，就跳到_out标签处执行
    __Require_Quiet(allowedCertificate != NULL, _out);

    //3.创建符合X.509的SecPolicyRef，用SecPolicyRef和证书SecCertificateRef创建SecTrustRef用于信任评估，判断SecTrustRef是否值得信任
    //3.1.新建默认策略为X.509的SecPolicyRef策略对象，不验证域名
    policy = SecPolicyCreateBasicX509();
    /*3.2.
     OSStatus SecTrustCreateWithCertificates(CFTypeRef certificates,
     CFTypeRef __nullable policies, SecTrustRef * __nonnull CF_RETURNS_RETAINED trust)
     基于给定的证书和策略创建一个SecTrustRef信任引用对象，然后赋值给trust。
     这个函数返回一个结果码，判断是否出错
     */
    //__Require_noErr_Quiet，第一个参数是错误码表达式，如果不等于0（出错了）就跳到_out标签处执行
    __Require_noErr_Quiet(SecTrustCreateWithCertificates(allowedCertificate, policy, &allowedTrust), _out);//创建SecTrustRef，如果出错就跳到_out
    __Require_noErr_Quiet(SecTrustEvaluate(allowedTrust, &result), _out);//对SecTrustRef进行信任评估，确认它是值得信任的

    //4.获取证书公钥
    //__bridge_transfer会将结果桥接成OC对象，然后将 SecTrustCopyPublicKey 返回的指针释放
    allowedPublicKey = (__bridge_transfer id)SecTrustCopyPublicKey(allowedTrust);

_out:
    //5.释放c指针
    if (allowedTrust) {
        CFRelease(allowedTrust);
    }

    if (policy) {
        CFRelease(policy);
    }

    if (allowedCertificate) {
        CFRelease(allowedCertificate);
    }

    return allowedPublicKey;
}

//验证serverTrust是否有效
static BOOL AFServerTrustIsValid(SecTrustRef serverTrust) {
    BOOL isValid = NO;
    SecTrustResultType result;
    __Require_noErr_Quiet(SecTrustEvaluate(serverTrust, &result), _out);//评估证书是否可信，确认它是值得信任的.去系统根目录找，然后把结果赋值给result。
    /*SecTrustResultType结果有两个维度。 1.serverTrust评估是否成功，2.是否由用户决定评估成功。
     如果是用户决定的，成功是 kSecTrustResultProceed 失败是kSecTrustResultDeny。
     非用户定义的， 成功是kSecTrustResultUnspecified 失败是kSecTrustResultRecoverableTrustFailure
     用户决策通过使用SecTrustCopyExceptions（）和SecTrustSetExceptions（）*/
    isValid = (result == kSecTrustResultUnspecified || result == kSecTrustResultProceed);

_out:
    return isValid;
}

//取出服务器返回的所有证书
static NSArray * AFCertificateTrustChainForServerTrust(SecTrustRef serverTrust) {
    CFIndex certificateCount = SecTrustGetCertificateCount(serverTrust);//获取评估证书链中的证书数目。
    NSMutableArray *trustChain = [NSMutableArray arrayWithCapacity:(NSUInteger)certificateCount];
    //遍历获取证书链中的每个证书，并添加到trustChain中//获取的顺序，从证书链的叶节点到根节点
    for (CFIndex i = 0; i < certificateCount; i++) {
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);//取得证书链中对应下标的证书
        //返回der格式的x.509证书
        [trustChain addObject:(__bridge_transfer NSData *)SecCertificateCopyData(certificate)];
    }

    return [NSArray arrayWithArray:trustChain];
}

//取出服务器返回的所有证书的公钥，函数的实现过程和函数AFPublicKeyForCertificate很像
static NSArray * AFPublicKeyTrustChainForServerTrust(SecTrustRef serverTrust) {
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    CFIndex certificateCount = SecTrustGetCertificateCount(serverTrust);
    NSMutableArray *trustChain = [NSMutableArray arrayWithCapacity:(NSUInteger)certificateCount];
    //获取的顺序，从证书链的叶节点到根节点
    for (CFIndex i = 0; i < certificateCount; i++) {
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);

        SecCertificateRef someCertificates[] = {certificate};//数组
        CFArrayRef certificates = CFArrayCreate(NULL, (const void **)someCertificates, 1, NULL);//CF数组

        SecTrustRef trust;
        __Require_noErr_Quiet(SecTrustCreateWithCertificates(certificates, policy, &trust), _out);

        SecTrustResultType result;
        __Require_noErr_Quiet(SecTrustEvaluate(trust, &result), _out);

        [trustChain addObject:(__bridge_transfer id)SecTrustCopyPublicKey(trust)];

    _out:
        if (trust) {
            CFRelease(trust);
        }

        if (certificates) {
            CFRelease(certificates);
        }

        continue;
    }
    CFRelease(policy);

    return [NSArray arrayWithArray:trustChain];
}

#pragma mark -

@interface AFSecurityPolicy()
@property (readwrite, nonatomic, assign) AFSSLPinningMode SSLPinningMode;//https验证模式
@property (readwrite, nonatomic, strong) NSSet *pinnedPublicKeys;//本地证书公钥
@end

@implementation AFSecurityPolicy
//以NSData的形式获取某个目录下的所有证书
+ (NSSet *)certificatesInBundle:(NSBundle *)bundle {
    NSArray *paths = [bundle pathsForResourcesOfType:@"cer" inDirectory:@"."];

    NSMutableSet *certificates = [NSMutableSet setWithCapacity:[paths count]];
    for (NSString *path in paths) {
        NSData *certificateData = [NSData dataWithContentsOfFile:path];
        [certificates addObject:certificateData];
    }

    return [NSSet setWithSet:certificates];
}

//以NSData的形式获取当前class目录下的所有证书
+ (NSSet *)defaultPinnedCertificates {
    static NSSet *_defaultPinnedCertificates = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSBundle *bundle = [NSBundle bundleForClass:[self class]];//根据当前的class获取对应NSBundle目录
        _defaultPinnedCertificates = [self certificatesInBundle:bundle];//以NSData的形式获取该目录下的所有证书
    });

    return _defaultPinnedCertificates;
}

//创建一个默认的AFSecurityPolicy，SSLPinningMode是不验证
+ (instancetype)defaultPolicy {
    AFSecurityPolicy *securityPolicy = [[self alloc] init];
    securityPolicy.SSLPinningMode = AFSSLPinningModeNone;
    return securityPolicy;
}

+ (instancetype)policyWithPinningMode:(AFSSLPinningMode)pinningMode {
    return [self policyWithPinningMode:pinningMode withPinnedCertificates:[self defaultPinnedCertificates]];
}

//根据指定的验证模式、证书创建AFSecurityPolicy
+ (instancetype)policyWithPinningMode:(AFSSLPinningMode)pinningMode withPinnedCertificates:(NSSet *)pinnedCertificates {
    AFSecurityPolicy *securityPolicy = [[self alloc] init];
    securityPolicy.SSLPinningMode = pinningMode;
    [securityPolicy setPinnedCertificates:pinnedCertificates];
    return securityPolicy;
}

- (instancetype)init {
    self = [super init];
    if (!self) {
        return nil;
    }
    self.validatesDomainName = YES;//验证证书域名
    return self;
}
//设置用于评估服务器是否可信的证书（本地证书）
//把证书中每个公钥放在了self.pinnedPublicKeys中,用于AFSSLPinningModePublicKey方式的验证
- (void)setPinnedCertificates:(NSSet *)pinnedCertificates {
    _pinnedCertificates = pinnedCertificates;

    if (self.pinnedCertificates) {
        //遍历取出所有证书中的公钥，然后保存在self.pinnedPublicKeys属性中
        NSMutableSet *mutablePinnedPublicKeys = [NSMutableSet setWithCapacity:[self.pinnedCertificates count]];
        for (NSData *certificate in self.pinnedCertificates) {
            id publicKey = AFPublicKeyForCertificate(certificate);
            if (!publicKey) {
                continue;
            }
            [mutablePinnedPublicKeys addObject:publicKey];
        }
        self.pinnedPublicKeys = [NSSet setWithSet:mutablePinnedPublicKeys];
    } else {
        self.pinnedPublicKeys = nil;
    }
}

#pragma mark -
//验证服务端是否可信，这个serverTrust是服务器传过来的，里面包含了服务器的证书信息，是用于我们本地客户端去验证该证书是否合法用的
/*SecTrustRef:
 大概意思是用于执行X.509证书信任评估，
 再讲简单点，其实就是一个容器，装了服务器端需要验证的证书的基本信息、公钥等等，不仅如此，它还可以装一些评估策略，还有客户端的锚点证书，这个客户端的证书，可以用来和服务端的证书去匹配验证的。
 */
- (BOOL)evaluateServerTrust:(SecTrustRef)serverTrust
                  forDomain:(NSString *)domain
{
    //判断矛盾的条件
    //如果有服务器域名、设置了允许信任无效或者过期证书（自签名证书）、需要验证域名、没有提供证书或者不验证证书，返回no。后两者和allowInvalidCertificates为真的设置矛盾，说明这次验证是不安全的。
    if (domain && self.allowInvalidCertificates && self.validatesDomainName && (self.SSLPinningMode == AFSSLPinningModeNone || [self.pinnedCertificates count] == 0)) {
        // https://developer.apple.com/library/mac/documentation/NetworkingInternet/Conceptual/NetworkingTopics/Articles/OverridingSSLChainValidationCorrectly.html
        //  According to the docs, you should only trust your provided certs for evaluation.
        //  Pinned certificates are added to the trust. Without pinned certificates,
        //  there is nothing to evaluate against.
        //
        //  From Apple Docs:
        //          "Do not implicitly trust self-signed certificates as anchors (kSecTrustOptionImplicitAnchors).
        //           Instead, add your own (self-signed) CA certificate to the list of trusted anchors."
        NSLog(@"In order to validate a domain name for self signed certificates, you MUST use pinning.");
        return NO;
    }

    //生成验证策略。如果要验证域名，就以域名为参数创建一个策略，否则创建默认的basicX509策略
    NSMutableArray *policies = [NSMutableArray array];
    if (self.validatesDomainName) {
        //SecPolicyCreateSSL函数，创建用于评估SSL证书链的策略对象。第一个参数：true将为SSL服务器证书创建一个策略。第二个参数：如果这个参数存在，证书链上的叶子节点表示的那个domain要和传入的domain相匹配
        [policies addObject:(__bridge_transfer id)SecPolicyCreateSSL(true, (__bridge CFStringRef)domain)];
    } else {
        //不验证域名。返回的服务器证书，只要是可信任CA机构签发的，都会校验通过
        [policies addObject:(__bridge_transfer id)SecPolicyCreateBasicX509()];
    }
    
    //设置评估中要使用的策略
    SecTrustSetPolicies(serverTrust, (__bridge CFArrayRef)policies);//为serverTrust设置验证的策略

    //设置完策略就进行验证
    //如果是AFSSLPinningModeNone（不使用本地证书，直接从客户端系统中的受信任颁发机构 CA 列表中去验证）
    if (self.SSLPinningMode == AFSSLPinningModeNone) {
        //不使用ssl pinning 但允许自建证书，直接返回YES；否则进行第二个条件判断，去客户端系统根证书里找是否有匹配的证书，验证serverTrust是否可信
        return self.allowInvalidCertificates || AFServerTrustIsValid(serverTrust);
    }
    //如果serverTrust不可信且不允许自签名，返回NO
    else if (!AFServerTrustIsValid(serverTrust) && !self.allowInvalidCertificates) {
        return NO;
    }

    //根据不同的SSLPinningMode分情况验证
    switch (self.SSLPinningMode) {
        //不验证
        case AFSSLPinningModeNone://上一部分已经判断过了，如果执行到这里的话就返回NO
        default:
            return NO;
        //验证证书
        case AFSSLPinningModeCertificate: {
            NSMutableArray *pinnedCertificates = [NSMutableArray array];
            //把nsdata证书（der编码的x.509证书）转成SecCertificateRef类型的数据
            for (NSData *certificateData in self.pinnedCertificates) {
                [pinnedCertificates addObject:(__bridge_transfer id)SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certificateData)];
            }
            // 将本地证书设置成需要参与验证的锚点证书（相当于系统可信任证书列表？）（锚点证书通常指：嵌入到操作系统中的根证书，通过SecTrustSetAnchorCertificates设置了参与校验锚点证书之后，假如验证的数字证书是这个锚点证书的子节点，即验证的数字证书是由锚点证书对应CA或子CA签发的，或是该证书本身，则本地系统信任该证书）
            //第二个参数，表示在验证证书时被SecTrustEvaluate函数视为有效（可信任）锚点的锚点证书集。 传递NULL以恢复默认的锚证书集。
            //自签证书在这步之前验证通过不了，把本地证书添加进去后就能验证成功。
            SecTrustSetAnchorCertificates(serverTrust, (__bridge CFArrayRef)pinnedCertificates);
            //验证服务器证书是否可信（由系统默认可信或者由用户选择可信）。
            if (!AFServerTrustIsValid(serverTrust)) {
                return NO;
            }

            //为什么这里验证过之后，接下来还要去取服务器证书链与本地证书匹配呢？个人看法：访问不安全的链接，这个从服务器传来的证书有可能是中间人的证书，如果是由用户选择信任该证书（在上一步中通过信任）或者中间人持有一个由收信任机构颁发的证书，不对服务器证书进行本地对比校验，就会导致不安全的访问了。
            // obtain the chain after being validated, which *should* contain the pinned certificate in the last position (if it's the Root CA)
            //注意，这个方法和我们之前的锚点证书没关系了，是去从我们需要被验证的服务端去拿证书链
            //这里的证书链顺序是从叶节点到根节点
            NSArray *serverCertificates = AFCertificateTrustChainForServerTrust(serverTrust);
            
            for (NSData *trustChainCertificate in [serverCertificates reverseObjectEnumerator]) {//reverseObjectEnumerator逆序
                //如果本地证书中，有一个和它证书链中的证书匹配的，就返回YES
                if ([self.pinnedCertificates containsObject:trustChainCertificate]) {
                    return YES;
                }
            }
            
            return NO;
        }
        //公钥验证 AFSSLPinningModePublicKey模式同样是用证书绑定(SSL Pinning)方式验证，客户端有服务端的证书拷贝，只是验证时只验证证书里的公钥，不验证证书的有效期等信息。只要公钥是正确的，就能保证通信不会被窃听，因为中间人没有私钥，无法解开通过公钥加密的数据。
        case AFSSLPinningModePublicKey: {
            NSUInteger trustedPublicKeyCount = 0;
            // 从serverTrust中取出服务器端传过来的所有可用的证书，并依次得到相应的公钥
            NSArray *publicKeys = AFPublicKeyTrustChainForServerTrust(serverTrust);
            //和本地公钥遍历对比
            for (id trustChainPublicKey in publicKeys) {
                for (id pinnedPublicKey in self.pinnedPublicKeys) {
                    if (AFSecKeyIsEqualToKey((__bridge SecKeyRef)trustChainPublicKey, (__bridge SecKeyRef)pinnedPublicKey)) {
                        trustedPublicKeyCount += 1;//判断如果相同 trustedPublicKeyCount+1
                    }
                }
            }
            return trustedPublicKeyCount > 0;
        }
    }
    
    return NO;
}

#pragma mark - NSKeyValueObserving

+ (NSSet *)keyPathsForValuesAffectingPinnedPublicKeys {
    return [NSSet setWithObject:@"pinnedCertificates"];
}

#pragma mark - NSSecureCoding

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (instancetype)initWithCoder:(NSCoder *)decoder {

    self = [self init];
    if (!self) {
        return nil;
    }

    self.SSLPinningMode = [[decoder decodeObjectOfClass:[NSNumber class] forKey:NSStringFromSelector(@selector(SSLPinningMode))] unsignedIntegerValue];
    self.allowInvalidCertificates = [decoder decodeBoolForKey:NSStringFromSelector(@selector(allowInvalidCertificates))];
    self.validatesDomainName = [decoder decodeBoolForKey:NSStringFromSelector(@selector(validatesDomainName))];
    self.pinnedCertificates = [decoder decodeObjectOfClass:[NSArray class] forKey:NSStringFromSelector(@selector(pinnedCertificates))];

    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:[NSNumber numberWithUnsignedInteger:self.SSLPinningMode] forKey:NSStringFromSelector(@selector(SSLPinningMode))];
    [coder encodeBool:self.allowInvalidCertificates forKey:NSStringFromSelector(@selector(allowInvalidCertificates))];
    [coder encodeBool:self.validatesDomainName forKey:NSStringFromSelector(@selector(validatesDomainName))];
    [coder encodeObject:self.pinnedCertificates forKey:NSStringFromSelector(@selector(pinnedCertificates))];
}

#pragma mark - NSCopying

- (instancetype)copyWithZone:(NSZone *)zone {
    AFSecurityPolicy *securityPolicy = [[[self class] allocWithZone:zone] init];
    securityPolicy.SSLPinningMode = self.SSLPinningMode;
    securityPolicy.allowInvalidCertificates = self.allowInvalidCertificates;
    securityPolicy.validatesDomainName = self.validatesDomainName;
    securityPolicy.pinnedCertificates = [self.pinnedCertificates copyWithZone:zone];

    return securityPolicy;
}

@end
