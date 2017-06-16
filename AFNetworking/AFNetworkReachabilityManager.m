// AFNetworkReachabilityManager.m
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

#import "AFNetworkReachabilityManager.h"
#if !TARGET_OS_WATCH

#import <netinet/in.h>
#import <netinet6/in6.h>
#import <arpa/inet.h>
#import <ifaddrs.h>
#import <netdb.h>

//网络状态发生变化时接受的通知
NSString * const AFNetworkingReachabilityDidChangeNotification = @"com.alamofire.networking.reachability.change";
//网络状态发生变化时发送通知，携带的userInfo的key就是这个，value是代表AFNetworkReachabilityStatus的NSNumber
NSString * const AFNetworkingReachabilityNotificationStatusItem = @"AFNetworkingReachabilityNotificationStatusItem";
//回调
typedef void (^AFNetworkReachabilityStatusBlock)(AFNetworkReachabilityStatus status);

//函数的实现 根据AFNetworkReachabilityStatus获取本地化字符串
//NSLocalizedStringFromTable用于 本地化
NSString * AFStringFromNetworkReachabilityStatus(AFNetworkReachabilityStatus status) {
    switch (status) {
        case AFNetworkReachabilityStatusNotReachable:
            return NSLocalizedStringFromTable(@"Not Reachable", @"AFNetworking", nil);
        case AFNetworkReachabilityStatusReachableViaWWAN:
            return NSLocalizedStringFromTable(@"Reachable via WWAN", @"AFNetworking", nil);
        case AFNetworkReachabilityStatusReachableViaWiFi:
            return NSLocalizedStringFromTable(@"Reachable via WiFi", @"AFNetworking", nil);
        case AFNetworkReachabilityStatusUnknown:
        default:
            return NSLocalizedStringFromTable(@"Unknown", @"AFNetworking", nil);
    }
}

//根据SCNetworkReachabilityFlags（连接状态）的标记来转换成开发中使用的网络状态
static AFNetworkReachabilityStatus AFNetworkReachabilityStatusForFlags(SCNetworkReachabilityFlags flags) {
    //&按位与运算 和&&不一样
    /*kSCNetworkReachabilityFlagsReachable可达指定的节点名称或地址
     是否可达*/
    //当由应用发送到网络堆栈的数据包可以离开本地设备的时候，远程主机就可以被认为可以到达。 可达性并不保证数据包一定会被主机接收到。
    BOOL isReachable = ((flags & kSCNetworkReachabilityFlagsReachable) != 0);
    /*kSCNetworkReachabilityFlagsConnectionRequired可以达到指定的节点名称或地址，但必须首先建立连接。
     是否联网之前需要先建立连接*/
    BOOL needsConnection = ((flags & kSCNetworkReachabilityFlagsConnectionRequired) != 0);
    /*kSCNetworkReachabilityFlagsConnectionOnDemand连接将由CFSocketStream API“On Demand”建立。 其他API将不会建立连接。
     kSCNetworkReachabilityFlagsConnectionOnTraffic指向指定名称或地址的任何流量将启动连接。
     是否可以自动连接*/
    BOOL canConnectionAutomatically = (((flags & kSCNetworkReachabilityFlagsConnectionOnDemand ) != 0) || ((flags & kSCNetworkReachabilityFlagsConnectionOnTraffic) != 0));
    /*kSCNetworkReachabilityFlagsInterventionRequired需要某种形式的用户干预来建立此连接，例如提供密码，认证令牌等。目前这个标志只有在你有一个通话配置的情况下才会被返回，在这种情况下，已经尝试连接，并且有些错误（例如没有拨号音， 没有回答，密码错误，...）在自动连接尝试期间遇到。 在这种情况下，PPP控制器将停止尝试建立连接，直到用户干预为止。
     在不需要用户手动设置的前提下是否可以连接*/
    BOOL canConnectWithoutUserInteraction = (canConnectionAutomatically && (flags & kSCNetworkReachabilityFlagsInterventionRequired) == 0);
    //是否可以联网 条件两个：1.可以达到指定的节点名称或地址 2.联网之前不需要先建立连接
    BOOL isNetworkReachable = (isReachable && (!needsConnection || canConnectWithoutUserInteraction));

//    转换成对应的网络状态，未知连接、不能连接、WWAN、WIFI
    AFNetworkReachabilityStatus status = AFNetworkReachabilityStatusUnknown;
    if (isNetworkReachable == NO) {
        status = AFNetworkReachabilityStatusNotReachable;
    }
#if	TARGET_OS_IPHONE
    else if ((flags & kSCNetworkReachabilityFlagsIsWWAN) != 0) {
        status = AFNetworkReachabilityStatusReachableViaWWAN;
    }
#endif
    else {
        status = AFNetworkReachabilityStatusReachableViaWiFi;
    }

    return status;
}

/**
 * Queue a status change notification for the main thread.
 *
 * This is done to ensure that the notifications are received in the same order
 * as they are sent. If notifications are sent directly, it is possible that
 * a queued notification (for an earlier status condition) is processed after
 * the later update, resulting in the listener being left in the wrong state.
 */
//根据flag来获得对应的网络状态，在主线程中进行对应的回调（block），发送通知。
//根据同一个status来处理block 和通知，封装到一个函数中保持两者统一
static void AFPostReachabilityStatusChange(SCNetworkReachabilityFlags flags, AFNetworkReachabilityStatusBlock block) {
    AFNetworkReachabilityStatus status = AFNetworkReachabilityStatusForFlags(flags);
    dispatch_async(dispatch_get_main_queue(), ^{
        if (block) {
            block(status);
        }
        NSNotificationCenter *notificationCenter = [NSNotificationCenter defaultCenter];
        NSDictionary *userInfo = @{ AFNetworkingReachabilityNotificationStatusItem: @(status) };
        [notificationCenter postNotificationName:AFNetworkingReachabilityDidChangeNotification object:nil userInfo:userInfo];
    });
}
//状态变化回调时候会用到
static void AFNetworkReachabilityCallback(SCNetworkReachabilityRef __unused target, SCNetworkReachabilityFlags flags, void *info) {
    AFPostReachabilityStatusChange(flags, (__bridge AFNetworkReachabilityStatusBlock)info);//这里void*和id的转换，在ARC下要加__bridge修饰
}

//调用了 Block_copy（用于 retain 一个 block 函数，即在堆空间新建或直接引用一个 block 拷贝）
static const void * AFNetworkReachabilityRetainCallback(const void *info) {
    return Block_copy(info);
}
//调用了 Block_release（用于 release 一个 block 函数，即将 block 从堆空间移除或移除相应引用）
static void AFNetworkReachabilityReleaseCallback(const void *info) {
    if (info) {
        Block_release(info);
    }
}

@interface AFNetworkReachabilityManager ()
@property (readonly, nonatomic, assign) SCNetworkReachabilityRef networkReachability;//SCNetworkReachabilityRef用来保存创建连接返回的引用
@property (readwrite, nonatomic, assign) AFNetworkReachabilityStatus networkReachabilityStatus;//在.h中是readonly
@property (readwrite, nonatomic, copy) AFNetworkReachabilityStatusBlock networkReachabilityStatusBlock;
@end

@implementation AFNetworkReachabilityManager

+ (instancetype)sharedManager {
    static AFNetworkReachabilityManager *_sharedManager = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _sharedManager = [self manager];
    });

    return _sharedManager;
}

+ (instancetype)managerForDomain:(NSString *)domain {
    //根据传入的域名创建网络连接引用
    //第一个参数可以为NULL或kCFAllocatorDefault，第二个参数比如为"www.apple.com"
    SCNetworkReachabilityRef reachability = SCNetworkReachabilityCreateWithName(kCFAllocatorDefault, [domain UTF8String]);
    AFNetworkReachabilityManager *manager = [[self alloc] initWithReachability:reachability];
    
    CFRelease(reachability);//手动管理内存

    return manager;
}

+ (instancetype)managerForAddress:(const void *)address {
    //根据传入的地址创建网络连接引用。
    //SCNetworkReachabilityCreateWithAddress第一个参数可以为NULL或kCFAllocatorDefault，第二个参数为需要测试连接的IP地址，当为0.0.0.0时则可以查询本机的网络连接状态。
    SCNetworkReachabilityRef reachability = SCNetworkReachabilityCreateWithAddress(kCFAllocatorDefault, (const struct sockaddr *)address);//返回的网络连接引用必须在用完后释放。
    AFNetworkReachabilityManager *manager = [[self alloc] initWithReachability:reachability];

    CFRelease(reachability);//手动管理内存
    
    return manager;
}
/*
 struct sockaddr {
	__uint8_t	sa_len;
 sa_family_t	sa_family;  协议族，一般都是“AF_xxx”的形式。通常大多用的是都是AF_INET,代表TCP/IP协议族
 char		sa_data[14];    14字节协议地址
 };
 这个数据结构用做bind、connect、recvfrom、sendto等函数的参数，指明地址信息。但一般编程中并不直接针对此数据结构操作，而是使用sockaddr_in
*/

//ipv6是iOS9和OSX10.11后推出的，涉及到socket知识
/*
 struct sockaddr_in {
 __uint8_t    sin_len;
 sa_family_t    sin_family; 协议族，在socket编程中只能是AF_INET
 in_port_t    sin_port;     存储端口号（使用网络字节顺序）
 struct in_addr  sin_addr;  按照网络字节顺序存储IP地址，使用in_addr这个数据结构
 char        sin_zero[8];   让sockaddr与sockaddr_in两个数据结构保持大小相同而保留的空字节。sockaddr_in和sockaddr是并列的结构，指向sockaddr_in的结构体的指针也可以指向sockaddr的结构体，并代替它。也就是说，你可以使用sockaddr_in建立你所需要的信息,然后用进行类型转换就可以了
 };
 
 struct in_addr {
	in_addr_t s_addr;
 };
 结构体in_addr 用来表示一个32位的IPv4地址。in_addr_t 是一个32位的unsigned long，其中每8位代表一个IP地址位中的一个数值。
 　　例如192.168.3.144记为0xc0a80390
 */
+ (instancetype)manager
{
#if (defined(__IPHONE_OS_VERSION_MIN_REQUIRED) && __IPHONE_OS_VERSION_MIN_REQUIRED >= 90000) || (defined(__MAC_OS_X_VERSION_MIN_REQUIRED) && __MAC_OS_X_VERSION_MIN_REQUIRED >= 101100)
    struct sockaddr_in6 address;
    bzero(&address, sizeof(address));
    address.sin6_len = sizeof(address);
    address.sin6_family = AF_INET6;
#else
    struct sockaddr_in address;
    bzero(&address, sizeof(address));//初始化
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
#endif
    return [self managerForAddress:&address];
}

- (instancetype)initWithReachability:(SCNetworkReachabilityRef)reachability {
    self = [super init];
    if (!self) {
        return nil;
    }
    _networkReachability = CFRetain(reachability);//为什么要retain？谁创建谁释放，这个参数reachability不是在这个方法中创建的。在+managerForDomain:和+managerForAddress:方法实现中，最后释放掉了网络连接引用reachability，因此要在本方法中先把它retain一次。
    self.networkReachabilityStatus = AFNetworkReachabilityStatusUnknown;

    return self;
}

//禁用该初始化方法
- (instancetype)init NS_UNAVAILABLE
{
    return nil;
}

- (void)dealloc {
    [self stopMonitoring];
    
    if (_networkReachability != NULL) {
        CFRelease(_networkReachability);//retain了就要release
    }
}

#pragma mark -

- (BOOL)isReachable {
    return [self isReachableViaWWAN] || [self isReachableViaWiFi];
}

- (BOOL)isReachableViaWWAN {
    return self.networkReachabilityStatus == AFNetworkReachabilityStatusReachableViaWWAN;
}

- (BOOL)isReachableViaWiFi {
    return self.networkReachabilityStatus == AFNetworkReachabilityStatusReachableViaWiFi;
}

#pragma mark -

- (void)startMonitoring {
    [self stopMonitoring];//先关闭监听

    if (!self.networkReachability) {//如果网络不可达，就返回
        return;
    }
    //避免循环引用要用weakself，避免在block执行过程中，突然出现self被释放的情况，就用strongself
    __weak __typeof(self)weakSelf = self;
    AFNetworkReachabilityStatusBlock callback = ^(AFNetworkReachabilityStatus status) {//1.网络状态变化时回调的是这个block
        __strong __typeof(weakSelf)strongSelf = weakSelf;

        strongSelf.networkReachabilityStatus = status;
        if (strongSelf.networkReachabilityStatusBlock) {
            strongSelf.networkReachabilityStatusBlock(status);//2.其中回调block中会执行_networkReachabilityStatusBlock，这个block才是核心，由-setReachabilityStatusChangeBlock:方法对这个block进行设置
        }

    };
    
    //创建上下文
    /*
     typedef struct {
     CFIndex		version;   作为参数传递到SCDynamicStore创建函数的结构类型的版本号，这里是version 0。
     void *		__nullable info; 表示网络状态处理的回调函数。指向用户指定的数据块的C指针，void* 相当于oc的id
     const void	* __nonnull (* __nullable retain)(const void *info); retain info
     void		(* __nullable release)(const void *info); 对应上一个元素 release
     CFStringRef	__nonnull (* __nullable copyDescription)(const void *info); 提供信息字段的描述
     } SCNetworkReachabilityContext;
     */
    SCNetworkReachabilityContext context = {0, (__bridge void *)callback, AFNetworkReachabilityRetainCallback, AFNetworkReachabilityReleaseCallback, NULL};
    //设置回调。SCNetworkReachabilitySetCallback给当前客户端指定一个target(第一个参数)，当设备对于这个target连接状态发生改变时，就进行回调（第二个参数）。它第二个参数：SCNetworkReachabilityCallBack类型的值，是当网络可达性更改时调用的函数，如果为NULL，则目标的当前客户端将被删除。SCNetworkReachabilityCallBack中的info参数就是SCNetworkReachabilityContext中对应的那个info
    SCNetworkReachabilitySetCallback(self.networkReachability, AFNetworkReachabilityCallback, &context);
    //加入runloop
    SCNetworkReachabilityScheduleWithRunLoop(self.networkReachability, CFRunLoopGetMain(), kCFRunLoopCommonModes);
    ////子线程中获取网络状态，主线程执行回调并发送通知（AFPostReachabilityStatusChange函数）
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0),^{
        SCNetworkReachabilityFlags flags;
        //SCNetworkReachabilityGetFlags获得可达性状态
        if (SCNetworkReachabilityGetFlags(self.networkReachability, &flags)) {
            AFPostReachabilityStatusChange(flags, callback);
        }
    });
    /*SCNetworkReachability 编程接口支持同步和异步两种模式。
    在同步模式中，可以通过调用SCNetworkReachabilityGetFlag函数来获得可达性状态；
    在异步模式中，可以调度SCNetworkReachability对象到客户端对象线程的运行循环上，客户端实现一个回调函数来接收通知，当远程主机改变可达性状态，回调则可响应。
    */
}

- (void)stopMonitoring {
    if (!self.networkReachability) {
        return;
    }
    SCNetworkReachabilityUnscheduleFromRunLoop(self.networkReachability, CFRunLoopGetMain(), kCFRunLoopCommonModes);
}

#pragma mark -

- (NSString *)localizedNetworkReachabilityStatusString {
    return AFStringFromNetworkReachabilityStatus(self.networkReachabilityStatus);
}

#pragma mark -

- (void)setReachabilityStatusChangeBlock:(void (^)(AFNetworkReachabilityStatus status))block {
    self.networkReachabilityStatusBlock = block;
}

#pragma mark - NSKeyValueObserving
//注册键值依赖
+ (NSSet *)keyPathsForValuesAffectingValueForKey:(NSString *)key {
    if ([key isEqualToString:@"reachable"] || [key isEqualToString:@"reachableViaWWAN"] || [key isEqualToString:@"reachableViaWiFi"]) {
        return [NSSet setWithObject:@"networkReachabilityStatus"];
    }

    return [super keyPathsForValuesAffectingValueForKey:key];
}

@end
#endif
