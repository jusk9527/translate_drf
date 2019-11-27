
### 流程图

```
graph LR

dispatch-->initialize_request
initialize_request-->initial
initial-->check_throttles
check_throttles-->get_throttles
get_throttles-->判断
判断-->allow_request=true
判断-->allow_request=false
allow_request=false-->返回需要等待多少秒
allow_request=true-->通过

```

![](https://raw.githubusercontent.com/jusk9527/images/master/data/20191127145618.png)

#### 执行dispatch()这个方法

- def dispatch(self, request, *args, **kwargs):


```
    def dispatch(self, request, *args, **kwargs):
        """
        `.dispatch()` is pretty much the same as Django's regular dispatch,
        but with extra hooks for startup, finalize, and exception handling.
        """
        self.args = args
        self.kwargs = kwargs

        # 对django原始的request进行封装，返回Request对象(新的对象)。
        request = self.initialize_request(request, *args, **kwargs)
        self.request = request
        self.headers = self.default_response_headers  # deprecate?

        try:
            # 这里的request是新封装的request,然后进一步封装，加入新的一些功能，比如认证，限速，权限
            self.initial(request, *args, **kwargs)

            # Get the appropriate handler method
            if request.method.lower() in self.http_method_names:
                handler = getattr(self, request.method.lower(),
                                  self.http_method_not_allowed)
            else:
                handler = self.http_method_not_allowed

            response = handler(request, *args, **kwargs)

        except Exception as exc:
            response = self.handle_exception(exc)

        self.response = self.finalize_response(request, response, *args, **kwargs)
        return self.response
```
#### 执行initialize_request

- self.initialize_request(request, *args, **kwargs)


```
def initialize_request(self, request, *args, **kwargs):
    """
    Returns the initial request object.
    """
    parser_context = self.get_parser_context(request)

    return Request(
        request,
        parsers=self.get_parsers(),
        authenticators=self.get_authenticators(),
        negotiator=self.get_content_negotiator(),
        parser_context=parser_context
    )

```

#### 执行initial()方法

- self.initial(request, *args, **kwargs)


```
def initial(self, request, *args, **kwargs):
    """
    Runs anything that needs to occur prior to calling the method handler.
    """
    self.format_kwarg = self.get_format_suffix(**kwargs)

    # Perform content negotiation and store the accepted info on the request
    neg = self.perform_content_negotiation(request)
    request.accepted_renderer, request.accepted_media_type = neg

    # Determine the API version, if versioning is in use.
    version, scheme = self.determine_version(request, *args, **kwargs)
    request.version, request.versioning_scheme = version, scheme

    # Ensure that the incoming request is permitted
    # 身份认证
    self.perform_authentication(request)
    # 检查权限
    self.check_permissions(request)
    # 流量限速
    self.check_throttles(request)
```



#### check_throttles


```
def check_throttles(self, request):
    """
    Check if request should be throttled.
    Raises an appropriate exception if the request is throttled.

    检查是否应该限制请求，如果请求被限制，则引发适当的异常
    """
    throttle_durations = []
    # 循环频率控制类结果
    for throttle in self.get_throttles():
        #判断启动的allow_request方法返回结果，true则频率通过，否则返回等待多少秒可以访问
        if not throttle.allow_request(request, self):
            throttle_durations.append(throttle.wait())

    if throttle_durations:
        # Filter out `None` values which may happen in case of config / rate
        # changes, see #1438
        durations = [
            duration for duration in throttle_durations
            if duration is not None
        ]

        duration = max(durations, default=None)
        self.throttled(request, duration)
```

#### get_throttles


```
def get_throttles(self):
    """
    Instantiates and returns the list of throttles that this view uses.

    利用列表生成式返回每个限速类的实例
    """
    return [throttle() for throttle in self.throttle_classes]
```

#### allow_request:

- 跑到限速基类那边去了


```
class BaseThrottle:
    """
    Rate throttling of requests.
    """

    def allow_request(self, request, view):
        """
        Return `True` if the request should be allowed, `False` otherwise.
        """
        raise NotImplementedError('.allow_request() must be overridden')

    #　获取请求 ip
    def get_ident(self, request):
        """
        Identify the machine making the request by parsing HTTP_X_FORWARDED_FOR
        if present and number of proxies is > 0. If not use all of
        HTTP_X_FORWARDED_FOR if it is available, if not use REMOTE_ADDR.
        """
        xff = request.META.get('HTTP_X_FORWARDED_FOR')
        remote_addr = request.META.get('REMOTE_ADDR')
        
        #这里request是封装以后的requst，django原生的是request._request.META 这样也可以获取
        num_proxies = api_settings.NUM_PROXIES

        if num_proxies is not None:
            if num_proxies == 0 or xff is None:
                return remote_addr
            addrs = xff.split(',')
            client_addr = addrs[-min(num_proxies, len(addrs))]
            return client_addr.strip()

        return ''.join(xff.split()) if xff else remote_addr

    def wait(self):
        """
        Optionally, return a recommended number of seconds to wait before
        the next request.
        """
        return None
```


### 速率控制类

#### BaseThrottle


- 最基本的控制速率类，很多时候我们需要重写allow_request和wait
```
class BaseThrottle:
    """
    Rate throttling of requests.
    """

    def allow_request(self, request, view):
        """
        Return `True` if the request should be allowed, `False` otherwise.
        """
        raise NotImplementedError('.allow_request() must be overridden')

    def get_ident(self, request):
        """
        Identify the machine making the request by parsing HTTP_X_FORWARDED_FOR
        if present and number of proxies is > 0. If not use all of
        HTTP_X_FORWARDED_FOR if it is available, if not use REMOTE_ADDR.
        """
        xff = request.META.get('HTTP_X_FORWARDED_FOR')
        remote_addr = request.META.get('REMOTE_ADDR')

        # 这里request是封装以后的request,django原生的是request._request.META 这样也可以获取
        num_proxies = api_settings.NUM_PROXIES

        if num_proxies is not None:
            if num_proxies == 0 or xff is None:
                return remote_addr
            addrs = xff.split(',')
            client_addr = addrs[-min(num_proxies, len(addrs))]
            return client_addr.strip()

        return ''.join(xff.split()) if xff else remote_addr

    def wait(self):
        """
        Optionally, return a recommended number of seconds to wait before
        the next request.

        返回下一次需要等待多少秒
        """
        return None
```


#### SimpleRateThrottle

比较多继承这个类去限速，他可以获取ip,并放在缓存中，然后进行请求限速
```
class SimpleRateThrottle(BaseThrottle):
    """
    A simple cache implementation, that only requires `.get_cache_key()`
    to be overridden.

    The rate (requests / seconds) is set by a `rate` attribute on the View
    class.  The attribute is a string of the form 'number_of_requests/period'.

    Period should be one of: ('s', 'sec', 'm', 'min', 'h', 'hour', 'd', 'day')

    Previous request information used for throttling is stored in the cache.
    """

    # 存放请求时间，类似与实例中的大字典，这里使用的是djagno的缓存
    cache = default_cache
    timer = time.time
    cache_format = 'throttle_%(scope)s_%(ident)s'
    scope = None
    THROTTLE_RATES = api_settings.DEFAULT_THROTTLE_RATES

    def __init__(self):
        if not getattr(self, 'rate', None):
            self.rate = self.get_rate()
        self.num_requests, self.duration = self.parse_rate(self.rate)

    def get_cache_key(self, request, view):
        """
        Should return a unique cache-key which can be used for throttling.
        Must be overridden.

        May return `None` if the request should not be throttled.


        # 获取请求的key标识，必须要有否则会报错，这里可以重写，使用用户的用户名、或其他作为key，在示例中使用的get_ident方法用户获取用户IP作为key
        """
        raise NotImplementedError('.get_cache_key() must be overridden')

    def get_rate(self):
        """
        Determine the string representation of the allowed request rate.

        获取配置文件的配置速率
        """
        if not getattr(self, 'scope', None):
            # 通过获取共有属性scope来获取配置的速率

            msg = ("You must set either `.scope` or `.rate` for '%s' throttle" %
                   self.__class__.__name__)
            raise ImproperlyConfigured(msg)

        try:
            return self.THROTTLE_RATES[self.scope]
        except KeyError:
            msg = "No default throttle rate set for '%s' scope" % self.scope
            raise ImproperlyConfigured(msg)

    # 格式化速率
    def parse_rate(self, rate):
        """
        Given the request rate string, return a two tuple of:
        <allowed number of requests>, <period of time in seconds>

        格式化速率
        """
        if rate is None:
            return (None, None)

        # 分离字符串
        num, period = rate.split('/')
        num_requests = int(num)

        # 转换时间为数字,示例配置的5/m，m转为60秒
        duration = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}[period[0]]
        return (num_requests, duration)

    def allow_request(self, request, view):
        """
        Implement the check to see if the request should be throttled.

        On success calls `throttle_success`.
        On failure calls `throttle_failure`.

        判断请求的速率是否通过
        """
        if self.rate is None:
            return True

        self.key = self.get_cache_key(request, view)
        if self.key is None:
            return True

        self.history = self.cache.get(self.key, [])
        self.now = self.timer()

        # Drop any requests from the history which have now passed the
        # throttle duration

        # 频率判断实现原理，已经举例进行了说明
        while self.history and self.history[-1] <= self.now - self.duration:
            self.history.pop()
        if len(self.history) >= self.num_requests:
            return self.throttle_failure()
        return self.throttle_success()

    # 频率通过返回true
    def throttle_success(self):
        """
        Inserts the current request's timestamp along with the key
        into the cache.
        """
        self.history.insert(0, self.now)
        self.cache.set(self.key, self.history, self.duration)
        return True

    # 不通过则返回false
    def throttle_failure(self):
        """
        Called when a request to the API has failed due to throttling.
        """
        return False

    # 返回等待时间
    def wait(self):
        """
        Returns the recommended next request time in seconds.
        """
        if self.history:
            remaining_duration = self.duration - (self.now - self.history[-1])
        else:
            remaining_duration = self.duration

        available_requests = self.num_requests - len(self.history) + 1
        if available_requests <= 0:
            return None

        return remaining_duration / float(available_requests)
```

举例使用：

```
from rest_framework.throttling import SimpleRateThrottle

class VisitThrottle(SimpleRateThrottle):
    """5秒内最多访问三次"""
    scope = "WD"  #settings配置文件中的key,用于获取配置的频率

    def get_cache_key(self, request, view):
        return self.get_ident(request)
```

setting中配置


```
REST_FRAMEWORK = {
    #频率控制配置
    "DEFAULT_THROTTLE_CLASSES":['utils.throttle.VisitThrottle'],   #全局配置，
    "DEFAULT_THROTTLE_RATES":{
        'WD':'5/m',         #速率配置每分钟不能超过5次访问，WD是scope定义的值，

    }
}
```

views中配置

```
class OrderView(APIView):
    '''查看订单'''
    from utils.permissions import MyPremission
    authentication_classes = [Authentication,]    #添加认证
    permission_classes = [MyPremission,]           #添加权限控制
    def get(self,request,*args,**kwargs):
        #request.user
        #request.auth
        ret = {'code':1000,'msg':"你的订单已经完成",'data':"买了一个mac"}
        return JsonResponse(ret,safe=True)
```

#### AnonRateThrottle匿名访问设置


```
class AnonRateThrottle(SimpleRateThrottle):
    """
    Limits the rate of API calls that may be made by a anonymous users.

    The IP address of the request will be used as the unique cache key.
    """
    scope = 'anon'

    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            return None  # Only throttle unauthenticated requests.

        return self.cache_format % {
            'scope': self.scope,
            'ident': self.get_ident(request)
        }
```

#### UserRateThrottle 对用户访问设置


```

class UserRateThrottle(SimpleRateThrottle):
    """
    Limits the rate of API calls that may be made by a given user.

    The user id will be used as a unique cache key if the user is
    authenticated.  For anonymous requests, the IP address of the request will
    be used.
    """
    scope = 'user'

    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            ident = request.user.pk
        else:
            ident = self.get_ident(request)

        return self.cache_format % {
            'scope': self.scope,
            'ident': ident
        }
```


#### 自定义访问设置

最主要重写allow_request，wait方法

```
from rest_framework.throttling import BaseThrottle
import time

REQUEST_RECORD = {}  # 访问记录，可使用nosql数据库


class VisitThrottle(BaseThrottle):
    '''60s内最多能访问5次'''

    def __init__(self):
        self.history = None

    def allow_request(self, request, view):
        # 获取用户ip (get_ident)
        remote_addr = self.get_ident(request)
        ctime = time.time()

        if remote_addr not in REQUEST_RECORD:
            REQUEST_RECORD[remote_addr] = [ctime, ]  # 保持请求的时间，形式{ip:[时间,]}
            return True  # True表示可以访问
        # 获取当前ip的历史访问记录
        history = REQUEST_RECORD.get(remote_addr)
       
        self.history = history

       
        while history and history[-1] < ctime - 60:
            # while循环确保每列表中是最新的60秒内的请求
            
            history.pop()
        # 访问记录小于5次，将本次请求插入到最前面，作为最新的请求
        if len(history) < 5:
            history.insert(0, ctime)
            return True

    def wait(self):
        '''返回等待时间'''
        ctime = time.time()
        return 60 - (ctime - self.history[-1])

```


#### 使用方式

- 使用方式
    - 继承BaseThrottle类
    - 重写request_allow方法和wait方法，request_allow方法返回true代表通过，否则拒绝，wait返回等待的时间

```
###全局使用

REST_FRAMEWORK = {
    #频率控制配置
    "DEFAULT_THROTTLE_CLASSES":['utils.throttle.VisitThrottle'],   #全局配置，
    "DEFAULT_THROTTLE_RATES":{
        'WD':'5/m',         #速率配置每分钟不能超过5次访问，WD是scope定义的值

    }
}

##单一视图使用
throttle_classes = [VisitThrottle,]

##优先级
单一视图>全局
```
