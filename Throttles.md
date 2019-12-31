
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

#### [2.速率源码过程解析](#)



```markdown
一、在django中客户端发来的请求会执行视图类的as_view方法，而as_view方法会执行dispatch方法，然后进行反射执行相应的方法（get、post等）


反射：通过字符串的形式操作对象相关的属性
https://www.chenshaowen.com/blog/reflection-of-python.html
1. getattr(object,‘name‘,‘default’)
如果存在name的属性方法，则返回name的属性方法，否则返回default的属性方法。
2. hasattr(object, ’name‘)
判断对象object是否包含名为name的属性方法，存在则返回True，否则返回False。hasattr是通过调用getattr(ojbect, ’name‘)是否抛出异常来实现）。
3. setattr(object,‘name’,’default‘)
设置对象object的name属性值为default,如果没有name属性，那么创建一个新的属性。
4. delattr(object,’name’)
删除对象object的name属性值。



举个栗子
import requests

class Http(object):


    def get(self,url):
        res = requests.get(url)
        response = res.text
        return response

    def post(self,url):
        res = requests.post(url)
        response = res.text
        return response

# 使用反射后
url = "https://www.jianshu.com/u/14140bf8f6c7"
method = input("请求方法>>>:")
h = Http()

if hasattr(h,method):
    func = getattr(h,method)
    res = func(url)
    print(res)
else:
    print("你的请求方式有误...")
    

https://www.chenshaowen.com/blog/reflection-of-python.html



二、drf中的APIView中只要重写as_view()方法
重写dispatch方法，就能加入相对应的功能，我们来看下drf中APIView中as_view()方法
```

##### [2-1.as_view()](#)
```python
# 类方法
@classmethod
def as_view(cls, **initkwargs):
    """
    Store the original class on the view function.

    This allows us to discover information about the view when we do URL
    reverse lookups.  Used for breadcrumb generation.
    """

    # 检查类中定义的queryset是否是这个models.query.QuerySet类型，必行抛异常
    if isinstance(getattr(cls, 'queryset', None), models.query.QuerySet):
        def force_evaluation():
            raise RuntimeError(
                'Do not evaluate the `.queryset` attribute directly, '
                'as the result will be cached and reused between requests. '
                'Use `.all()` or call `.get_queryset()` instead.'
            )
        cls.queryset._fetch_all = force_evaluation

    # 执行父类的as_view方法
    view = super().as_view(**initkwargs)
    view.cls = cls
    view.initkwargs = initkwargs

    # Note: session based authentication is explicitly CSRF validated,
    # all other authentication is CSRF exempt.

    # 返回view，由于是前后端分离就取消csrf认证
    return csrf_exempt(view)
```

**小结**
```markdown
这个方法是APIView里面的，我们可以看到他执行了父类的as_view方法,
也就相当于初始化父类，我们接下来看下最基础django中父类View中的as_view方法是怎么样的
```



##### [2-2.View](#)

```python
class View:
    # 类方法
    @classonlymethod
    def as_view(cls, **initkwargs):
        """Main entry point for a request-response process."""
        for key in initkwargs:
            if key in cls.http_method_names:
                raise TypeError("You tried to pass in the %s method name as a "
                                "keyword argument to %s(). Don't do that."
                                % (key, cls.__name__))
            if not hasattr(cls, key):
                raise TypeError("%s() received an invalid keyword %r. as_view "
                                "only accepts arguments that are already "
                                "attributes of the class." % (cls.__name__, key))

        def view(request, *args, **kwargs):
            self = cls(**initkwargs)
            if hasattr(self, 'get') and not hasattr(self, 'head'):
                self.head = self.get
            self.request = request
            self.args = args
            self.kwargs = kwargs
            return self.dispatch(request, *args, **kwargs)
        view.view_class = cls
        view.view_initkwargs = initkwargs

        # take name and docstring from class
        update_wrapper(view, cls, updated=())

        # and possible attributes set by decorators
        # like csrf_exempt from dispatch
        update_wrapper(view, cls.dispatch, assigned=())
        return view
```

**小结**

```markdown
父类绕来绕去还是去执行self.dispatch了，下面我们来总结下上面的执行过程

1、View 的执行顺序：
as_view()方法-----》返回view函数名称（一旦有请求来了就必须要执行as_view方法，然后再执行dispatch方法）


2、APIView 的执行顺序
执行父类as_view方法---》执行dispath方法(APIView重写dispath方法)



==问==：这个看来没有封装什么，只是检查了是否queryset值的类型，然后由于前后端分取消csrf认证

==答==：他执行了

view = super().as_view(**initkwargs)

就一定会执行dispatch()方法

==疑问==：会不会重写了dispatch()方法呢？,搜索一下
```



![](https://raw.githubusercontent.com/jusk9527/images/master/data/20191114100944.png)

##### [2-3.dispatch()](#)


```python
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

**小结**
```
这里我们可以知道APIView 重写了父类View的dispatch

1. 从这里我们可以知道 
2. 对django原始的request进行封装，返回Request对象(新的对象)。

request = self.initialize_request(request, *args, **kwargs)

我们接下来看看他在原有的request基础上封装了什么
```






##### [self.initialize_request()](#)

```python
def initialize_request(self, request, *args, **kwargs):
    """
    Returns the initial request object.
    """
    parser_context = self.get_parser_context(request)

    # 这里将原来的request封装进来，加入新的功能
    return Request(
        request,
        parsers=self.get_parsers(),
        # 加入认证
        authenticators=self.get_authenticators(),
        negotiator=self.get_content_negotiator(),
        parser_context=parser_context
    )
```

这里我们可以知道返回了一个新的Request，到低封装了什么呢?


![](https://raw.githubusercontent.com/jusk9527/images/master/data/20191113173823.png)

![](https://raw.githubusercontent.com/jusk9527/images/master/data/20191113173941.png)




```markdown

新的Request他封装了

- 请求（HttpRequest）。原始请求实例

- 解析器类（列表/元组）。用于分析

- 请求内容。

- 身份验证类（列表/元组）。用于尝试的身份验证


这里我们由于是分析他的认证就不对他封装的其他进行说明，我们还是回到
```


![](https://raw.githubusercontent.com/jusk9527/images/master/data/20191113174516.png)



在APIView中

![](https://raw.githubusercontent.com/jusk9527/images/master/data/20191113174643.png)


![](https://raw.githubusercontent.com/jusk9527/images/master/data/20191113174751.png)

```markdown
1. self.get_authenticators()源码分析，采用列表生成式，循环self.authentication_classes，实例化其中的每一个类，返回列表。
2. 不难发现authentication_classes属性正式我们在认证的时候用到认证类列表，这里会自动寻找该属性进行认证。
3. 倘若我们的视图类没有定义认证方法呢？，当然django rest framework 已经给我们加了默认配置，
4. 如果我们没有定义会自动使用settings中的DEFAULT_AUTHENTICATION_CLASSES作为默认(全局)下面是APIView类中的共有属性
```


```python
self.authentication_classes
```


![](https://raw.githubusercontent.com/jusk9527/images/master/data/20191113175015.png)



```



我们上面分析了APIView在原有的request基础上封装了一些其他功能


self.initialize_request(request, *args, **kwargs)


我们继续分析往下从diapath()这个方法往下走


我们可以看到他是将我们封装后的新的request继续往下传递，然后执行

```

![](https://raw.githubusercontent.com/jusk9527/images/master/data/20191113175609.png)

##### [self.initial()]()


```python
# 这里的request 是封装后的request，传入def initial(self, request, *args, **kwargs)这个方法
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



```markdown
原来他是调用了这个方法完成认证。我们继续看下这个方法是如何完成认证的
```


#### [check_throttles()](#)


```python
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

#### [get_throttles](#)


```python
def get_throttles(self):
    """
    Instantiates and returns the list of throttles that this view uses.

    利用列表生成式返回每个限速类的实例
    """
    return [throttle() for throttle in self.throttle_classes]
```

#### [allow_request:](#)

- 跑到限速基类那边去了


```python
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
```python
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
```python
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

```python
from rest_framework.throttling import SimpleRateThrottle

class VisitThrottle(SimpleRateThrottle):
    """5秒内最多访问三次"""
    scope = "WD"  #settings配置文件中的key,用于获取配置的频率

    def get_cache_key(self, request, view):
        return self.get_ident(request)
```

setting中配置


```python
REST_FRAMEWORK = {
    #频率控制配置
    "DEFAULT_THROTTLE_CLASSES":['utils.throttle.VisitThrottle'],   #全局配置，
    "DEFAULT_THROTTLE_RATES":{
        'WD':'5/m',         #速率配置每分钟不能超过5次访问，WD是scope定义的值，

    }
}
```

views中配置

```python
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


```python
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


```python
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

```python
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

```python
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
