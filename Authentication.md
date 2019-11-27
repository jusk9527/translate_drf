
### 源码流程

![](https://raw.githubusercontent.com/jusk9527/images/master/data/20191114111308.png)

#### 一、认证源码过程解析

分析：

1、在django中客户端发来的请求会执行视图类的as_view方法，而as_view方法会执行dispatch方法，然后进行反射执行相应的方法（get、post等）


2、drf中的APIView中只要重写as_view()方法，重写dispatch方法，就能加入相对应的功能，我们来看下drf中APIView中as_view()方法

``` 
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


- View


```
class View:

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

1、View 的执行顺序：
as_view()方法-----》返回view函数名称（一旦有请求来了就必须要执行as_view方法，然后再执行dispatch方法）


2、APIView 的执行顺序
执行父类as_view方法---》执行dispath方法(APIView重写dispath方法)




==问==：这个看来没有封装什么，只是检查了是否queryset值的类型，然后由于前后端分取消csrf认证

==答==：他执行了

```
view = super().as_view(**initkwargs)
```

就一定会执行dispatch()方法

==疑问==：会不会重写了dispatch()方法呢？,搜索一下


![](https://raw.githubusercontent.com/jusk9527/images/master/data/20191114100944.png)

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


==小结：==

1. 从这里我们可以知道 
2. 对django原始的request进行封装，返回Request对象(新的对象)。

```
request = self.initialize_request(request, *args, **kwargs)
```



- self.initialize_request(request, *args, **kwargs)
```
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



新的Request他封装了

- 请求（HttpRequest）。原始请求实例

- 解析器类（列表/元组）。用于分析

- 请求内容。

- 身份验证类（列表/元组）。用于尝试的身份验证


这里我们由于是分析他的认证就不对他封装的其他进行说明，我们还是回到



![](https://raw.githubusercontent.com/jusk9527/images/master/data/20191113174516.png)



在APIView中

![](https://raw.githubusercontent.com/jusk9527/images/master/data/20191113174643.png)


![](https://raw.githubusercontent.com/jusk9527/images/master/data/20191113174751.png)

```
self.get_authenticators()源码分析，采用列表生成式，循环self.authentication_classes，实例化其中的每一个类，返回列表，不难发现authentication_classes属性正式我们在认证的时候用到认证类列表，这里会自动寻找该属性进行认证。倘若我们的视图类没有定义认证方法呢？，当然django rest framework 已经给我们加了默认配置，如果我们没有定义会自动使用settings中的DEFAULT_AUTHENTICATION_CLASSES作为默认(全局)下面是APIView类中的共有属性

```


```
self.authentication_classes
```

我们继续

![](https://raw.githubusercontent.com/jusk9527/images/master/data/20191113175015.png)



我们上面分析了

```
self.initialize_request(request, *args, **kwargs)
```
这行代码在封装什么的话

我们继续分析往下从diapath()这个方法往下走

![](https://raw.githubusercontent.com/jusk9527/images/master/data/20191113175609.png)


我们可以看到他是将我们封装后的新的request继续往下传递，然后执行

- self.initial(request, *args, **kwargs)

看下这个方法


```
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


原来他是调用了这个方法完成认证。我们继续看下这个方法是如何完成认证的

- self.perform_authentication(request)



```
    def perform_authentication(self, request):
        """
        Perform authentication on the incoming request.

        Note that if you override this and simply 'pass', then authentication
        will instead be performed lazily, the first time either
        `request.user` or `request.auth` is accessed.
        """
        request.user
```


他返回的是新封装request的user属性。那我们就得看下他源码是如何封装这个属性，以及user这个属性表示什么


```
    @property
    def user(self):
        """
        Returns the user associated with the current request, as authenticated
        by the authentication classes provided to the request.
        
        返回与当前请求关联的经过身份验证的用户，提供给请求的身份验证
        """
        # 判断如果_user 不在request中的话，执行 self._authenticate()这个方法
        if not hasattr(self, '_user'):
            with wrap_attributeerrors():
                # 执行认证方法
                self._authenticate()
        return self._user
```

我们可以看到他其实还是执行了self._authenticate()。我们还是要看下他的这个authenticate()方法。


-  self._authenticate()

```
    def _authenticate(self):
        """
        Attempt to authenticate the request using each authentication instance
        in turn.
        """
        for authenticator in self.authenticators:
            try:

                # 执行认证类的authenticate方法
                # 这里分三种情况
                # 1.如果authenticate方法抛出异常，self._not_authenticated()执行
                # 2.有返回值，必须是元组：（request.user,request.auth）
                
                
                
                # 认证类的实例执行authenticate()这个方法，这个可以重写自己的代码逻辑
                user_auth_tuple = authenticator.authenticate(self)
            except exceptions.APIException:
                self._not_authenticated()
                raise

            # 3.返回None，表示当前认证不处理，等下一个认证来处理
            if user_auth_tuple is not None:
                self._authenticator = authenticator
                # 返回值对应示例中的token_obj.user和token_obj
                self.user, self.auth = user_auth_tuple
                return

        self._not_authenticated()
```

这里他将执行每一个认证类的实例的authenticate()方法，必须要求返回元祖，然后元祖不为空时就将元祖内的user赋值给self.user



- def authenticate(self, request)

```
class ForcedAuthentication:
    """
    This authentication class is used if the test client or request factory
    forcibly authenticated the request.
    """

    def __init__(self, force_user, force_token):
        self.force_user = force_user
        self.force_token = force_token

    # 一定返回元组
    def authenticate(self, request):
        return (self.force_user, self.force_token)
```

这个认证工厂要求必须返回元祖


- def _not_authenticated(self)


```
    def _not_authenticated(self):
        """
        Set authenticator, user & authtoken representing an unauthenticated request.

        Defaults are None, AnonymousUser & None.
        """
        self._authenticator = None

        if api_settings.UNAUTHENTICATED_USER:
            self.user = api_settings.UNAUTHENTICATED_USER()
        else:
            self.user = None

        if api_settings.UNAUTHENTICATED_TOKEN:
            self.auth = api_settings.UNAUTHENTICATED_TOKEN()
        else:
            self.auth = None
```

没有身份，相当于匿名用户，默认设置AnonymousUser，如需要单独设置匿名用户返回值，则编写需要写UNAUTHENTICATED_USER的返回值：



- 所以我们需要认证的时候，需要在每一个认证类中定义authenticate进行验证，并且需要返回元祖。


#### 配置认证类

我们知道全局配置都在api_setting中

其中引用了django，settings.py中的REST_FRAMEWORK作为key作为配置，所以全局配置示例：


```
#全局认证配置
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES":['API.utils.auth.Authentication',]   #其中写认证的类的路径，不要在views中，这里我放在了utils目录下auth.py中
}
```


##### 局部使用

局部某个视图不需要认证，则在视图类中加入authentication_classes=[]


```
authentication_classes = []    #authentication_classes为空，代表不需要认证
```


#### 匿名设置


```
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES":['API.utils.auth.Authentication',]，  #其中写认证的类的路径，不要在views中，这里我放在了utils目录下auth.py中
    "UNAUTHENTICATED_USER": lambda:"匿名"，#匿名用户配置，只需要函数或类的对应的返回值，对应request.user="匿名"
"UNAUTHENTICATED_token": None，#匿名token，只需要函数或类的对应的返回值，对应request.auth=None


}
```


#### 内置认证类

1. BaseAuthentication

BaseAuthentication是django rest framework为我们提供了最基本的认证类，正如源码流程一样，该类中其中定义的两个方法authenticate和authenticate_header(认证失败返回的响应头),使用时候重写该两个方法进行认证，正如示例：



```
class BaseAuthentication(object):
    """
    All authentication classes should extend BaseAuthentication.
    """

    def authenticate(self, request):
        """
        Authenticate the request and return a two-tuple of (user, token).
        """
        raise NotImplementedError(".authenticate() must be overridden.")

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        pass
```

其他认证类


```
rest_framework.authentication

BasicAuthentication  #基于浏览器进行认证
SessionAuthentication #基于django的session进行认证
RemoteUserAuthentication #基于django admin中的用户进行认证，这也是官网的示例
TokenAuthentication #基于drf内部的token认证
```


自定义认证类

继承BaseAuthentication，重写authenticate方法和authenticate_header(pass就可以)，authenticate()方法需要有三种情况(返回元祖、出现异常、返回none)。


认证配置


```
#全局认证
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES":['API.utils.auth.Authentication',]
}

#局部认证
authentication_classes = [BaseAuthentication,]

#是某个视图不进行认证
authentication_classes =[]
```



### 总结



### 参考资料
- https://www.zmrenwu.com/courses/django-class-based-views-source-code-analysis/materials/37/#as_view
- https://blog.csdn.net/qq_39980136/article/details/88846492
- https://www.cnblogs.com/wdliu/p/8747372.html