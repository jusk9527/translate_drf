
### 流程图

```
graph LR
dispatch-->initialize_request
initialize_request-->initial
initial-->determine_version
determine_version-->判断
判断-->versioning_clas=None
判断-->versioning_clas
versioning_clas-->版本-对象
版本-对象-->request.version-request.versioning_scheme
```

![](https://raw.githubusercontent.com/jusk9527/images/master/data/20191127145204.gif)


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

#### determine_version()

- version, scheme = self.determine_version(request, *args, **kwargs)


```
def determine_version(self, request, *args, **kwargs):
    """
    If versioning is being used, then determine any API version for the
    incoming request. Returns a two-tuple of (version, versioning_scheme)

    如果正在使用版本控制，则确定传入请求，返回两元组(version, versioning_scheme)
    """

    # 先判断版本类是否存在self.verisoning_class 是否存在，不存在返回tuple,(none,none)
    if self.versioning_class is None:
        return (None, None)

    # 存在返回版本类对象
    scheme = self.versioning_class()

    # 版本类存在，最后返回版本类对象的determine_version方法结果(也就是返回的版本号)，和类对象，这也就是每个版本类必须
    # 要有的方法，用来获取版本
    return (scheme.determine_version(request, *args, **kwargs), scheme)
```

- 返回版本和类对象赋值给


```
request.version, request.versioning_scheme = version, scheme
```


### 版本控制类


#### 基类BaseVersioning
```

class BaseVersioning:

    # 默认版本配置
    default_version = api_settings.DEFAULT_VERSION
    # 允许版本配置
    allowed_versions = api_settings.ALLOWED_VERSIONS
    # 版本key配置
    version_param = api_settings.VERSION_PARAM

    def determine_version(self, request, *args, **kwargs):
        msg = '{cls}.determine_version() must be implemented.'
        raise NotImplementedError(msg.format(
            cls=self.__class__.__name__
        ))

    def reverse(self, viewname, args=None, kwargs=None, request=None, format=None, **extra):
        return _reverse(viewname, args, kwargs, request, format, **extra)

    def is_allowed_version(self, version):
        if not self.allowed_versions:
            return True
        return ((version is not None and version == self.default_version) or
                (version in self.allowed_versions))
```


#### QueryParameterVersioning

- 获取版本看是否能通过
- 使用实例
- setting


```
REST_FRAMEWORK = {
    # 'DEFAULT_PERMISSION_CLASSES': (
    #     'rest_framework.permissions.IsAuthenticated',
    # ),

    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_jwt.authentication.JSONWebTokenAuthentication',
        'rest_framework.authentication.BasicAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ),
    #限速设置
    'DEFAULT_THROTTLE_CLASSES': (
            'rest_framework.throttling.AnonRateThrottle',   #未登陆用户
            'rest_framework.throttling.UserRateThrottle'    #登陆用户
        ),

    "DEFAULT_VERSIONING_CLASS": "rest_framework.versioning.URLPathVersioning",  # 类的路径
    "DEFAULT_VERSION": 'v1',  # 默认的版本
    "ALLOWED_VERSIONS": ['v1', 'v2'],  # 允许的版本
    #  "VERSION_PARAM":'version'             #使用QueryParameterVersioning时候进行的配置，get请求时候传递的参数的key


    # 'DEFAULT_THROTTLE_RATES': {
    #     'anon': '2/minute',                      #每分钟可以请求两次
    #     'user': '1000/minute'                    #每分钟可以请求五次
    # }
}
```

- url
```
urlpatterns = [


    path(r'auth/v1/info/', ser_user.UserInfoView.as_view(), name='user_info'),

]
```
- view


```
class UserInfoView(APIView):
    '''
    获取当前用户信息和权限
    '''

    versioning_class = QueryParameterVersioning  # 添加版本

    def get(self, request):
        """
        get:
        发送信息到指定人员邮箱
        参数列表：

            id：用户id
            username：用户名
            avatar：头像接口
            email：邮件
            is_active：是否激活
            createTime：创建时间
            position: 职位
            roles：角色

        """
        print("dd"+str(request.version))
        url = request.versioning_scheme.reverse(viewname='user_info', request=request)
        print(url)
        if request.user.id is not None:
            perms = self.get_permission_from_role(request)
            org = self.get_department_from_organization(request)

            data = {
                'id': request.user.id,
                'username': request.user.username,
                'email': request.user.email,
                'is_active': request.user.is_active,
                'createTime':request.user.date_joined,
                'department':org,
                'position': request.user.position,
                'roles': perms,
            }
            return XopsResponse(data, status=OK)
        else:
            return XopsResponse('请登录后访问!', status=FORBIDDEN)
```


```
class QueryParameterVersioning(BaseVersioning):
    """
    GET /something/?version=0.1 HTTP/1.1
    Host: example.com
    Accept: application/json
    """
    # 当setting.py配置了允许的版本时候，不匹配版本返回的错误信息，可以自己定义
    invalid_version_message = _('Invalid version in query parameter.')

    # 获取版本方法
    def determine_version(self, request, *args, **kwargs):

        # request.query_params方法获取(本质是request.MATE.get), default_version默认是version，是在settings中配置的
        version = request.query_params.get(self.version_param, self.default_version)

        # 不允许的版本抛出异常
        if not self.is_allowed_version(version):
            raise exceptions.NotFound(self.invalid_version_message)

        # 无异常则返回版本号
        return version

    # url 反解析，可以通过该方法生成请求的url
    def reverse(self, viewname, args=None, kwargs=None, request=None, format=None, **extra):
        url = super().reverse(
            viewname, args, kwargs, request, format, **extra
        )
        if request.version is not None:
            return replace_query_param(url, self.version_param, request.version)
        return url

```

- 发送请求

![](https://raw.githubusercontent.com/jusk9527/images/master/data/20191126173219.png)

- 结果

```
{"detail":"Invalid version in query parameter."}
```

- 改变发送version的版本号v1

![](https://raw.githubusercontent.com/jusk9527/images/master/data/20191126173930.png)

#### URLPathVersioning

- url
```
class URLPathVersioning(BaseVersioning):
    """
    To the client this is the same style as `NamespaceVersioning`.
    The difference is in the backend - this implementation uses
    Django's URL keyword arguments to determine the version.

    An example URL conf for two views that accept two different versions.

    urlpatterns = [
        url(r'^(?P<version>[v1|v2]+)/users/$', users_list, name='users-list'),
        url(r'^(?P<version>[v1|v2]+)/users/(?P<pk>[0-9]+)/$', users_detail, name='users-detail')
    ]

    GET /1.0/something/ HTTP/1.1
    Host: example.com
    Accept: application/json
    """
    # 不允许的版本信息，可定制
    invalid_version_message = _('Invalid version in URL path.')

    # 同样实现determine_version方法获取版本
    def determine_version(self, request, *args, **kwargs):
        # 由于传递的版本url的正则中，所以从kwargs中获取，self.version_param默认version
        version = kwargs.get(self.version_param, self.default_version)
        if version is None:
            version = self.default_version

        if not self.is_allowed_version(version):
            # 没获取到，抛出异常
            raise exceptions.NotFound(self.invalid_version_message)
        # 正常获取，返回版本号
        return version

    def reverse(self, viewname, args=None, kwargs=None, request=None, format=None, **extra):
        if request.version is not None:
            kwargs = {} if (kwargs is None) else kwargs
            kwargs[self.version_param] = request.version

        return super().reverse(
            viewname, args, kwargs, request, format, **extra
        )
```


#### 使用说明

##### 举例 URLPathVersioning 的使用说明

1. 配置url,name取别名


```
urlpatterns = [

    url(r'^api/v1/auth', views.AuthView.as_view()),
    url(r'^api/v1/order', views.OrderView.as_view()),
    url(r'^api/(?P<version>[v1|v2]+)/user', views.UserView.as_view(),name="user_view"),
]
```
2. 利用reverse方法反向生成请求的url,UserView视图。


```
class UserView(APIView):
    '''查看用户信息'''

    from rest_framework.versioning import URLPathVersioning

    versioning_class =URLPathVersioning
    def get(self,request,*args,**kwargs):
        print(request.version)

        url = request.versioning_scheme.reverse(viewname='user_view', request=request)
        #versioning_scheme已经在源码中分析过了，就是版本类实例化的对象
        print(url)
        res={"name":"wd","age":22}
        return JsonResponse(res,safe=True)
```
3. 结果

![](https://images2018.cnblogs.com/blog/1075473/201806/1075473-20180601010550448-751003248.png)


##### 全局配置

```
REST_FRAMEWORK = {
     "DEFAULT_VERSIONING_CLASS":"rest_framework.versioning.URLPathVersioning",  #类的路径
    "DEFAULT_VERSION":'v1',               #默认的版本
    "ALLOWED_VERSIONS":['v1','v2'],       #允许的版本
   #  "VERSION_PARAM":'version'             #使用QueryParameterVersioning时候进行的配置，get请求时候传递的参数的key  
}

#单一视图
versioning_class =URLPathVersioning
```
