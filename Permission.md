
> 作者：jusk
>
> 之前我们分析了认证的一些东西，下面我们还是分析下权限。由于代码和上篇认证有相同之处，我们就把主要的东西分析下



#### 验证流程

```
graph LR
dispatch-->initialize_request
initialize_request-->initial
initial-->check_permissions
check_permissions-->get_permissions
get_permissions-->判断
判断-->has_permission=true
判断-->has_permission=flase
has_permission=flase-->引发异常
```

![](https://raw.githubusercontent.com/jusk9527/images/master/data/20191127144907.png)

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


#### 执行check_permissions()方法

- self.check_permissions(request)


```
    def check_permissions(self, request):
        """
        Check if the request should be permitted.
        Raises an appropriate exception if the request is not permitted.
        """

        # 1.循环对象get_permissions方法的结果，如果自己没有，则去父类寻找
        for permission in self.get_permissions():

            # 2.判断每个对象中的has_permission方法返回值（其实就是权限判断），这就是为什么我们需要对权限类定义has_permission方法
            if not permission.has_permission(request, self):
                # 3. 返回无权限信息，也就是我们定义的message共有属性
                self.permission_denied(
                    request, message=getattr(permission, 'message', None)
                )
```



#### 执行get_permissions()方法

- self.get_permissions():


```
    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.
        """
        return [permission() for permission in self.permission_classes]
```

和认证一样，循环遍历获得每个认证类的实例


1. 去默认的self.permission_classes找

```
permission_classes = api_settings.DEFAULT_PERMISSION_CLASSES
```
2. 类中设置了就去自己设置的这个里面找

继续往下走
- self.permission_denied()


```
    def permission_denied(self, request, message=None):
        """
        If request is not permitted, determine what kind of exception to raise.
        """
        # 如果不允许请求，请确定引发哪种异常。
        if request.authenticators and not request.successful_authenticator:
            raise exceptions.NotAuthenticated()
        # 如果定义了message属性，则抛出属性值
        raise exceptions.PermissionDenied(detail=message)
```

到这里其实就结束了，如果有这个权限认证就过，没有就抛出异常


#### 内置权限验证类


```
rest_framework.permissions

##基本权限验证
class BasePermission(object)

##允许所有
class AllowAny(BasePermission)

##基于django的认证权限，官方示例
class IsAuthenticated(BasePermission):

##基于django admin权限控制
class IsAdminUser(BasePermission)

##也是基于django admin
class IsAuthenticatedOrReadOnly(BasePermission)
.....
```



#### 使用方法

- 自定义权限流程
    - 继承BasePermission类(推荐)
    - 重写has_permission方法
    - has_permission方法返回True表示有权访问，False无权访问


#### 配置
- 全局使用


```
REST_FRAMEWORK = {
   #权限
    "DEFAULT_PERMISSION_CLASSES":['API.utils.permission.MyPremission'],
}
```


- 内部类使用


```
##单一视图使用,为空代表不做权限验证
permission_classes = [MyPremission,]
```

- 优先级

```
单一视图>全局配置
```


##### 内置权限类分析

###### BasePermission


- 默认实现**has_permission**, **has_object_permission**方法
```
class BasePermission(metaclass=BasePermissionMetaclass):
    """
    A base class from which all permission classes should inherit.
    """

    def has_permission(self, request, view):
        """
        Return `True` if permission is granted, `False` otherwise.
        """
        return True

    def has_object_permission(self, request, view, obj):
        """
        Return `True` if permission is granted, `False` otherwise.
        """
        return True
```


###### AllowAny

- 允许全部请求

```
class AllowAny(BasePermission):
    """
    Allow any access.
    This isn't strictly required, since you could use an empty
    permission_classes list, but it's useful because it makes the intention
    more explicit.
    """

    def has_permission(self, request, view):
        return True
```


###### IsAuthenticated

- 只允许认证的人
```
class IsAuthenticated(BasePermission):
    """
    Allows access only to authenticated users.
    """

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)
```


###### IsAdminUser

- 超级管理员

```
class IsAdminUser(BasePermission):
    """
    Allows access only to admin users.
    """

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_staff)
```

###### IsAuthenticatedOrReadOnly

- 认证用户有权限，否则只能有读权限
```
class IsAuthenticatedOrReadOnly(BasePermission):
    """
    The request is authenticated as a user, or is a read-only request.
    """

    def has_permission(self, request, view):
        return bool(
            request.method in SAFE_METHODS or
            request.user and
            request.user.is_authenticated
        )
```

###### [DjangoModelPermissions](https://nicksors.cc/2018/07/25/Python%E7%B3%BB%E5%88%97%E4%B9%8B%E3%80%8ADjango-DRF-%E6%9D%83%E9%99%90%E3%80%8B.html)

- django 与内置模块一起的请求权限，视图中包括增删改查。这些我们可以调配


```
perms_map = {
    'GET': [],
    'OPTIONS': [],
    'HEAD': [],
    'POST': ['%(app_label)s.add_%(model_name)s'],
    'PUT': ['%(app_label)s.change_%(model_name)s'],
    'PATCH': ['%(app_label)s.change_%(model_name)s'],
    'DELETE': ['%(app_label)s.delete_%(model_name)s'],
}
```


- 使用方法

    - settings
```
REST_FRAMEWORK = {
    ······
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.DjangoModelPermissions',
    ),
}
```
- 优点： 不用在每个视图里去写了，
- 缺点： 如果你一但写一个viewset没有queryset的话，将会出错，解决：使用permission_classes = (IsAuthenticated, ) 写在你的viewset里，自己定义其他认证方式，覆盖全局的配置即可。

```
class DjangoModelPermissions(BasePermission):
    """
    The request is authenticated using `django.contrib.auth` permissions.
    See: https://docs.djangoproject.com/en/dev/topics/auth/#permissions

    It ensures that the user is authenticated, and has the appropriate
    `add`/`change`/`delete` permissions on the model.

    This permission can only be applied against view classes that
    provide a `.queryset` attribute.
    """

    # Map methods into required permission codes.
    # Override this if you need to also provide 'view' permissions,
    # or if you want to provide custom permission codes.
    perms_map = {
        'GET': [],
        'OPTIONS': [],
        'HEAD': [],
        'POST': ['%(app_label)s.add_%(model_name)s'],
        'PUT': ['%(app_label)s.change_%(model_name)s'],
        'PATCH': ['%(app_label)s.change_%(model_name)s'],
        'DELETE': ['%(app_label)s.delete_%(model_name)s'],
    }

    authenticated_users_only = True

    def get_required_permissions(self, method, model_cls):
        """
        Given a model and an HTTP method, return the list of permission
        codes that the user is required to have.
        """
        kwargs = {
            'app_label': model_cls._meta.app_label,
            'model_name': model_cls._meta.model_name
        }

        if method not in self.perms_map:
            raise exceptions.MethodNotAllowed(method)

        return [perm % kwargs for perm in self.perms_map[method]]

    def _queryset(self, view):
        assert hasattr(view, 'get_queryset') \
            or getattr(view, 'queryset', None) is not None, (
            'Cannot apply {} on a view that does not set '
            '`.queryset` or have a `.get_queryset()` method.'
        ).format(self.__class__.__name__)

        if hasattr(view, 'get_queryset'):
            queryset = view.get_queryset()
            assert queryset is not None, (
                '{}.get_queryset() returned None'.format(view.__class__.__name__)
            )
            return queryset
        return view.queryset

    def has_permission(self, request, view):
        # Workaround to ensure DjangoModelPermissions are not applied
        # to the root view when using DefaultRouter.
        if getattr(view, '_ignore_model_permissions', False):
            return True

        if not request.user or (
           not request.user.is_authenticated and self.authenticated_users_only):
            return False

        queryset = self._queryset(view)
        perms = self.get_required_permissions(request.method, queryset.model)

        return request.user.has_perms(perms)
```


