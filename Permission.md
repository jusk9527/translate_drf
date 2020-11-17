
> 作者：jusk
>
> 之前我们分析了认证的一些东西，下面我们还是分析下权限。权限在我们实现业务需求的时候分为**功能权限**和**数据权限**,我们根据业务需求进行代码书写。



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

#### [2.权限源码过程解析](#)



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






##### [2-4.self.initialize_request()](#)

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



**小结**
```markdown

新的Request他封装了

- 请求（HttpRequest）。原始请求实例

- 解析器类（列表/元组）。用于分析

- 请求内容。

- 身份验证类（列表/元组）。用于尝试的身份验证


这里我们由于是分析他的认证就不对他封装的其他进行说明，我们继续在dispath()上往下走
```


##### [2-5.执行initial()方法](#)

- self.initial(request, *args, **kwargs)


```python
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

**小结**
```markdown

这里他加入了检查权限
self.check_permissions(request),我们可以看到他权限检查中加了什么
```


##### [2-6.执行check_permissions()方法](#)

- self.check_permissions(request)


```python
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
**小结**
```markdown

for permission in self.get_permissions():
这里他去循环遍历self.get_permissions方法的结果。
```


##### [2-7.get_permissions()方法](#)

- self.get_permissions():


```python
def get_permissions(self):
    """
    Instantiates and returns the list of permissions that this view requires.
    """
    return [permission() for permission in self.permission_classes]
```

**小结**
```markdown

return [permission() for permission in self.permission_classes]

这里他将类权限类实例化和认证一样，循环遍历获得每个认证类的实例，
返回实例列表生成式，如果在**视图类中没有的写的话**，
就会去默认的setting配置中找

permission_classes = api_settings.DEFAULT_PERMISSION_CLASSES

我们继续在check_permissions里面往下走，看到了

if not permission.has_permission(request, self):
    self.permission_denied(
        request, message=getattr(permission, 'message', None)
    )

这里意思是如果实例permission的has_permission方法为空，就执行permission_denied方法
```



[2-8.self.permission_denied()](#)


```python
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


**小结**
```markdown
这里意思是请求不允许就抛异常，到这里其实就结束了
如果有这个权限认证就过，没有就抛出异常
```




#### [3.内置权限验证类](#)


```markdown
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


- 自定义权限流程
    - 继承BasePermission类(推荐)
    - 重写has_permission方法
    - has_permission方法返回True表示有权访问，False无权访问

.....等等

基本的权限类供我们一些基础需求,但是我们更多的是需要自己单独写权限。

下面我们看下使用方法,基本的单独写权限
```



##### [3-1使用方法](#)

- 内部类使用
```
##单一视图使用,为空代表不做权限验证
class MenuViewSet(ModelViewSet, TreeAPIView):
    permission_classes = [MyPremission,]
```



- 全局使用



```python
REST_FRAMEWORK = {
   #权限
    "DEFAULT_PERMISSION_CLASSES":['API.utils.permission.MyPremission'],
}
```




- 优先级


```
单一视图(内部类) > 全局配置（全局）
```



##### 内置权限类分析

###### BasePermission


- 默认实现**has_permission**, **has_object_permission**方法

```python
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

**小结**
```markdown
这里没什么可说的，基本认证类等于没写一样，全返回True
```


###### AllowAny


- 允许全部请求

```python
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


**小结**
```markdown
继承父类BasePermission,这里没什么可说的，允许全部权限
```


###### IsAuthenticated

- 只允许认证的人
```python
class IsAuthenticated(BasePermission):
    """
    Allows access only to authenticated users.
    """

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)
```
**小结**
```markdown
继承父类BasePermission,使用bool判断,意思是只允许认证过的人返回True,不然Flase
```

###### IsAdminUser


```python
class IsAdminUser(BasePermission):
    """
    Allows access only to admin users.
    """

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_staff)
```



**小结**
```markdown
继承父类BasePermission,使用bool判断,意思是表示认证且用户属性is_staff为True的人才可以登录，也就是表示后台管理员可以登录
```

###### IsAuthenticatedOrReadOnly


```python
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

**小结**
```markdown
继承父类BasePermission,使用bool判断,意思是 认证用户有权限，否则只能有读权限
```

###### [DjangoModelPermissions](https://nicksors.cc/2018/07/25/Python%E7%B3%BB%E5%88%97%E4%B9%8B%E3%80%8ADjango-DRF-%E6%9D%83%E9%99%90%E3%80%8B.html)

- django 与内置模块一起的请求权限，视图中包括增删改查。这些我们可以调配


```python
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

**小结**
```markdown
这里我们尅点击DjangoModelPermissions看详情使用
```

使用方法
settings
```python
REST_FRAMEWORK = {
    ······
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.DjangoModelPermissions',
    ),
}
```




```python
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

**小结**
```markdown
优点： 不用在每个视图里去写了，
缺点： 如果你一但写一个viewset没有queryset的话，将会出错，解决：使用permission_classes = (IsAuthenticated, )
写在你的viewset里，自己定义其他认证方式，覆盖全局的配置即可。
```

#### [自己动手写一个权限类实现效果](#)


- views.py


```python
class MenuViewSet(ModelViewSet, TreeAPIView):
    '''
    菜单管理：增删改查

    权限树

    list:
        获取菜单+id具体菜单
    create:
        添加一个菜单
    delete:
        删除一个菜单
    update:
        修改一个菜单
    '''

    perms_map = ({'*': 'admin'}, {'*': 'menu_all'}, {'get': 'menu_list'}, {'post': 'menu_create'}, {'put': 'menu_edit'},
                 {'delete': 'menu_delete'})
    queryset = Menu.objects.all()
    serializer_class = MenuSerializer
    pagination_class = CommonPagination
    filter_backends = (SearchFilter, OrderingFilter,)
    search_fields = ('name',)
    ordering_fields = ('sort',)
    # authentication_classes = (JSONWebTokenAuthentication, SessionAuthentication,)
    authentication_classes = (SessionAuthentication,)
    permission_classes = (RbacPermission,)
```
- custom.py

```python
class RbacPermission(BasePermission):
    '''
    自定义权限
    '''

    @classmethod
    def get_permission_from_role(self, request):
        try:
            perms = request.user.roles.values(
                'permissions__method',
            ).distinct()
            return [p['permissions__method'] for p in perms]
        except AttributeError:
            return None

    def has_permission(self, request, view):
        perms = self.get_permission_from_role(request)
        if perms:
            if 'admin' in perms:
                return True
            elif not hasattr(view, 'perms_map'):
                return True
            else:
                perms_map = view.perms_map
                _method = request._request.method.lower()
                for i in perms_map:
                    for method, alias in i.items():
                        if (_method == method or method == '*') and alias in perms:
                            return True
```


```markdown
这个认证类查看视图类定义的功能权限是否有与数据库中的权限，比如删除，导出等，这些都是功能权限。如果有就返回True,没有就Flase。实现完功能权限就ok了吗。在一个小型平台上面数据还没做到数据的权限不同。
```

```markdown
上面仅仅实现了功能权限的功能，并没有实现数据权限功能，比如公司有个平台实现多学校缴费的功能,
那么每个学校的数据互相是不能看的，那么这个时候数据权限就体现出重要性了。可以怎么实现呢。

https://segmentfault.com/a/1190000004400312
```


权限本质

```markdown
权限本质就是
```

