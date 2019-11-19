### 权限

之前我们分析了认证的一些东西，下面我们还是分析下权限。由于代码和上篇认证有相同之处，我们就把主要的东西分析下

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
- check_permissions()
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
- check_permissions()
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


### 总结

#### 使用方法

- 自定义权限流程
1. 继承BasePermission类(推荐)
2. 重写has_permission方法
3. has_permission方法返回True表示有权访问，False无权访问


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


#### 验证流程


```
graph LR
dispatch-->initialize_request
initialize_request-->check_permissions
check_permissions-->get_permissions
get_permissions-->判断
判断-->has_permission=true
判断-->has_permission=flase
has_permission=flase-->引发异常
```
![](https://raw.githubusercontent.com/jusk9527/images/master/data/20191119104630.png)