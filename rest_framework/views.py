"""
Provides an APIView class that is the base of all views in REST framework.

提供一个APIView类，它是TEST框架中所有视图的基础
"""
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.db import connection, models, transaction
from django.http import Http404
from django.http.response import HttpResponseBase
from django.utils.cache import cc_delim_re, patch_vary_headers
from django.utils.encoding import smart_text
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View

from rest_framework import exceptions, status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.schemas import DefaultSchema
from rest_framework.settings import api_settings
from rest_framework.utils import formatting


def get_view_name(view):
    """
    Given a view instance, return a textual name to represent the view.
    This name is used in the browsable API, and in OPTIONS responses.

    This function is the default for the `VIEW_NAME_FUNCTION` setting.

    给定视图实例，返回表示视图的文本名称

    此名称用于可浏览API和选项响应中
    此函数是“查看名称”函数设置的默认值
    """
    # Name may be set by some Views, such as a ViewSet.

    # 名称可以由某些视图（如视图集）设置
    name = getattr(view, 'name', None)
    if name is not None:
        return name

    name = view.__class__.__name__
    name = formatting.remove_trailing_string(name, 'View')
    name = formatting.remove_trailing_string(name, 'ViewSet')
    name = formatting.camelcase_to_spaces(name)

    # Suffix may be set by some Views, such as a ViewSet.

    # 后缀可以由某些视图设置，例如视图集
    suffix = getattr(view, 'suffix', None)
    if suffix:
        name += ' ' + suffix

    return name


def get_view_description(view, html=False):
    """
    Given a view instance, return a textual description to represent the view.
    This name is used in the browsable API, and in OPTIONS responses.

    This function is the default for the `VIEW_DESCRIPTION_FUNCTION` setting.


    给定一个视图实例，返回一个文本描述来表示该视图，此名称用于可浏览API的选项响应中
    """
    # Description may be set by some Views, such as a ViewSet.

    # 描述可以由某些视图（如视图集）设置
    description = getattr(view, 'description', None)
    if description is None:
        description = view.__class__.__doc__ or ''

    description = formatting.dedent(smart_text(description))
    if html:
        return formatting.markup_description(description)
    return description


def set_rollback():
    atomic_requests = connection.settings_dict.get('ATOMIC_REQUESTS', False)
    if atomic_requests and connection.in_atomic_block:
        transaction.set_rollback(True)


def exception_handler(exc, context):
    """
    Returns the response that should be used for any given exception.

    By default we handle the REST framework `APIException`, and also
    Django's built-in `Http404` and `PermissionDenied` exceptions.

    Any unhandled exceptions may return `None`, which will cause a 500 error
    to be raised.

    返回应用于任何给定异常的响应

    默认情况下，我们处理REST 框架APIException，并且Django的内置Http404和PermissionDenied异常

    任何未处理的异常都可能返回None,这将导致500个错误被抛出

    """
    if isinstance(exc, Http404):
        exc = exceptions.NotFound()
    elif isinstance(exc, PermissionDenied):
        exc = exceptions.PermissionDenied()

    if isinstance(exc, exceptions.APIException):
        headers = {}
        if getattr(exc, 'auth_header', None):
            headers['WWW-Authenticate'] = exc.auth_header
        if getattr(exc, 'wait', None):
            headers['Retry-After'] = '%d' % exc.wait

        if isinstance(exc.detail, (list, dict)):
            data = exc.detail
        else:
            data = {'detail': exc.detail}

        set_rollback()
        return Response(data, status=exc.status_code, headers=headers)

    return None


class APIView(View):

    # The following policies may be set at either globally, or per-view.
    # 以下策略可以设置为全局策略或按视图策略

    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES
    # 默认解析器
    parser_classes = api_settings.DEFAULT_PARSER_CLASSES
    # 默认认证
    authentication_classes = api_settings.DEFAULT_AUTHENTICATION_CLASSES
    # 默认限速
    throttle_classes = api_settings.DEFAULT_THROTTLE_CLASSES
    # 默认权限
    permission_classes = api_settings.DEFAULT_PERMISSION_CLASSES
    content_negotiation_class = api_settings.DEFAULT_CONTENT_NEGOTIATION_CLASS
    metadata_class = api_settings.DEFAULT_METADATA_CLASS
    versioning_class = api_settings.DEFAULT_VERSIONING_CLASS

    # Allow dependency injection of other settings to make testing easier.
    settings = api_settings

    schema = DefaultSchema()

    @classmethod
    def as_view(cls, **initkwargs):
        """
        Store the original class on the view function.

        This allows us to discover information about the view when we do URL
        reverse lookups.  Used for breadcrumb generation.

        把原始类存储在view函数上，这允许我们在执行url时发现有关视图的信息，反向查找，用于面包屑的生成
        """
        # getattr 取得cls类中queryset的值
        # 检查类中定义的queryset是否是这个models.query.QuerySet类型，必行抛异常
        if isinstance(getattr(cls, 'queryset', None), models.query.QuerySet):
            def force_evaluation():
                raise RuntimeError(
                    'Do not evaluate the `.queryset` attribute directly, '
                    'as the result will be cached and reused between requests. '
                    'Use `.all()` or call `.get_queryset()` instead.'

                    # 不要直接计算queryset属性，结果将被缓存并在请求之间中庸，使用all() 或get\queryset()
                )
            cls.queryset._fetch_all = force_evaluation

        # 执行父类的as_view方法
        view = super().as_view(**initkwargs)
        view.cls = cls
        view.initkwargs = initkwargs

        # Note: session based authentication is explicitly CSRF validated,
        # all other authentication is CSRF exempt.

        # 返回view，由于是前后端分离就取出csrf认证
        return csrf_exempt(view)

    # 允许的请求
    @property
    def allowed_methods(self):
        """
        Wrap Django's private `_allowed_methods` interface in a public property.

        在公共属性中包装Django的私有 允许的 方法接口
        """
        return self._allowed_methods()

    # 默认请求头
    @property
    def default_response_headers(self):
        headers = {
            'Allow': ', '.join(self.allowed_methods),
        }
        if len(self.renderer_classes) > 1:
            headers['Vary'] = 'Accept'
        return headers

    # 不允许请求
    def http_method_not_allowed(self, request, *args, **kwargs):
        """
        If `request.method` does not correspond to a handler method,
        determine what kind of exception to raise.

        如果 request.method 与处理程序方法不对应，确定要引发的异常类型
        """
        raise exceptions.MethodNotAllowed(request.method)


    # check_permissions方法过来的，确定引发哪种异常
    def permission_denied(self, request, message=None):
        """
        If request is not permitted, determine what kind of exception to raise.

        如果不允许请求，请确定引发哪种异常
        """
        # 如果不允许请求，请确定引发哪种异常。
        if request.authenticators and not request.successful_authenticator:
            raise exceptions.NotAuthenticated()
        # 如果定义了message属性，则抛出属性值
        raise exceptions.PermissionDenied(detail=message)


    def throttled(self, request, wait):
        """
        If request is throttled, determine what kind of exception to raise.

        # 如果请求被限制，请确定引发哪种异常。
        """
        raise exceptions.Throttled(wait)


    def get_authenticate_header(self, request):
        """
        If a request is unauthenticated, determine the WWW-Authenticate
        header to use for 401 responses, if any.

        # 如果请求未经身份验证，请确定WWW身份验证
        # 用于401响应的头（如果有）。
        """
        authenticators = self.get_authenticators()
        if authenticators:
            return authenticators[0].authenticate_header(request)

    def get_parser_context(self, http_request):
        """
        Returns a dict that is passed through to Parser.parse(),
        as the `parser_context` keyword argument.

        返回传递给Parser.parse(),作为“parser\u context”关键字参数。
        """
        # Note: Additionally `request` and `encoding` will also be added
        #       to the context by the Request object.
        return {
            'view': self,
            'args': getattr(self, 'args', ()),
            'kwargs': getattr(self, 'kwargs', {})
        }

    def get_renderer_context(self):
        """
        Returns a dict that is passed through to Renderer.render(),
        as the `renderer_context` keyword argument.

        返回传递给Renderer.render()的dict
        作为renderer_context 关键字参数
        """
        # Note: Additionally 'response' will also be added to the context,
        #       by the Response object.
        return {
            'view': self,
            'args': getattr(self, 'args', ()),
            'kwargs': getattr(self, 'kwargs', {}),
            'request': getattr(self, 'request', None)
        }

    def get_exception_handler_context(self):
        """
        Returns a dict that is passed through to EXCEPTION_HANDLER,
        as the `context` argument.

        返回传递给异常处理程序的dict,作为context参数
        """
        return {
            'view': self,
            'args': getattr(self, 'args', ()),
            'kwargs': getattr(self, 'kwargs', {}),
            'request': getattr(self, 'request', None)
        }

    def get_view_name(self):
        """
        Return the view name, as used in OPTIONS responses and in the
        browsable API.

        返回视图名称，如选项响应和可浏览的API
        """
        func = self.settings.VIEW_NAME_FUNCTION
        return func(self)

    def get_view_description(self, html=False):
        """
        Return some descriptive text for the view, as used in OPTIONS responses
        and in the browsable API.


        返回视图的一些描述性文本，如选项响应中使用可浏览的API
        """
        func = self.settings.VIEW_DESCRIPTION_FUNCTION
        return func(self, html)

    # API policy instantiation methods

    # 确定请求是否包含“.json”样式的格式后缀
    def get_format_suffix(self, **kwargs):
        """
        Determine if the request includes a '.json' style format suffix

        确定请求是否包含.json样式的格式后缀
        """
        if self.settings.FORMAT_SUFFIX_KWARG:
            return kwargs.get(self.settings.FORMAT_SUFFIX_KWARG)

    def get_renderers(self):
        """
        Instantiates and returns the list of renderers that this view can use.

        实例化并返回此视图可以使用的渲染器列表
        """
        return [renderer() for renderer in self.renderer_classes]

    def get_parsers(self):
        """
        Instantiates and returns the list of parsers that this view can use.

        实例化并返回此视图可以使用的分析器列表
        """
        return [parser() for parser in self.parser_classes]


    def get_authenticators(self):
        """
        Instantiates and returns the list of authenticators that this view can use.

        利用列表生成式返回每个认证类的实例
        """
        return [auth() for auth in self.authentication_classes]


    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.

        利用列表生成式返回每个权限类的实例
        """
        return [permission() for permission in self.permission_classes]


    def get_throttles(self):
        """
        Instantiates and returns the list of throttles that this view uses.

        利用列表生成式返回每个限速类的实例
        """
        return [throttle() for throttle in self.throttle_classes]

    def get_content_negotiator(self):
        """
        Instantiate and return the content negotiation class to use.

        实例化并返回要使用的列荣协商类
        """
        if not getattr(self, '_negotiator', None):
            self._negotiator = self.content_negotiation_class()
        return self._negotiator

    def get_exception_handler(self):
        """
        Returns the exception handler that this view uses.

        返回此视图使用的异常处理程序
        """
        return self.settings.EXCEPTION_HANDLER

    # API policy implementation methods

    def perform_content_negotiation(self, request, force=False):
        """
        Determine which renderer and media type to use render the response.

        确定要使用哪个呈现器和媒体类型来呈现响应
        """
        renderers = self.get_renderers()
        conneg = self.get_content_negotiator()

        try:
            return conneg.select_renderer(request, renderers, self.format_kwarg)
        except Exception:
            if force:
                return (renderers[0], renderers[0].media_type)
            raise


    # self.perform_authentication(request)调用来的，执行request的user
    def perform_authentication(self, request):
        """
        Perform authentication on the incoming request.

        Note that if you override this and simply 'pass', then authentication
        will instead be performed lazily, the first time either
        `request.user` or `request.auth` is accessed.


        对传入请求执行身份验证
        请注意，如果覆盖此项并简单地通过，则身份验证
        而是第一次懒散地表演
        以访问request.user或request.auth
        """
        request.user


    # 检查是否有权限请求，如果不允许就引发适当的异常
    def check_permissions(self, request):
        """
        Check if the request should be permitted.
        Raises an appropriate exception if the request is not permitted.

        检查这个请求是否应该别允许，如果这个请求不允许就抛出对应异常
        """

        # 循环对象get_permissions方法的结果，如果自己没有，则去父类寻找
        for permission in self.get_permissions():

            # 判断每个对象中的has_permission方法返回值（其实就是权限判断），这就是为什么我们需要对权限类定义has_permission方法
            if not permission.has_permission(request, self):
                # 返回无权限信息，也就是我们定义的message共有属性

                self.permission_denied(
                    request, message=getattr(permission, 'message', None)
                )

    def check_object_permissions(self, request, obj):
        """
        Check if the request should be permitted for a given object.
        Raises an appropriate exception if the request is not permitted.

        检查是否允许对给定对象执行请求，如果不允许，则引发适当的异常
        """
        for permission in self.get_permissions():
            if not permission.has_object_permission(request, self, obj):
                self.permission_denied(
                    request, message=getattr(permission, 'message', None)
                )

    def check_throttles(self, request):
        """
        Check if request should be throttled.
        Raises an appropriate exception if the request is throttled.

        检查是否应该限制请求，如果请求被限制，则引发适当的异常
        """
        throttle_durations = []
        for throttle in self.get_throttles():
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

    def determine_version(self, request, *args, **kwargs):
        """
        If versioning is being used, then determine any API version for the
        incoming request. Returns a two-tuple of (version, versioning_scheme)

        如果正在使用版本控制，则确定传入请求，返回两元组(version, versioning_scheme)
        """
        if self.versioning_class is None:
            return (None, None)
        scheme = self.versioning_class()
        return (scheme.determine_version(request, *args, **kwargs), scheme)

    # Dispatch methods

    # 将旧的request请求封装成新的Request中,添加新功能
    def initialize_request(self, request, *args, **kwargs):
        """
        Returns the initial request object.

        返回初始请求对象
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

    # 运行在调用方法处理程序之前需要发生的任何事情。
    def initial(self, request, *args, **kwargs):
        """
        Runs anything that needs to occur prior to calling the method handler.

        运行在调用方法处理程序之前需要发生的任何事情
        """
        self.format_kwarg = self.get_format_suffix(**kwargs)

        # Perform content negotiation and store the accepted info on the request
        # 执行内容协商并在请求中储存接受的信息
        neg = self.perform_content_negotiation(request)
        request.accepted_renderer, request.accepted_media_type = neg

        # Determine the API version, if versioning is in use.
        # 如果正在使用版本控制，请确定API版本

        version, scheme = self.determine_version(request, *args, **kwargs)
        request.version, request.versioning_scheme = version, scheme

        # Ensure that the incoming request is permitted
        # 确保允许传入请求

        # 身份认证
        self.perform_authentication(request)
        # 检查权限
        self.check_permissions(request)
        # 流量限速
        self.check_throttles(request)



    def finalize_response(self, request, response, *args, **kwargs):
        """
        Returns the final response object.

        返回最终响应对象
        """
        # Make the error obvious if a proper response is not returned
        assert isinstance(response, HttpResponseBase), (
            'Expected a `Response`, `HttpResponse` or `HttpStreamingResponse` '
            'to be returned from the view, but received a `%s`'
            % type(response)
        )

        if isinstance(response, Response):
            if not getattr(request, 'accepted_renderer', None):
                neg = self.perform_content_negotiation(request, force=True)
                request.accepted_renderer, request.accepted_media_type = neg

            response.accepted_renderer = request.accepted_renderer
            response.accepted_media_type = request.accepted_media_type
            response.renderer_context = self.get_renderer_context()

        # Add new vary headers to the response instead of overwriting.

        # 向响应添加新的vary头并不是覆盖
        vary_headers = self.headers.pop('Vary', None)
        if vary_headers is not None:
            patch_vary_headers(response, cc_delim_re.split(vary_headers))

        for key, value in self.headers.items():
            response[key] = value

        return response



    def handle_exception(self, exc):
        """
        Handle any exception that occurs, by returning an appropriate response,
        or re-raising the error.

        通过适当的响应来处理发生的任何异常、或者重新提出错误
        """
        if isinstance(exc, (exceptions.NotAuthenticated,
                            exceptions.AuthenticationFailed)):
            # WWW-Authenticate header for 401 responses, else coerce to 403
            # WWW Authenticate报头用于401响应，否则强制为403
            auth_header = self.get_authenticate_header(self.request)

            if auth_header:
                exc.auth_header = auth_header
            else:
                exc.status_code = status.HTTP_403_FORBIDDEN

        exception_handler = self.get_exception_handler()

        context = self.get_exception_handler_context()
        response = exception_handler(exc, context)

        if response is None:
            self.raise_uncaught_exception(exc)

        response.exception = True
        return response

    def raise_uncaught_exception(self, exc):
        if settings.DEBUG:
            request = self.request
            renderer_format = getattr(request.accepted_renderer, 'format')
            use_plaintext_traceback = renderer_format not in ('html', 'api', 'admin')
            request.force_plaintext_errors(use_plaintext_traceback)
        raise exc

    # Note: Views are made CSRF exempt from within `as_view` as to prevent
    # accidental removal of this exemption in cases where `dispatch` needs to
    # be overridden.

    # 驶入在as-view内被设置为CSRF豁免，以防止


    # 这是最重要地方，封装新的request，封装新的一些方法等
    def dispatch(self, request, *args, **kwargs):
        """
        `.dispatch()` is pretty much the same as Django's regular dispatch,
        but with extra hooks for startup, finalize, and exception handling.

        dispathc() 与Django 的常规调度几乎相同，但是有额外的狗子用于启动，完成和异常处理
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
            # 查看是否请求在http_method_names
            if request.method.lower() in self.http_method_names:

                # 得到GET等请求最后获得的值，没有的话获取不允许请求的值
                handler = getattr(self, request.method.lower(),
                                  self.http_method_not_allowed)
            else:
                handler = self.http_method_not_allowed


            response = handler(request, *args, **kwargs)

        except Exception as exc:
            response = self.handle_exception(exc)

        self.response = self.finalize_response(request, response, *args, **kwargs)

        # 返回请求结果
        return self.response

    def options(self, request, *args, **kwargs):
        """
        Handler method for HTTP 'OPTIONS' request.

        http options 请求的处理程序方法
        """
        if self.metadata_class is None:
            return self.http_method_not_allowed(request, *args, **kwargs)
        data = self.metadata_class().determine_metadata(request, self)
        return Response(data, status=status.HTTP_200_OK)
