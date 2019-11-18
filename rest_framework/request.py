"""
The Request class is used as a wrapper around the standard request object.

The wrapped request then offers a richer API, in particular :

    - content automatically parsed according to `Content-Type` header,
      and available as `request.data`
    - full support of PUT method, including support for file uploads
    - form overloading of HTTP method, content type and content

请求类用作标准请求对象的包装器

然后，包装的请求提供了更丰富的API,特别是：

    - 根据content Type 标题自动分析内容
    - 并作为request.data提供
    - 完全支持PUT方法，包括支持文件上传

"""
import io
import sys
from contextlib import contextmanager

from django.conf import settings
from django.http import HttpRequest, QueryDict
from django.http.multipartparser import parse_header
from django.http.request import RawPostDataException
from django.utils.datastructures import MultiValueDict

from rest_framework import HTTP_HEADER_ENCODING, exceptions
from rest_framework.settings import api_settings


def is_form_media_type(media_type):
    """
    Return True if the media type is a valid form media type.

    吐过媒体类型是有效的表单媒体类型，则返回True
    """
    base_media_type, params = parse_header(media_type.encode(HTTP_HEADER_ENCODING))
    return (base_media_type == 'application/x-www-form-urlencoded' or
            base_media_type == 'multipart/form-data')


class override_method:
    """
    A context manager that temporarily overrides the method on a request,
    additionally setting the `view.request` attribute.

    Usage:

        with override_method(view, request, 'POST') as request:
            ... # Do stuff with `view` and `request`

    在请求时临时重写方法的上下文管理器

    另外还设置了view.request属性

    用法：
        使用override_方法（view, request,POST）作为请求：
        使用view 和request进行操作
    """

    def __init__(self, view, request, method):
        self.view = view
        self.request = request
        self.method = method
        self.action = getattr(view, 'action', None)

    def __enter__(self):
        self.view.request = clone_request(self.request, self.method)
        # For viewsets we also set the `.action` attribute.
        action_map = getattr(self.view, 'action_map', {})
        self.view.action = action_map.get(self.method.lower())
        return self.view.request

    def __exit__(self, *args, **kwarg):
        self.view.request = self.request
        self.view.action = self.action


class WrappedAttributeError(Exception):
    pass


@contextmanager
def wrap_attributeerrors():
    """
    Used to re-raise AttributeErrors caught during authentication, preventing
    these errors from otherwise being handled by the attribute access protocol.

    用于重新引发身份验证期间捕获的AttributeRors，防止这些错误由属性访问协议处理
    """
    try:
        yield
    except AttributeError:
        info = sys.exc_info()
        exc = WrappedAttributeError(str(info[1]))
        raise exc.with_traceback(info[2])


class Empty:
    """
    Placeholder for unset attributes.
    Cannot use `None`, as that may be a valid value.

    未设置属性的占位符
    不能使用None, 因为这是一个有效值
    """
    pass


def _hasattr(obj, name):
    return not getattr(obj, name) is Empty


def clone_request(request, method):
    """
    Internal helper method to clone a request, replacing with a different
    HTTP method.  Used for checking permissions against other methods.

    克隆请求的尼日不帮助程序方法，替换为其他HTTP方法，用于对照其他方法检查权限
    """
    ret = Request(request=request._request,
                  parsers=request.parsers,
                  authenticators=request.authenticators,
                  negotiator=request.negotiator,
                  parser_context=request.parser_context)
    ret._data = request._data
    ret._files = request._files
    ret._full_data = request._full_data
    ret._content_type = request._content_type
    ret._stream = request._stream
    ret.method = method
    if hasattr(request, '_user'):
        ret._user = request._user
    if hasattr(request, '_auth'):
        ret._auth = request._auth
    if hasattr(request, '_authenticator'):
        ret._authenticator = request._authenticator
    if hasattr(request, 'accepted_renderer'):
        ret.accepted_renderer = request.accepted_renderer
    if hasattr(request, 'accepted_media_type'):
        ret.accepted_media_type = request.accepted_media_type
    if hasattr(request, 'version'):
        ret.version = request.version
    if hasattr(request, 'versioning_scheme'):
        ret.versioning_scheme = request.versioning_scheme
    return ret


class ForcedAuthentication:
    """
    This authentication class is used if the test client or request factory
    forcibly authenticated the request.

    如果测试客户端或请求工厂

    强制验证请求
    """

    def __init__(self, force_user, force_token):
        self.force_user = force_user
        self.force_token = force_token

    # 一定返回元组
    def authenticate(self, request):
        return (self.force_user, self.force_token)


class Request:
    """
    Wrapper allowing to enhance a standard `HttpRequest` instance.

        - request(HttpRequest). The original request instance.
        - parsers_classes(list/tuple). The parsers to use for parsing the
          request content.
        - authentication_classes(list/tuple). The authentications used to try
          authenticating the request's user.

    允许增强标准 HttpRequest 实例的包装器

        - 请求（HttpRequest） 原始请求实例
        - 语法分析类（列表、元组）。用于分析
        请求内容
        - 身份验证类（列表、元组）。用于尝试的身份验证
        正在验证请求的用户
    """

    def __init__(self, request, parsers=None, authenticators=None,
                 negotiator=None, parser_context=None):
        assert isinstance(request, HttpRequest), (
            'The `request` argument must be an instance of '
            '`django.http.HttpRequest`, not `{}.{}`.'
            .format(request.__class__.__module__, request.__class__.__name__)
        )

        # 将原来的request封装成新request的一个属性，为_request
        self._request = request
        self.parsers = parsers or ()
        self.authenticators = authenticators or ()
        self.negotiator = negotiator or self._default_negotiator()
        self.parser_context = parser_context
        self._data = Empty
        self._files = Empty
        self._full_data = Empty
        self._content_type = Empty
        self._stream = Empty

        if self.parser_context is None:
            self.parser_context = {}
        self.parser_context['request'] = self
        self.parser_context['encoding'] = request.encoding or settings.DEFAULT_CHARSET

        force_user = getattr(request, '_force_auth_user', None)
        force_token = getattr(request, '_force_auth_token', None)
        if force_user is not None or force_token is not None:
            forced_auth = ForcedAuthentication(force_user, force_token)
            self.authenticators = (forced_auth,)

    def _default_negotiator(self):
        return api_settings.DEFAULT_CONTENT_NEGOTIATION_CLASS()

    @property
    def content_type(self):
        meta = self._request.META
        return meta.get('CONTENT_TYPE', meta.get('HTTP_CONTENT_TYPE', ''))

    @property
    def stream(self):
        """
        Returns an object that may be used to stream the request content.

        返回可用于stream处理请求内容的对象
        """
        if not _hasattr(self, '_stream'):
            self._load_stream()
        return self._stream

    @property
    def query_params(self):
        """
        More semantically correct name for request.GET.

        从语义上来说，请更正reques.GET的名称
        """
        return self._request.GET

    @property
    def data(self):
        if not _hasattr(self, '_full_data'):
            self._load_data_and_files()
        return self._full_data

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

    # 设置user的属性值，将值封装在_user里面
    @user.setter
    def user(self, value):
        """
        Sets the user on the current request. This is necessary to maintain
        compatibility with django.contrib.auth where the user property is
        set in the login and logout functions.

        Note that we also set the user on Django's underlying `HttpRequest`
        instance, ensuring that it is available to any middleware in the stack.

        设置当前请求的用户，这是必要的

        与当前属性为django.contrib.auth兼容

        在登录和注销功能中设置

        注意，我们还在django的底层HttpRequest上设置了用户
        实例，确保栈中的任何中间件都可以使用它
        """
        self._user = value
        self._request.user = value

    @property
    def auth(self):
        """
        Returns any non-user authentication information associated with the
        request, such as an authentication token.

        置用户关于认证请求的信息，如身份验证令牌
        """
        if not hasattr(self, '_auth'):
            with wrap_attributeerrors():
                self._authenticate()
        return self._auth

    @auth.setter
    def auth(self, value):
        """
        Sets any non-user authentication information associated with the
        request, such as an authentication token.

        设置用户关于认证请求的信息，比如身份验证令牌
        """
        self._auth = value
        self._request.auth = value

    @property
    def successful_authenticator(self):
        """
        Return the instance of the authentication instance class that was used
        to authenticate the request, or `None`.

        返回使用的身份验证实例类的实例，验证请求，或“无”
        """
        if not hasattr(self, '_authenticator'):
            with wrap_attributeerrors():
                self._authenticate()
        return self._authenticator

    def _load_data_and_files(self):
        """
        Parses the request content into `self.data`.

        将请求内容解析为self.data
        """
        if not _hasattr(self, '_data'):
            self._data, self._files = self._parse()
            if self._files:
                self._full_data = self._data.copy()
                self._full_data.update(self._files)
            else:
                self._full_data = self._data

            # if a form media type, copy data & files refs to the underlying
            #             # http request so that closable objects are handled appropriately.

            # 如果表单媒体类型，则将数据和文件负责到基础
            # http请求，以便适当地处理可关闭对象
            if is_form_media_type(self.content_type):
                self._request._post = self.POST
                self._request._files = self.FILES

    def _load_stream(self):
        """
        Return the content body of the request, as a stream.

        以stream的形式返回请求的内容体
        """
        meta = self._request.META
        try:
            content_length = int(
                meta.get('CONTENT_LENGTH', meta.get('HTTP_CONTENT_LENGTH', 0))
            )
        except (ValueError, TypeError):
            content_length = 0

        if content_length == 0:
            self._stream = None
        elif not self._request._read_started:
            self._stream = self._request
        else:
            self._stream = io.BytesIO(self.body)

    def _supports_form_parsing(self):
        """
        Return True if this requests supports parsing form data.

        如果此请求支持分析表单数据，则返回True
        """
        form_media = (
            'application/x-www-form-urlencoded',
            'multipart/form-data'
        )
        return any([parser.media_type in form_media for parser in self.parsers])

    def _parse(self):
        """
        Parse the request content, returning a two-tuple of (data, files)

        May raise an `UnsupportedMediaType`, or `ParseError` exception.

        解析请求内容，返回两个元组（数据、文件）

        可能引发UnsupportedMediaType 或 ParseError异常
        """
        media_type = self.content_type
        try:
            stream = self.stream
        except RawPostDataException:
            if not hasattr(self._request, '_post'):
                raise
            # If request.POST has been accessed in middleware, and a method='POST'
            # request was made with 'multipart/form-data', then the request stream
            # will already have been exhausted.

            # 如果在中间件中访问了request.POST,并且方法为POST,使用multipart/form data，然后请求流

            if self._supports_form_parsing():
                return (self._request.POST, self._request.FILES)
            stream = None

        if stream is None or media_type is None:
            if media_type and is_form_media_type(media_type):
                empty_data = QueryDict('', encoding=self._request._encoding)
            else:
                empty_data = {}
            empty_files = MultiValueDict()
            return (empty_data, empty_files)

        parser = self.negotiator.select_parser(self, self.parsers)

        if not parser:
            raise exceptions.UnsupportedMediaType(media_type)

        try:
            parsed = parser.parse(stream, media_type, self.parser_context)
        except Exception:
            # If we get an exception during parsing, fill in empty data and
            # re-raise.  Ensures we don't simply repeat the error when
            # attempting to render the browsable renderer response, or when
            # logging the request or similar.
            self._data = QueryDict('', encoding=self._request._encoding)
            self._files = MultiValueDict()
            self._full_data = self._data
            raise

        # Parser classes may return the raw data, or a
        # DataAndFiles object.  Unpack the result as required.
        try:
            return (parsed.data, parsed.files)
        except AttributeError:
            empty_files = MultiValueDict()
            return (parsed, empty_files)

    # 执行认证方法
    def _authenticate(self):
        """
        Attempt to authenticate the request using each authentication instance
        in turn.

        尝试使用每个身份验证实例对请求进行身份验证
        """

        # self.get_authenticators() 他返回的是每个认证类的的实例
        # 将原来封装在新的authenticators=self.get_authenticators()的这个属性进行遍历
        for authenticator in self.authenticators:
            try:

                # 执行认证类的authenticate方法
                # 这里分三种情况
                # 1.如果authenticate方法抛出异常，self._not_authenticated()执行
                # 2.有返回值，必须是元组：（request.user,request.auth）
                # 3.返回None，表示当前认证不处理，等下一个认证来处理


                # 注意：
                # 这个认证类的实例authenticator调用authenticate方法
                user_auth_tuple = authenticator.authenticate(self)
            except exceptions.APIException:
                self._not_authenticated()
                raise

            if user_auth_tuple is not None:
                self._authenticator = authenticator
                self.user, self.auth = user_auth_tuple
                return

        self._not_authenticated()

    def _not_authenticated(self):
        """
        Set authenticator, user & authtoken representing an unauthenticated request.

        Defaults are None, AnonymousUser & None.

        设置authenticator,user,authtoken,表示未经身份验证的请求
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

    def __getattr__(self, attr):
        """
        If an attribute does not exist on this instance, then we also attempt
        to proxy it to the underlying HttpRequest object.

        如果此实例上不存在属性，则我们也尝试将其带到底层HttpRequest对象
        """
        try:
            return getattr(self._request, attr)
        except AttributeError:
            return self.__getattribute__(attr)

    @property
    def DATA(self):
        raise NotImplementedError(
            '`request.DATA` has been deprecated in favor of `request.data` '
            'since version 3.0, and has been fully removed as of version 3.2.'
        )

    @property
    def POST(self):
        # Ensure that request.POST uses our request parsing.
        if not _hasattr(self, '_data'):
            self._load_data_and_files()
        if is_form_media_type(self.content_type):
            return self._data
        return QueryDict('', encoding=self._request._encoding)

    @property
    def FILES(self):
        # Leave this one alone for backwards compat with Django's request.FILES
        # Different from the other two cases, which are not valid property
        # names on the WSGIRequest class.
        if not _hasattr(self, '_files'):
            self._load_data_and_files()
        return self._files

    @property
    def QUERY_PARAMS(self):
        raise NotImplementedError(
            '`request.QUERY_PARAMS` has been deprecated in favor of `request.query_params` '
            'since version 3.0, and has been fully removed as of version 3.2.'
        )

    def force_plaintext_errors(self, value):
        # Hack to allow our exception handler to force choice of
        # plaintext or html error responses.
        self._request.is_ajax = lambda: value
