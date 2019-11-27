### 流程图

```
graph LR
dispatch-->initialize_request
initialize_request-->get_parsers
get_parsers-->request.data
request.data-->判断是否设置了_full_data值
判断是否设置了_full_data值-->None
判断是否设置了_full_data值-->True
None-->_load_data_and_files
_load_data_and_files-->self._parse
self._parse-->select_parser选择解析器
select_parser选择解析器-->返回数据,文件
返回数据,文件-->self._full_data
```

![](https://raw.githubusercontent.com/jusk9527/images/master/data/20191127145346.gif)


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



#### 执行get_parsers


```
def get_parsers(self):
    """
    Instantiates and returns the list of parsers that this view can use.
    """

    # 列表生成式获取解析器实例
    return [parser() for parser in self.parser_classes]
```


#### 执行parser_classes


```
parser_classes = api_settings.DEFAULT_PARSER_CLASSES
```


#### 执行request.data


```
@property
def data(self):
    if not _hasattr(self, '_full_data'):


        # 执行_load_data_and_files() ,获取请求体数据获取文件数据
        self._load_data_and_files()
    return self._full_data
```


#### 执行_load_data_and_files

- 把文件流和数据放入self._full_data


```
    def _load_data_and_files(self):
        """
        Parses the request content into `self.data`.
        """

        # 如果设置了request._data="xxx",且值为空的话
        if not _hasattr(self, '_data'):

            # 执行self._parse(),获取解析器，并对content_type进行解析，选择解析器，返回元组
            # (数据，文件)
            self._data, self._files = self._parse()

            # 判断文件流数据，存在则加入到self._full_data(也就是我们的request.data)中
            if self._files:
                # 浅拷贝赋值
                self._full_data = self._data.copy()
                self._full_data.update(self._files)
            else:

                # 不存在将无文件流的解析完成的数据赋值到self._full_data(request.data)
                self._full_data = self._data

            # if a form media type, copy data & files refs to the underlying
            # http request so that closable objects are handled appropriately.
            if is_form_media_type(self.content_type):
                self._request._post = self.POST
                self._request._files = self.FILES
```


#### self._parse() 返回元祖(数据、文件)


```
def _parse(self):
    """
    Parse the request content, returning a two-tuple of (data, files)

    May raise an `UnsupportedMediaType`, or `ParseError` exception.

    解析请求内容，返货两个元组(数据、文件)

    可能引发"UnsupportedMediaType"或者“ParseError”异常
    """

    # 获取请求体中的content-type
    media_type = self.content_type
    try:
        # 如果是文件数据,则获取文件流数据
        stream = self.stream
    except RawPostDataException:
        if not hasattr(self._request, '_post'):
            raise
        # If request.POST has been accessed in middleware, and a method='POST'
        # request was made with 'multipart/form-data', then the request stream
        # will already have been exhausted.

        # 如果是form表单
        if self._supports_form_parsing():

            # 处理文件类型数据
            return (self._request.POST, self._request.FILES)
        stream = None

    # 如果文件流为空,和media_type也为空
    if stream is None or media_type is None:
        if media_type and is_form_media_type(media_type):
            empty_data = QueryDict('', encoding=self._request._encoding)
        else:
            empty_data = {}
        empty_files = MultiValueDict()
        return (empty_data, empty_files)

    # 选择解析器
    parser = self.negotiator.select_parser(self, self.parsers)

    # 没有解析器则抛出异常
    if not parser:
        raise exceptions.UnsupportedMediaType(media_type)

    try:

        # 执行解析器的parse方法(从这里可以看出每个解析器都必须有该方法),对请求数据进行解析
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

        # 返回解析结果, 元组,解析后的数据parsed.data(在load_data_and_files中
        # 使用self._data和self._files进行接受)
        # 文件数据咋parsed.files中

        return (parsed.data, parsed.files)
    except AttributeError:
        empty_files = MultiValueDict()
        return (parsed, empty_files)
```

#### 执行 self.negotiator.select_parser(self, self.parsers)

- 选择分析器

- 给定解析器列表和媒体类型，返回处理传入请求的分析器。

![](https://raw.githubusercontent.com/jusk9527/images/master/data/20191127125923.png)




### 内置解析器

#### BaseParser

- 解析器基类
- 必须要执行parse方法,返回解析内容

```
class BaseParser:
    """
    All parsers should extend `BaseParser`, specifying a `media_type`
    attribute, and overriding the `.parse()` method.
    """

    # 解析的Content-type类型
    media_type = None

    def parse(self, stream, media_type=None, parser_context=None):
        """
        Given a stream to read from, return the parsed representation.
        Should return parsed data, or a `DataAndFiles` object consisting of the
        parsed data and files.
        """
        raise NotImplementedError(".parse() must be overridden.")
```

#### JSONParser

- json解析器
- 本质是使用json类进行解析

```
class JSONParser(BaseParser):
    """
    Parses JSON-serialized data.
    """


    # 解析的Content-type类型

    media_type = 'application/json'
    renderer_class = renderers.JSONRenderer
    strict = api_settings.STRICT_JSON


    # 该方法用于解析请求体
    def parse(self, stream, media_type=None, parser_context=None):
        """
        Parses the incoming bytestream as JSON and returns the resulting data.
        """
        parser_context = parser_context or {}
        encoding = parser_context.get('encoding', settings.DEFAULT_CHARSET)

        try:
            decoded_stream = codecs.getreader(encoding)(stream)
            parse_constant = json.strict_constant if self.strict else None

            # 本质使用json类进行解析
            return json.load(decoded_stream, parse_constant=parse_constant)
        except ValueError as exc:
            raise ParseError('JSON parse error - %s' % str(exc))
```


#### FormParser

- form 表单解析
```
class FormParser(BaseParser):
    """
    Parser for form data.
    """

    # form表单解析
    media_type = 'application/x-www-form-urlencoded'

    def parse(self, stream, media_type=None, parser_context=None):
        """
        Parses the incoming bytestream as a URL encoded form,
        and returns the resulting QueryDict.
        """
        parser_context = parser_context or {}
        encoding = parser_context.get('encoding', settings.DEFAULT_CHARSET)
        return QueryDict(stream.read(), encoding=encoding)
```

#### FileUploadParser

- 文件上传解析

```
class FileUploadParser(BaseParser):
    """
    Parser for file upload data.
    """

    # 文件上传解析
    media_type = '*/*'
    errors = {
        'unhandled': 'FileUpload parse error - none of upload handlers can handle the stream',
        'no_filename': 'Missing filename. Request should include a Content-Disposition header with a filename parameter.',
    }

    def parse(self, stream, media_type=None, parser_context=None):
        """
        Treats the incoming bytestream as a raw file upload and returns
        a `DataAndFiles` object.

        `.data` will be None (we expect request body to be a file content).
        `.files` will be a `QueryDict` containing one 'file' element.
        """
        parser_context = parser_context or {}
        request = parser_context['request']
        encoding = parser_context.get('encoding', settings.DEFAULT_CHARSET)
        meta = request.META
        upload_handlers = request.upload_handlers
        filename = self.get_filename(stream, media_type, parser_context)

        if not filename:
            raise ParseError(self.errors['no_filename'])

        # Note that this code is extracted from Django's handling of
        # file uploads in MultiPartParser.
        content_type = meta.get('HTTP_CONTENT_TYPE',
                                meta.get('CONTENT_TYPE', ''))
        try:
            content_length = int(meta.get('HTTP_CONTENT_LENGTH',
                                          meta.get('CONTENT_LENGTH', 0)))
        except (ValueError, TypeError):
            content_length = None

        # See if the handler will want to take care of the parsing.
        for handler in upload_handlers:
            result = handler.handle_raw_input(stream,
                                              meta,
                                              content_length,
                                              None,
                                              encoding)
            if result is not None:
                return DataAndFiles({}, {'file': result[1]})

        # This is the standard case.
        possible_sizes = [x.chunk_size for x in upload_handlers if x.chunk_size]
        chunk_size = min([2 ** 31 - 4] + possible_sizes)
        chunks = ChunkIter(stream, chunk_size)
        counters = [0] * len(upload_handlers)

        for index, handler in enumerate(upload_handlers):
            try:
                handler.new_file(None, filename, content_type,
                                 content_length, encoding)
            except StopFutureHandlers:
                upload_handlers = upload_handlers[:index + 1]
                break

        for chunk in chunks:
            for index, handler in enumerate(upload_handlers):
                chunk_length = len(chunk)
                chunk = handler.receive_data_chunk(chunk, counters[index])
                counters[index] += chunk_length
                if chunk is None:
                    break

        for index, handler in enumerate(upload_handlers):
            file_obj = handler.file_complete(counters[index])
            if file_obj is not None:
                return DataAndFiles({}, {'file': file_obj})

        raise ParseError(self.errors['unhandled'])

    def get_filename(self, stream, media_type, parser_context):
        """
        Detects the uploaded file name. First searches a 'filename' url kwarg.
        Then tries to parse Content-Disposition header.
        """
        try:
            return parser_context['kwargs']['filename']
        except KeyError:
            pass

        try:
            meta = parser_context['request'].META
            disposition = parse_header(meta['HTTP_CONTENT_DISPOSITION'].encode())
            filename_parm = disposition[1]
            if 'filename*' in filename_parm:
                return self.get_encoded_filename(filename_parm)
            return force_str(filename_parm['filename'])
        except (AttributeError, KeyError, ValueError):
            pass

    def get_encoded_filename(self, filename_parm):
        """
        Handle encoded filenames per RFC6266. See also:
        https://tools.ietf.org/html/rfc2231#section-4
        """
        encoded_filename = force_str(filename_parm['filename*'])
        try:
            charset, lang, filename = encoded_filename.split('\'', 2)
            filename = parse.unquote(filename)
        except (ValueError, LookupError):
            filename = force_str(filename_parm['filename'])
        return filename
```

#### 使用方式


```
#全局使用
REST_FRAMEWORK = {
   
    #解析器
    "DEFAULT_PARSER_CLASSES":["rest_framework.parsers.JSONParser","rest_framework.parsers.FormParser"]
}

#单一视图使用
parser_classes = [JSONParser,FormParser]
```


### 总结

解析器是按请求头Content-Type来实现的，不同的类型选择不同的解析器