### 前言

- 导读：[python 序列化](https: // www.cnblogs.com / yyds / p / 6563608.
html)
- 里面涉及到一些构造方法，看起来比较费力，下次来看
-

参考资料：

https: // www
.520
mwx.com / view / 3049

```
sequenceDiagram
模型类对象-> > python
字典: 序列化
python
字典-> > 模型类对象: 反序列化
```

```markdown
其实还是有些不准确的。

** 序列化 **：就是把变量从内存中变成可存储或传输的过程称之为序列化

** 反序列化 **：就是把变量内容从序列化的对象重新读到内存称之为反序列化
```

---
#### 序列化对象
- 创建对象

```python
from datetime import datetime


class Comment(object):
    def __init__(self, email, content, created=None):
        self.email = email
        self.content = content
        self.created = created or datetime.now()


comment = Comment(email='leila@example.com', content='foo bar')
```

- 声明

```python
from rest_framework import serializers


class CommentSerializer(serializers.Serializer):
    email = serializers.EmailField()
    content = serializers.CharField(max_length=200)
    created = serializers.DateTimeField()


```

- 序列化对象(转化为字典)

```python
serializer = CommentSerializer(comment)
serializer.data
# {'email': 'leila@example.com', 'content': 'foo bar', 'created': '2016-01-27T15:17:10.375877'}
```

- 转成标准json格式

```python
from rest_framework.renderers import JSONRenderer

json = JSONRenderer().render(serializer.data)
json
# b'{"email":"leila@example.com","content":"foo bar","created":"2016-01-27T15:17:10.375877"}'
```

#### 反序列化对象

- 流转化为python数据类型

```python
from django.utils.six import BytesIO
from rest_framework.parsers import JSONParser

stream = BytesIO(json)
data = JSONParser().parse(stream)
```
- 然后我们将这些原生数据类型恢复到已验证数据的字典中。


```
serializer = CommentSerializer(data=data)
serializer.is_valid()
# True
serializer.validated_data
# {'content': 'foo bar', 'email': 'leila@example.com', 'created': datetime.datetime(2012, 08, 22, 16, 20, 09, 822243)}
```

#### 深入源码看看到底在干什么

- HyperlinkedModelSerializer
- ModelSerializer
- Serializer
- BaseSerializer
- Field
- SerializerMetaclass
- type

有过ORM经验的话我们想到的是先看看类是怎么生成的

- 例子
```
queryset = Book.objects.all()
serializer = BookSerializer(data=queryset, many=True)
```

##### BaseSerializer


```python


def __new__(cls, *args, **kwargs):
    # We override this method in order to automagically create
    # `ListSerializer` classes instead when `many=True` is set.

    # many参数，如果有则执行cls.many_init,没有则执行super(BaseSerializer).__new__
    if kwargs.pop('many', False):
        # many=True,表示对QuerySet进行处理，走该逻辑
        return cls.many_init(*args, **kwargs)

    # many = False ，表示对单独的对象进行处理
    return super().__new__(cls, *args, **kwargs)


```

```markdown
原来序列化是先判断类的参数里面有没有many这个参数，有的话我们走
return cls.many_init(*args, **kwargs)
没的话return
super().__new__(cls, *args, **kwargs)
就走正常模式
```

##### cls.many_init(*args, **kwargs)

```markdown
我们当many = True时, 是怎么样的
```

```python


# many=True， 执行该方法
@classmethod
def many_init(cls, *args, **kwargs):
    """
    This method implements the creation of a `ListSerializer` parent
    class when `many=True` is used. You can customize it if you need to
    control which keyword arguments are passed to the parent, and
    which are passed to the child.

    Note that we're over-cautious in passing most arguments to both parent
    and child classes in order to try to cover the general case. If you're
    overriding this method you'll probably want something much simpler, eg:

    @classmethod
    def many_init(cls, *args, **kwargs):
        kwargs['child'] = cls()
        return CustomListSerializer(*args, **kwargs)
    """
    allow_empty = kwargs.pop('allow_empty', None)
    child_serializer = cls(*args, **kwargs)
    list_kwargs = {
        'child': child_serializer,
    }
    if allow_empty is not None:
        list_kwargs['allow_empty'] = allow_empty
    list_kwargs.update({
        key: value for key, value in kwargs.items()
        if key in LIST_SERIALIZER_KWARGS
    })
    meta = getattr(cls, 'Meta', None)
    list_serializer_class = getattr(meta, 'list_serializer_class', ListSerializer)

    # 最后使用ListSerializer进行实例化
    return list_serializer_class(*args, **list_kwargs)


```

```markdown
list_serializer_class = getattr(meta, 'list_serializer_class', ListSerializer)
return list_serializer_class(*args, **list_kwargs)

原来他是调用ListSerializer进行实例化, 继续跟踪
```

```python


@property
def data(self):
    # 执行父类data属性
    ret = super().data
    return ReturnList(ret, serializer=self)


```

```markdown
我们知道序列化时
serializer = BookSerializer(data=queryset, many=True)
data是起属性, 他是怎么将模型类数据集data序列化呢。继续跟踪,
他调用了父类的data。
```
##### BaseSerializer
```python


@property
def data(self):
    # 数据验证时候使用
    if hasattr(self, 'initial_data') and not hasattr(self, '_validated_data'):
        msg = (
            'When a serializer is passed a `data` keyword argument you '
            'must call `.is_valid()` before attempting to access the '
            'serialized `.data` representation.\n'
            'You should either call `.is_valid()` first, '
            'or access `.initial_data` instead.'
        )
        raise AssertionError(msg)

    if not hasattr(self, '_data'):

        # 判断有无错误，无错误进行序列化
        if self.instance is not None and not getattr(self, '_errors', None):
            # 将instance(QuerySet对象)传入,开始序列化
            self._data = self.to_representation(self.instance)
        elif hasattr(self, '_validated_data') and not getattr(self, '_errors', None):
            self._data = self.to_representation(self.validated_data)
        else:
            self._data = self.get_initial()
    return self._data


```

```markdown

他里面最后还是要执行
self._data = self.to_representation(self.instance)
进行序列化
```

##### to_representation跟踪(Serializer)

```python


def to_representation(self, instance):
    """
    Object instance -> Dict of primitive datatypes.

    对象实例--> 基本数据类型的Dict
    """

    # 先将instance转换为有序字典
    ret = OrderedDict()
    fields = self._readable_fields

    # 循环定义的字段，这个字段你可以是我们自己定义的，也可以是model中的字段
    for field in fields:
        try:
            # 调用字段的get_attribute方法(参数是对象),
            # 在示例中可以理解为group.get_attribute(group_obj)，
            # 其实就是获取instance每个字段的数据
            attribute = field.get_attribute(instance)
        except SkipField:
            continue

        # We skip `to_representation` for `None` values so that fields do
        # not have to explicitly deal with that case.
        #
        # For related fields with `use_pk_only_optimization` we need to
        # resolve the pk value.
        check_for_none = attribute.pk if isinstance(attribute, PKOnlyObject) else attribute
        if check_for_none is None:
            ret[field.field_name] = None
        else:
            ret[field.field_name] = field.to_representation(attribute)

    return ret


```

```markdown
fields = self._readable_fields

查看_readable_fields


@property
def _readable_fields(self):
    for field in self.fields.values():
        if not field.write_only:
            yield field


获取每一个字段名称

attribute = field.get_attribute(instance)

每个字段都调用get_attribute方法进行序列化
```

##### 执行get_attribute跟踪调查(Field)


```python


def get_attribute(self, instance):
    """
    Given the *outgoing* object instance, return the primitive value
    that should be used for this field.

    给定outgoing 对象实例,返回原语句值应该用在这个field
    """
    try:

        # 执行get_attribute函数，用于根据定义的字段属性，获取不同的数据，
        # 注意该方法没有带self, 是一个函数，并不是类方法。

        # self.source是我们自定义字段传入的source参数，
        # 如：gp=serializers.CharField(source='group.name')，
        # sss=serializers.CharField(source='get_user_type_display')
        # 最后分割变成['group', 'name']
        return get_attribute(instance, self.source_attrs)
    except BuiltinSignatureError as exc:
        msg = (
            'Field source for `{serializer}.{field}` maps to a built-in '
            'function type and is invalid. Define a property or method on '
            'the `{instance}` instance that wraps the call to the built-in '
            'function.'.format(
                serializer=self.parent.__class__.__name__,
                field=self.field_name,
                instance=instance.__class__.__name__,
            )
        )
        raise type(exc)(msg)
    except (KeyError, AttributeError) as exc:
        if self.default is not empty:
            return self.get_default()
        if self.allow_null:
            return None
        if not self.required:
            raise SkipField()
        msg = (
            'Got {exc_type} when attempting to get a value for field '
            '`{field}` on serializer `{serializer}`.\nThe serializer '
            'field might be named incorrectly and not match '
            'any attribute or key on the `{instance}` instance.\n'
            'Original exception text was: {exc}.'.format(
                exc_type=type(exc).__name__,
                field=self.field_name,
                serializer=self.parent.__class__.__name__,
                instance=instance.__class__.__name__,
                exc=exc
            )
        )
        raise type(exc)(msg)


```

```markdown
return get_attribute(instance, self.source_attrs)

执行get_attribute函数，用于根据定义的字段属性，获取不同的数据，
注意该方法没有带self, 是一个函数，并不是类方法。

self.source是我们自定义字段传入的source参数，
如：gp = serializers.CharField(source='group.name')，
sss = serializers.CharField(source='get_user_type_display')
最后分割变成['group', 'name']
每个字段都调用get_attribute方法进行序列化
```

##### 参数里面有self.source_attrs,我们继续跟踪查看


```python
if self.source == '*':
    self.source_attrs = []
else:
    self.source_attrs = self.source.split('.')
```

```markdown

如：
# gp=serializers.CharField(source='group.name')，
# 　sss=serializers.CharField(source='get_user_type_display')
最后分割变成['group', 'name']
```

##### 继续回到get_attribute-----------------(Field)


```python


def get_attribute(instance, attrs):
    """
    Similar to Python's built in `getattr(instance, attr)`,
    but takes a list of nested attributes, instead of a single attribute.

    Also accepts either attribute lookup on objects or dictionary lookups.
    """
    for attr in attrs:  # 循环列表
        try:

            # 如果是model 字段映射(DRF 的内部字段转化),直接调用model类
            if isinstance(instance, Mapping):
                # 重新赋值，此时的instance已经改变
                instance = instance[attr]
            else:
                # 否则, 使用反射获取结果,如instance=getattr(userinfo_obj,group)
                instance = getattr(instance, attr)
        except ObjectDoesNotExist:
            return None
        # 判断是否可以执行,此时如我们示例中的get_user_type_display,其判断过程在类似下面TIPS中
        # 这里不再做过多说明
        if is_simple_callable(instance):

            try:
                # 重新赋值，加括号进行执行
                instance = instance()
            except (AttributeError, KeyError) as exc:
                # If we raised an Attribute or KeyError here it'd get treated
                # as an omitted field in `Field.get_attribute()`. Instead we
                # raise a ValueError to ensure the exception is not masked.
                raise ValueError(
                    'Exception raised in callable attribute "{}"; original exception was: {}'.format(attr, exc))

    return instance


```


