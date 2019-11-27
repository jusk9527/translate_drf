



### [django的内置组件](https://www.cnblogs.com/Mixtea/p/10494455.html)

#### 认证组件

- auth模块


```
models
用户模型主要有下面几个字段：username、password、email、first_name、last_name

一般我们继承AbstractUser去扩展

#注意要在setting设置这个、重载系统的用户，让UserProfile生效
AUTH_USER_MODEL = 'users.UserProfile'

authenticate()  
提供了用户认证，即验证用户名以及密码是否正确,一般需要username  password两个关键字参数
        
login(HttpRequest, user)
该函数接受一个HttpRequest对象，以及一个认证了的User对象

此函数使用django的session框架给某个已认证的用户附加上session id等信息

logout(request) 
注销用户

```




```
user = authenticate(username='someone',password='somepassword')
```

```
from django.contrib.auth import authenticate, login
   
def my_view(request):
  username = request.POST['username']
  password = request.POST['password']
  user = authenticate(username=username, password=password)
  if user is not None:
    login(request, user)
    # Redirect to a success page.
    ...
  else:
    # Return an 'invalid login' error message.
    ...
```


```
from django.contrib.auth import logout
   
def logout_view(request):
  logout(request)
  # Redirect to a success page.
```


#### [缓存](https://www.cnblogs.com/ZJiQi/p/10590217.html)


1. 默认缓存


```
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake'
    }
 }
```

2. 基于redis的缓存


```
pip install django-redis

CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'CONNECTION_POOL_KWARGS': {
                'max_connections': 1000
            },
            # 'PASSWORD': 'xxx', # 如果有设置了redis-server密码在这里设置
        }
    }
}
```

3. [drf-extensions](https://www.cnblogs.com/derek1184405959/p/8877643.html)


```
pip install drf-extensions

from rest_framework_extensions.cache.mixins import CacheResponseMixin
#CacheResponseMixin一定要放在第一个位置

class GoodsListViewSet(CacheResponseMixin,mixins.ListModelMixin, mixins.RetrieveModelMixin,viewsets.GenericViewSet):
```

```
setting

#缓存配置
REST_FRAMEWORK_EXTENSIONS = {
    'DEFAULT_CACHE_RESPONSE_TIMEOUT': 5   #5s过期，时间自己可以随便设定
}
```



4. 自定义cache


```
django_redis.cache.RedisCache 都是继承了from django.core.cache.backends.base import BaseCache 

继承实现他就可以

```

FBV缓存举例

```
# 引入装饰器装饰视图函数即可缓存视图
from django.views.decorators.cache import cache_page

import time
from django.views.decoratosr.cache import cache_page


@chace_page(60*5)  # 必须设置缓存的更新间隔，单位秒
def content_detail(request):
   return HTTPResponse('hello' + str(time.time()))
```

CBV缓存举例

```
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
import time
@method_decorator(cache_page(5),name='dispatch')
class ShowTime(APIView):
    def get(self,request):
        ctime = time.strftime('%Y-%m-%d %H:%M:%S')
        return render(request,'show_time.html',{'ctime':ctime})
```

#### [日志](https://segmentfault.com/a/1190000016068105)
- 这个可以具体看下这篇博客说的，有效避免了print()



#### [邮件](https://www.cnblogs.com/zyj-python/p/7522471.html)

1. email

settring中配置

```
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_USE_TLS = False   #是否使用TLS安全传输协议(用于在两个通信应用程序之间提供保密性和数据完整性。)
EMAIL_USE_SSL = True    #是否使用SSL加密，qq企业邮箱要求使用
EMAIL_HOST = 'smtp.163.com'   #发送邮件的邮箱 的 SMTP服务器，这里用了163邮箱
EMAIL_PORT = 25     #发件箱的SMTP服务器端口
EMAIL_HOST_USER = 'charleschen@xmdaren.com'    #发送邮件的邮箱地址
EMAIL_HOST_PASSWORD = '*********'         #发送邮件的邮箱密码(这里使用的是授权码)
```


```
from django.core.mail import send_mail  
# send_mail的参数分别是  邮件标题，邮件内容，发件箱(settings.py中设置过的那个)，收件箱列表(可以发送给多个人),失败静默(若发送失败，报错提示我们)
send_mail('Subject here', 'Here is the message.', 'charleschen@xmdaren.com',
    ['to@example.com'], fail_silently=False)
```

#### 分页

1. Paginator


```
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage, InvalidPage
from django.http import HttpResponse
from django.shortcuts import render

def paginator_view(request):
    book_list = []
    '''
    数据通常是从 models 中获取。这里为了方便，直接使用生成器来获取数据。
    '''
    for x in range(1, 26):  # 一共 25 本书
        book_list.append('Book ' + str(x))

    # 将数据按照规定每页显示 10 条, 进行分割
    paginator = Paginator(book_list, 10)

    if request.method == "GET":
        # 获取 url 后面的 page 参数的值, 首页不显示 page 参数, 默认值是 1
        page = request.GET.get('page')
        try:
            books = paginator.page(page)
        # todo: 注意捕获异常
        except PageNotAnInteger:
            # 如果请求的页数不是整数, 返回第一页。
            books = paginator.page(1)
        except InvalidPage:
            # 如果请求的页数不存在, 重定向页面
            return HttpResponse('找不到页面的内容')
        except EmptyPage:
            # 如果请求的页数不在合法的页数范围内，返回结果的最后一页。
            books = paginator.page(paginator.num_pages)

    template_view = 'page.html'
    return render(request, template_view, {'books': books})
```
#### [静态文件管理](https://juejin.im/entry/5ac439af5188255cb07d52f0)


```
STATIC_URL = '/static/'
STATICFILES_DIRS = (
    os.path.join(BASE_DIR, "static"),
)

# STATIC_ROOT = os.path.join(BASE_DIR, "static/")       #线上设置


```

```
执行python manage.py collectstatic          # 实现静态文件的打包
```



### ORM的一些常用方法
- 从数据库中查询出来的结果一般是一个集合，这个集合叫做 QuerySet


```
1. filter               # 过滤
2. exclude              # 排除
3. annotate             # 聚合
4. order_by             # 排序
5. reverse              # 反向排序
6. distinct             # 去除查询结果中重复的行
7. values               # 迭代时返回字典而不是模型实例对象
8. values_list          # 迭代时返回元祖而不是字典
9. dates                # 表示特定种类的所有可用日期
10. datetimes           # 表示特定种类的所有可用日期
11. all                 # 返回所有结果
12. select_felated      # 外键查询
13. using               # 多个数据库控制QuerySet在那个数据库上求职
```

- ROM中能写sql 语句的方法


```
1. 使用extra：查询人民邮电出版社出版并且价格大于50元的书籍
Book.objects.filter(publisher__name='人民邮电出版社').extra(where=['price>50']) 

2. 使用raw
books=Book.objects.raw('select * from hello_book')  
for book in books:  
   print book 

3. 自定义sql

from django.db import connection  
  
cursor = connection.cursor()  
cursor.execute("insert into hello_author(name) VALUES ('郭敬明')")  
cursor.execute("update hello_author set name='韩寒' WHERE name='郭敬明'")  
cursor.execute("delete from hello_author where name='韩寒'")  
cursor.execute("select * from hello_author")  
cursor.fetchone()  
cursor.fetchall()
```

4. orm高级用法

    - 大于、大于等于
    
    ```
    __gt                    # 大于
    __gte                   # 大于等于>=
    
    Students.objects.filter(age__gt=10)         //查询年龄大于10的学生
    Studnets.objects.filter(age__gte=10)        // 查询年龄大于等于10岁的学生
    ```
    
    - 小于、小于等于
    ```
    __lt                    # 小于<
    __lte                   # 小于等于<=
    
    Students.objects.filter(age__lt=10)         //查询年龄小于10岁的学生
    Students.objects.filter(age__lte=10)        //查询年龄小于等于10岁的学生
    
    ```
    - like
    
    ```
    __exact                 # 精确等于          //like "aaa"
    __iexact                # 精确等于          //忽略大小写 ilike  "aaa"
    __contains              # 包含              // like "%aaa"
    __icontains             # 包含，忽略大小写  //ilike "aaa",但对于sqlite来说，contains的作用效果等同于icontains
    
    
    ```
    
    - in:
    
    ```
    __in
    
    Student.objects.filter(age__in=[10,20,30])              # 查询年龄在某一范围的学生
    
    
    ```
    
    - is null/is not null:
    
    ```
    __isnull                # 判空
    Students.objects.filter(name__isnull=True)  //查询用户名为空的学生
    Students.objects.filter(name__isnull=False) //查询用户名不为空的学生
    
    ```
    
    - 不等于/不包含于
    
    ```
    Students.objects.filter().excute(age=10)        // 查询年龄不为10的学生
    Students.objects.filter().excute(age__in=[10,20]        // 查询年龄不在[10,20]的学生
    
    ```
    - 其他常用模糊查询：
    
    ```
    __startswith                                //以...开头
    __istartswith                               // 以....开头，忽略大小写
    __endswith                                  // 以...结尾
    __iendswith                                 // 以...结尾，忽略大小写
    __range                                     // 在...范围内
    __year                                      //日期字段的年份
    __month                                     //日期字段的月份
    __day                                       // 日期字段的日
    ```








- F与Q的作用

F作用：操作数据表中的某列值，F() 允许Django在啊未实际连接数据库的情况下对数据库字段的引用，不能获取对象放在内存中再对字段进行操作，直接执行原生sql语句操作

使用场景：对数据库中的所有的商品，在原价格的基础上涨价10元

```
from django.db.models import F
from app01.models import Book
Book.objects.update(price=F("price")+20)  # 对于book表中每本书的价格都在原价格的基础上增加20元
```


Q作用：对对象进行复杂查询，并支持&（and）,|（or），~（not）操作符

使用场景：filter查询条件只有一个，而使用Q可以设置多个查询条件

```
from django.db.models import Q
search_obj=Asset.objects.filter(Q(hostname__icontains=keyword)|Q(ip=keyword))
```


当同时使用filter的关键字查询和Q查询时，一定要把Q对象放在前面


```
Asset.objects.get(
Q(pub_date=date(2005, 5, 2)) | Q(pub_date=date(2005, 5, 6)),question__startswith='Who')
```


### Model中ForeignKey字段中的on_delete参数有什么作用

on_delete 有CASCADE、PROTECT、SET_NULL、SET_DEFAULT、SET()


```
1. CASCADE: 级联删除; 默认值
2. PROTECT: 抛出ProtectedError 以阻止被引用对象的删除，它是django.db.IntegrityError 的一个子类
3. SET_NULL: 把ForeignKey 设置为null； null 参数为True 时才可以这样做
4. SET_DEFAULT: ForeignKey 值设置成它的默认值；此时必须设置ForeignKey 的default 参数
5. SET: 设置ForeignKey 为传递给SET() 的值，如果传递的是一个可调用对象，则为调用后的结果。在大部分情形下，传递一个可调用对象用于避免models.py 在导入时执行查询


```

#### djagno 实现websocket

原因：http是对于服务器是被动的，而websocket可以主动发送客户端信息或动作
- 使用Channels实现websocket

https://www.jianshu.com/p/3de90e457bb4



### 　[drf 常用组件](https://www.cnblogs.com/yuanchenqi/articles/8719520.html)

我们知道drf是django的更上一层包装，构建api时前后端分离利器

#### 权限组件



#####  局部视图权限

```
- app01.service.permissions.py


from rest_framework.permissions import BasePermission
class SVIPPermission(BasePermission):
    message="SVIP才能访问!"
    def has_permission(self, request, view):
        if request.user.user_type==3:
            return True
        return False
```



```
这个表示自己只能查阅自己的权限

class IsOwnerOrReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in ['GET','POST']:
            return True
        return obj.user == request.user
```




```
- views.py

from app01.service.permissions import *

class BookViewSet(generics.ListCreateAPIView):
    permission_classes = [SVIPPermission,]
    queryset = Book.objects.all()
    serializer_class = BookSerializers
```


##### 全局设置权限


```
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': (
    
        'rest_framework.permissions.IsAuthenticated',       # 必须是登录用户
        'app01.service.auth.Authentication',                # 必须是符合这个权限的登录用户
    ),
}
```

#### 访问频率组件

#####  局部视图 throttle


```
- app01.service.throttles.py

from rest_framework.throttling import BaseThrottle

VISIT_RECORD={}
class VisitThrottle(BaseThrottle):

    def __init__(self):
        self.history=None

    def allow_request(self,request,view):
        remote_addr = request.META.get('REMOTE_ADDR')
        print(remote_addr)
        import time
        ctime=time.time()

        if remote_addr not in VISIT_RECORD:
            VISIT_RECORD[remote_addr]=[ctime,]
            return True

        history=VISIT_RECORD.get(remote_addr)
        self.history=history

        while history and history[-1]<ctime-60:
            history.pop()

        if len(history)<3:
            history.insert(0,ctime)
            return True
        else:
            return False

    def wait(self):
        import time
        ctime=time.time()
        return 60-(ctime-self.history[-1])
```




```
- views.py

from app01.service.throttles import *

class BookViewSet(generics.ListCreateAPIView):
    throttle_classes = [VisitThrottle,]
    queryset = Book.objects.all()
    serializer_class = BookSerializers
```


##### 全局视图throttle


```
REST_FRAMEWORK={
    "DEFAULT_AUTHENTICATION_CLASSES":["app01.service.auth.Authentication",],
    "DEFAULT_PERMISSION_CLASSES":["app01.service.permissions.SVIPPermission",],
    "DEFAULT_THROTTLE_CLASSES":["app01.service.throttles.VisitThrottle",]
}
```


#### 分页组件

##### 简单分页


```
from rest_framework.pagination import PageNumberPagination,LimitOffsetPagination

class PNPagination(PageNumberPagination):
        page_size = 1
        page_query_param = 'page'
        page_size_query_param = "size"
        max_page_size = 5

class BookViewSet(viewsets.ModelViewSet):

    queryset = Book.objects.all()
    serializer_class = BookSerializers
    def list(self,request,*args,**kwargs):

        book_list=Book.objects.all()
        pp=LimitOffsetPagination()
        pager_books=pp.paginate_queryset(queryset=book_list,request=request,view=self)
        print(pager_books)
        bs=BookSerializers(pager_books,many=True)

        #return Response(bs.data)
        return pp.get_paginated_response(bs.data)
```

#### 序列化
- serializers


- ModelSerializer


```
class BookSerializer(serializers.ModelSerializer):
    """
    后端：xxx
    """
    class Meta:
        model = Book
        fields = "__all__"
        depth=1             #深度、默认为0
```


```
class UserSerializer(serializers.Serializer):
    """
    用户
    """
    id = serializers.IntegerField()
    name = serializers.CharField(max_length=20)
    type = serializers.ChoiceField(choices=Organization.organization_type_choices, default='company')


```


实现连接序列化

-[HyperlinkedIdentityField](https://www.django-rest-framework.org/api-guide/relations/)


```
class AlbumSerializer(serializers.HyperlinkedModelSerializer):
    track_listing = serializers.HyperlinkedIdentityField(view_name='track-list')

    class Meta:
        model = Album
        fields = ['album_name', 'artist', 'track_listing']
```




```
{
    'album_name': 'The Eraser',
    'artist': 'Thom Yorke',
    'track_listing': 'http://www.example.com/api/track_list/12/',
}
```



#### mixin类编写视图
这个之前已经写过，就不再写了



#### 登录模式


##### 局部认证

```

from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework.authentication import SessionAuthentication

class StudentsFeeViewset(ModelViewSet):
    """
    后端：xxx
    """
    lookup_field = 'id'
    authentication_classes = (JSONWebTokenAuthentication, SessionAuthentication)
```


##### 全局认证

表示默认JWT、表单、cookie模式都可以登录


```
REST_FRAMEWORK = {

    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_jwt.authentication.JSONWebTokenAuthentication',
        'rest_framework.authentication.BasicAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ),

}
```




#### [解析器](https://www.cnblogs.com/derek1184405959/p/8768059.html)

##### request


```
.data                     # request.data 返回请求主题的解析内容

.query_params             # request.query_params 等同于 request.GET，不过其名字更加容易理解，为了代码更加清晰可读，推荐使用 request.query_params ，而不是 Django 中的 request.GET，这样那够让你的代码更加明显的体现出 ----- 任何 HTTP method 类型都可能包含查询参数（query parameters），而不仅仅只是 'GET' 请求。

.parser                   #


```

##### response


```
.data                           # 还没有渲染，但已经序列化的响应数据。

.status_code                    # .status_code

.content                        # 将会返回的响应内容，必须先调用 .render() 方法，才能访问 .content 。

.template_name                  # 只有在 response 的渲染器是 HTMLRenderer 或其他自定义模板渲染器时才需要提供


```





### 项目执行小技巧



#### url的包装

- 根url
```
urlpatterns = [
    # user的接口
    path(r'', include('users.urls')),


]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
```
- users模块url


```
from django.urls import path,include
from users.views import ser_user,menu,oranization,role,permission
from rest_framework import routers

router = routers.SimpleRouter()
router.register(r'users', ser_user.UserViewSet, base_name="users")

urlpatterns = [

    path(r'api/', include(router.urls)),
    path(r'api/menu/tree/', menu.MenuTreeView.as_view(), name='menus_tree'),

]
```

这样路由就可以分模块查询，自己维护也比较轻松



#### 初期的状态码定义等


```
from rest_framework import status

# 成功
OK = status.HTTP_200_OK

NO_CONTENT = status.HTTP_204_NO_CONTENT
# 失败
BAD = status.HTTP_400_BAD_REQUEST
# 无权限
FORBIDDEN = status.HTTP_403_FORBIDDEN
# 未认证
UNAUTHORIZED = status.HTTP_401_UNAUTHORIZED
# 创建
CREATED = status.HTTP_201_CREATED
# NOT_FOUND
NOT_FOUND = status.HTTP_404_NOT_FOUND

```

这样先约定好状态码，然后重写response


```
from django.utils import six
from rest_framework.response import Response
from rest_framework.serializers import Serializer


class XopsResponse(Response):
    def __init__(self, data=None, status=200, msg='成功',
                 template_name=None, headers=None,
                 exception=False, content_type=None):

        super(Response, self).__init__(None, status=status)

        if isinstance(data, Serializer):
            msg = (
                # 'You passed a Serializer instance as data, but '
                # 'probably meant to pass serialized `.data` or '
                # '`.error`. representation.'
                "哈哈"
            )
            raise AssertionError(msg)
        if status >= 400:
            msg = '失败'
        self.data = {
            'code': status,
            'message': msg,
            'detail': data
        }
        self.template_name = template_name
        self.exception = exception
        self.content_type = content_type

        if headers:
            for name, value in six.iteritems(headers):
                self[name] = value
```

我们在返回前端时就能直接这样

XopsResponse(data)等，比较好的将参数返回前端，前端根据以此判断



#### 跨域的解决

- https://segmentfault.com/a/1190000018025987
- https://github.com/adamchainz/django-cors-headers


#### [中间件的问题](https://www.cnblogs.com/derek1184405959/p/8445842.html)

- 中间件其实就是一个类，在请求来和结束后，django 会根据自己的规则在合适的实际执行执行相对于的中间件中相应的方法


```
# 方法在请求到来的时候调用
process_request(self,request)


# 在本次将要执行的View函数被调用前调用本函数
process_view(self, request, callback, callback_args, callback_kwargs)


# 需使用render()方法才会执行process_template_response
process_template_response(self,request,response)


# View函数在抛出异常时该函数被调用，得到的exception参数是实际上抛出的异常实例。通过此方法可以进行很好的错误控制，提供友好的用户界面。
process_exception(self, request, exception)


# 在执行完View函数准备将响应发到客户端前被执行
process_response(self, request, response)
```

- 执行顺序


```
（1）process_request(self,request)　

请求来时执行，不写时直接跳过，执行下一个中间件；当有return HttpResonse时，下面中间件不再执行

（2）process_view(self, request, callback, callback_args, callback_kwargs)   

先执行process_request，执行完后，再从起始执行proces_view

（3）process_template_response(self,request,response)　　

如果Views中的函数返回的对象中，具有render方法，此方法执行

（4）process_exception(self, request, exception)　　           

异常触发执行，当views.py函数执行出错后，此方法执行；出错时，最低层的exception优先级最高，执行最近的一个，

然后执行respnse方法

（5）process_response(self, request, response)　　　　　　

请求返回时执行，不写时直接跳过，执行下一个中间件；当有return HttpResonse时，会替换原数据

以上方法的返回值可以是None和HttpResonse对象，如果是None，则继续按照django定义的规则向下执行，如果是HttpResonse对象，则直接将该对象返回给用户
```




- 使用场景

如果是想要修改请求，例如被传送到view中的HttpRequest对象

比如想想写一个判断浏览器来源，是pc还是手机，

或者说做一个拦截器，发信一定时间内某个ip对网页的访问次数过多，则将其加入黑名单



#### model 转字典

- model_to_dict

同时接收两个参数fields和exclude。这两个分别对应的是显示和排除哪些字段

```
model_to_dict(Permission.objects.get(id=1))
{'id': 1, 'name': '系统管理员', 'method': 'admin', 'pid': None}
```

- to_dict

自定义

```
from django.db.models.fields import DateTimeField
from django.db.models.fields.related import ManyToManyField

class User(models.Model):
    ...

    def to_dict(self, fields=None, exclude=None):
        data = {}
        for f in self._meta.concrete_fields + self._meta.many_to_many:
            value = f.value_from_object(self)

            if fields and f.name not in fields:
                continue

            if exclude and f.name in exclude:
                continue

            if isinstance(f, ManyToManyField):
                value = [ i.id for i in value ] if self.pk else None

            if isinstance(f, DateTimeField):
                value = value.strftime('%Y-%m-%d %H:%M:%S') if value else None

            data[f.name] = value

        return data
```


```
>>> User.objects.get(id=2).to_dict()
{'is_active': True, 'update_time': '2018-10-12 21:21:39', 'username': 'ops-coffee@163.com', 'id': 2, 'leader': 1, 'group': [1, 3, 5], 'create_time': '2018-10-12 21:20:19', 'fullname': '运维咖啡吧'}
>>> 
>>> User.objects.get(id=2).to_dict(fields=['fullname','is_active','create_time'])
{'is_active': True, 'fullname': '运维咖啡吧', 'create_time': '2018-10-12 21:20:19'}
>>> 
>>> User.objects.get(id=2).to_dict(exclude=['group','leader','id','create_time'])
{'is_active': True, 'update_time': '2018-10-12 21:21:39', 'username': 'ops-coffee@163.com', 'fullname': '运维咖啡吧'}
```


```
拥有model_to_dict一样的便利性，同时也解决了不能输出time时间字段（editable=False）的问题，还能对value按照自己需要的格式输出，一举多得 当然拥有便利性的同时需要自己实现to_dict的代码，增加了复杂度
```


#### "__"的使用

2. 双下划线表示的是连表的操作



```
# 设置过滤
filter_fields = ("grade_name__name","grade_name__pid__id","fee_name","is_must")



 class A(models.Model):
    name = models.CharField(u'名称')
 class B(models.Model):
    aa = models.ForeignKey(A)
 
B.objects.filter(aa__name__contains='searchtitle')#查询B表中外键aa所对应的表中字段name包含searchtitle的B表对象。
```


这样就表示可以按外键为年级的名字等过滤


```
lookup_field = 'grade_name_id'
```

==问==：为什么model设置为grade_name、而这是grade_name_id呢？

==回答==：这是因为这个字段是外键，而存在数据库中的字段其实是grade_name_id,所以就用grade_name_id



#### serializers 的问题

资料：
- https://juejin.im/post/5a68934551882573443cddf8
- https://www.django-rest-framework.org/tutorial/1-serialization/



- **嵌套的serializers问题**

比如学校、班级、年级

我们知道学校包含班级，年级包含班级，这样我们我们如果嵌套呢？


```
class ClassSerializer(serializers.ModelSerializer):
    """
    班级
    """
    class Meta:
        model = Class
        fields = "__all__"


class GradeSerializer(serializers.ModelSerializer):
    """
    年级
    """
    grade_class = ClassSerializer(many=True, read_only=True)
    class Meta:
        model = Grade
        fields = "__all__"
        

class SchoolSerializer(serializers.ModelSerializer):
    """
    学校
    """
    school_grade = GradeSerializer(many=True, read_only=True)
    class Meta:
        model = Sch
        fields = (---------------------)

        depth = 3           # 深度


```

像grade_class、school_grade这样的字段不是随便弄得，他是反向查询的字段

当然你也可这样改变字段名字，自由灵活
```
children = UserSerializer(many=True, read_only=True, source='user_department')
```


- Grade
```
school = models.ForeignKey(Organization, verbose_name="学校",blank=True, on_delete=models.CASCADE, null=False,
                                                help_text="学校", related_name="school_grade")
```

这个年级的外键school指向这个学校，related_name就可以表示这个学校的的所有年级
```
related_name="school_grade")
```


- serializer 对某些字段的验证

就是validate_字段。非常方便
```
class UserModifySerializer(serializers.ModelSerializer):
    '''
    用户编辑的序列化
    '''
    # mobile = serializers.CharField(max_length=11)

    class Meta:
        model = UserProfile
        fields = ['id', 'username', 'name','department', 'email', 'image', 'position',
                  'is_active', 'roles']

    def validate_mobile(self, mobile):
        REGEX_MOBILE = "^1[358]\d{9}$|^147\d{8}$|^176\d{8}$"
        if not re.match(REGEX_MOBILE, mobile):
            raise serializers.ValidationError("手机号码不合法")
        return mobile
```


- 取得某个外键的名字而不是id，我们可以这样


比如这个数据库外键是menus,那么我们如果让外键的名字如何显现出来呢？

**source='menus.name'**, 比较方便的解决了这个问题

```
class PermissionListSerializer(serializers.ModelSerializer):
    '''
    权限列表序列化
    '''
    menuname = serializers.ReadOnlyField(source='menus.name')

    class Meta:
        model = Permission
        fields = ('id','name','method','menuname','pid','menus')
```


- 如果需要嵌套外键的某些内容，我们在serializer里面直接


```
class UserListSerializer(serializers.ModelSerializer):
    '''
    用户列表的序列化
    '''
    roles = serializers.SerializerMethodField()

    def get_roles(self, obj):
        return obj.roles.values()

    class Meta:
        model = UserProfile
        fields = [------------------]
        depth = 1
```

depth 就表示深度，默认为0，最好别弄得非常多层。


其他的我建议看下上面的链接！比我介绍的详细且规律




#### 视图

这个可以先查阅下源码，这样在使用时心中有数，错误也好排查

一般我们把继承的大接口就用viewsets里面的东西写

from rest_framework.viewsets import --------

而小接口就可以使用APIView写，这样大小兼顾，灵活多变是比较好的

from rest_framework.views import APIView


- 批量删除

[自定义action](https://juejin.im/post/5d064f856fb9a07f0420478a#heading-52)

```
from rest_framework.decorators import action


# 批量删除
@action(methods=['delete'], detail=False)
def multiple_delete(self, request, *args, **kwargs):
    delete_id = request.query_params.get('deleteid', None)
    if not delete_id:
        return XopsResponse("失败",status=NOT_FOUND)
    for i in delete_id.split(','):
        get_object_or_404(Students, pk=int(i)).delete()
    return XopsResponse("成功",status=OK)
```

我们在批量删除时可以选择装饰器action, 数值只需要用,隔开就能删除


```
http://xx.com/api/multiple_delete/?deleteid=173,174,175
```






#### 信号

- https://juejin.im/post/5b960c0bf265da0ad70189a4
-

比如创建创建用户名和密码时需要加密

```
from django.db.models.signals import post_save
from django.dispatch import receiver


from django.contrib.auth import get_user_model
User = get_user_model()


# post_save:接收信号的方式
# sender: 接收信号的model
@receiver(post_save, sender=User)
def create_user(sender, instance=None, created=False, **kwargs):
    # 是否新建，因为update的时候也会进行post_save
    if created:
        password = instance.password
        #instance相当于user
        instance.set_password(password)
        instance.save()
```



#### 依赖包问题

将依赖包导入到requirements.txt里面
```
pip freeze > requirements.txt
```

安装 requirements.txt 里面的依赖包


```
pip install -r requirement.txt
```

#### restful api

有时候我们确实不不好用名词一个接口写增删改查使用，增删改查分开来如何写呢？


```
举例：

urlpatterns = [
    path('basic/structure/', views_structure.StructureView.as_view(), name='basic-structure'),
    path('basic/structure/create/', views_structure.StructureCreateView.as_view(), name='basic-structure-create'),
    path('basic/structure/list/', views_structure.StructureListView.as_view(), name='basic-structure-list'),
    path('basic/structure/delete/', views_structure.StructureDeleteView.as_view(), name='basic-structure-delete'),
]
```



### 服务器问题

#### mysql下载




```
#1.安装
wget http://dev.mysql.com/get/mysql-community-release-el7-5.noarch.rpm
rpm -ivh mysql-community-release-el7-5.noarch.rpm
yum install mysql-community-server

#2.重启服务
service mysqld restart

#3. 设置bind-ip

    vim /etc/my.cnf
    在 [mysqld]:
        下面加一行
        bind-address = 0.0.0.0

#4.登录mysql
mysql -u root

#5. 设置外部ip可以访问
#mysql中输入命令：
#后面用navicat连接远程服务器mysql的用户名和密码
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY '123456' WITH GRANT OPTION;

FLUSH PRIVILEGES；

#6.设置mysql密码
进入mysql：
set password =password('123456');     #密码123456
flush privileges;
```


#### python 3.6安装


```
#安装pip


wget https://bootstrap.pypa.io/get-pip.py  --no-check-certificate

sudo python get-pip.py

#安装python3.6
首先安装这两个

yum -y install zlib*

yum install openssl-devel -y


1. 获取

wget https://www.python.org/ftp/python/3.6.2/Python-3.6.2.tgz
tar -xzvf Python-3.6.2.tgz -C  /tmp
cd  /tmp/Python-3.6.2/

2. 把Python3.6安装到 /usr/local 目录

./configure --prefix=/usr/local
make
make altinstall

3. 更改/usr/bin/python链接

ln -s /usr/local/bin/python3.6 /usr/bin/python3
```

注意需要安装gcc 解释器，这个是源码安装，比较慢

#### 虚拟环境的安装


```
yum install python-setuptools python-devel
pip install virtualenvwrapper

#编辑.bashrc文件
vim ~/.bashrc

#添加进去
export WORKON_HOME=$HOME/.virtualenvs
source /usr/bin/virtualenvwrapper.sh

#sudo find / -name virtualenvwrapper.sh      查看你的virtualenvwrapper.sh在什么地方

#重新加载.bashrc文件
source ~/.bashrc

#虚拟环境保存的路径
cd ~/.virtualenvs/      （创建的虚拟环境都会保存在这个目录，前面设置的）

#创建指定python版本的虚拟环境方法
mkvirtualenv MxShop --python=python3.6

workon MxShop

#进虚拟环境安装依赖包

首先 pip freeze > requirements.txt 将本地的虚拟环境安装包导出来，上传到服务器

pip install -r requirements.txt

#安装mysqlclient出问题

    centos 7：
        yum install python-devel mariadb-devel -y

    ubuntu：
        sudo apt-get install libmysqlclient-dev

    然后：
        pip install mysqlclient
```



#### WSGI

- 描述web server如何与web application通信的一种规范



```
[uwsgi]
#使用HTTP访问的端口号, 使用这个端口号是直接访问了uWSGI, 绕过了Nginx
http = :8010
#与外界连接的端口号, Nginx通过这个端口转发给uWSGI
socket = 127.0.0.1:8001

#是否使用主线程
master = true
# 项目在服务器中的目录(绝对路径)
chdir = /home/gitpackage/MxOnline
# Django's wsgi 文件目录
wsgi-file = MxShop/wsgi.py
# 指定静态文件
static-map = /static=/home/gitpackage/MxOnline/static
# 最大进程数
processes = 10
#每个进程的线程数
threads = 2
#状态监听端口
stats = 127.0.0.1:9191
# 退出时自动清理环境配置
vacuum = true
#目录下文件改动时自动重启
touch-reload = /home/gitpackage/MxOnline
#Python文件改动时自动重启
#py-auto-reload = 1
#后台运行并把日志存到.log文件
daemonize = /root/projects/Mxshop/MxShop/uWSGI.log

```




#### django的一些常用命令


```

运行可以

python manage.py + 下例参数执行命令

例如：

python manage.py startapp [name]                # 创建一个app

[auth]                                          # 认证相关
    changepassword                              # 修改密码
    createsuperuser                             # 创建一个超级管理员

[contenttypes]
    remove_stale_contenttypes

[django]
    check           
    compilemessages
    createcachetable
    dbshell                                     # 这个命令会执行数据库的SQL语句，如果你对SQL比较熟悉，可能喜欢这种方式
    diffsettings
    dumpdata                                    # 导出数据      python manage.py dumpdata appname > appname.json
    flush                                       # 清空数据库
    inspectdb
    loaddata                                    # 导入数据      python manage.py loaddata appname.json
    makemessages
    makemigrations                              # 在当前目录之下生成一个migrations文件夹，该问佳佳的内容就是数据库要执行的内容
    migrate                                     # migrate就是执行之前生成migrations 文件，这异步才是操作数据库的一步
    sendtestemail
    shell                                       # 这个命令和 直接运行 python 或 bpython 进入 shell 的区别是：你可以在这个 shell 里面调用当前项目的 models.py 中的 API，对于操作数据，还有一些小测试非常方便
    showmigrations                              # 展示所有进行了makemigrations的文件
    sqlflush
    sqlmigrate
    sqlsequencereset
    squashmigrations
    startapp                                    # 创建一个app
    startproject                                # 创建一个项目
    test
    testserver

[rest_framework]
    generateschema

[sessions]
    clearsessions                               # 清空sessions

[staticfiles]
    collectstatic                               # 把静态文件收集到STATIC_ROOT中
    findstatic
    runserver                                   # 使用开发者服务器运行，后面可以加端口
```


#### 豆瓣源


```
pip install -i https://pypi.douban.com/simple xxx模块

```



### django 的一些常见问题

- 参考连接 
- https://www.kancloud.cn/hmoonmoon/django/738443