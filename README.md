
## django 学习小结


> 作者：jusk
>
> 看了几门课程，把自己看到的、学习的进行一次小结。以后复习的时候也可以很快进行复习


#### chapter01 - 学习资料

- [Python文档](https://docs.python.org/zh-cn/3/index.html)
- [django文档]()
- [drf中文文档](http://www.iamnancy.top/djangorestframework/Home/)

- [python资料](https://github.com/vinta/awesome-python)


#### [chapter02 python基础](http://naotu.baidu.com/file/b0dbc01fce1bc2c30ff16254374fa253?token=9e983fe16ab0887d)

```markdown
这里是以脑图的形式展示出来，里面添加了一些参考链接
目前的话在Unix IO模型不是很清楚,使得在多进程多线程、协程只能依葫芦画瓢
```


#### [chapter03 drf-认证分析](./Authentication.md)

```markdown
这里是对DRF的认证的源码跟踪。使得我们知道请求的是谁

```




#### [chapter04 drf-权限分析](./Permission.md)


```markdown
这里是对DRF的权限进行分析查看,权限的自由设计有助于业务的正常进行
```


#### [chapter05 drf-频率分析](./Throttles.md)


```markdown
这里是对DRF的频率进行分析查看,爬虫的出现、恶意的攻击都会使
得系统不稳定，这里去请求的分析可以让针对性的对频率进行限制
，保障系统的稳定运行
```


#### [chapter06 drf-API版本分析](./VersionControl.md)


```markdown
这里是对DRF的API版本分析,程序的更新迭代很正常，如何对每个
版本进行管理这是我们业务面对的问题,API版本有效扩展了这一需求。
```


#### [chapter07 drf-解析器分析](./Parser.md)

```markdown
这里是对DRF的解析器分析,解析器的出现使得我们在调用request.data 时,
他会自动选择正确的解析器进行数据解析。让我们少走很多弯路。
```
#### [chapter07 drf-序列化分析](./serializer.md)
```markdown
这里是对DRF的序列化分析,序列化使得数据库的数据和传输网络的数据变得灵活
```



#### [chapter07 drf- 分页分析](./Paging.md)

```markdown
这里是对DRF的分页分析,分业在业务是再正常不过的需求。
```

#### [chapter08 drf- 视图与路由分析](./Authentication.md)

```
路由是如何运用的呢？
```



#### [对使用django+drf 前后端分离总结](./summary.md)


```
这里是对DRF以及django的一些总结
```
