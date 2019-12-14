TODO

修改Serializer的FallbackSigners到dict

修改Serializer的IterUnSigners为generator - channel

改变函数返回类型 要修改的后面有标注TODO

增加每个函数返回的错误与错误时候的默认参数

对调用Serializer和Signer的地方把类型写死不用interfaceAPI而是直接用struct

增加可传入的参数 对应python的 arg=None, 有时候不一定要传入到函数里面 也可以通过读取/修改一些全局变量来达成`传入`的目的. 比如`echo.NotFoundHandler`

replace append concentration to `https://stackoverflow.com/questions/1760757/how-to-efficiently-concatenate-strings`

create a `rsplit` function we need it in `unsign`