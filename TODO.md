TODO

增加可传入的参数 对应python的 arg=None, 有时候不一定要传入到函数里面 也可以通过读取/修改一些全局变量来达成`传入`的目的. 比如`echo.NotFoundHandler`

修改代碼結構 將要繼承的要方法轉成函數(如果能轉才轉) 比如serializer中有很多是完全override的 轉不了
如果不行那建議寫個函數是創建那些struct的因為名字太長了