当前版本的设计文档C:\Users\x\Downloads\amsi_tracer-main\doc\iteration_record\result_3\DelayHook_Implementation_Plan_CN_Rev3.md已经很接近我们最终的目标了，但是有一点我需要给你说明一下

对ntdll的ldrloaddll返回位置的hook应该复用当前codebase中的代码，不需要重新实现hook相关的代码

可以参考C:\Users\x\Downloads\amsi_tracer-main\controller\HookCoreLib\HookCore.cpp的76行的applyhook函数

另外一点需要说明的就是我们不需要移除对ldrloaddll的hook，因为我们可能随时需要dll load mon的功能，且这个hook对程序的正常运行并没有太大的影响



现在再来迭代一版设计文档，放到C:\Users\x\Downloads\amsi_tracer-main\doc\iteration_record\result_4

