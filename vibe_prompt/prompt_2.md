对C:\Users\x\Downloads\amsi_tracer-main\vibe_prompt\result_2.md的修改意见：

主要是watchlist获取机制相关的

你给的方案是使用共享内存，需要umcontroller向目标进程中写入一块内存，这个涉及到进程句柄权限相关的东西，我不是很想这样做

我更倾向于使用文件进行数据的共享


根据我的修改意见，给出新的设计方案，保存到C:\Users\x\Downloads\amsi_tracer-main\vibe_prompt\result_3.md中