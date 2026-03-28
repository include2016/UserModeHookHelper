C:\Users\x\Downloads\amsi_tracer-main\hook_component\DllLoadMon\DllLoadMon.cpp存在比较多的问题

 - 你应该参考C:\Users\x\Downloads\amsi_tracer-main\hook_component\HookCodeTemplate\dllmain.cpp的写法，导出函数DllLoadMonHook应该先调用PROLOGX64（64位）或者PROLOGWin32（32位）来获取hook现场的寄存器值
  - 然后将rid强转为PUNICODE_STRING，和watch list中的dll名进行对比
  - 另外比较重要的一个注意事项就是，DllLoadMon是作为一个dll直接注入到别的进程中的，我们需要一个机制来从umcontroller中获取到watchlist



你先根据我这个修改意见，给出修改方案，放到C:\Users\x\Downloads\amsi_tracer-main\vibe_prompt\result_1.md