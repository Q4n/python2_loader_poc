							python2_loader_poc

众所周知啊, 有的selinux规则限制的非常严格, 在用户目录/tmp等地方不允许执行任何脚本/二进制.
那么假如我们想要利用二进制漏洞LPE, 我们就需要一个可以用于执行汇编的上下文. 浏览器就是一种
很好用的上下文, 奈何本人cb, 挖不到浏览器的洞...

这个poc用于解决上述问题, 通过python的交互式shell来加载shellcode执行我们的提权代码, 
用于绕过某些严格的selinux规则. 缺点也很明显, 由于需要一个交互式的python作为执行上下文, 
所以在实战环境好像没什么用(?). 但是在某些场景下好像还是有用的(x).

用法很简单, 我们可以通过scc等软件生成一个shellcode写入到文件中, 之后直接复制pwn.py的代码到
python交互式shell中运行, 就会根据路径去执行shellcode啦. 
read_addr.py是在python中加载so, 在shellcode去使用一些so中的函数啥的操作可能可以用到:D 

这个poc只在 x64和aarch64, python2.7.18 环境上测试

Refer: 
	https://www.anquanke.com/post/id/86366
	