from ctypes import *
libc = CDLL('libc.so.6')
libp = CDLL("libpthread.so")
libcpt = CDLL("libcrypt.so")

def function_addr(func):
    p = cast(func, c_void_p)
    # print("addr_of: "+ hex(p.value))
    return p.value


cmd = 'scc --arch x64 -f bin -m64 --platform linux '
cmd += ' --func pthread_create '+hex(function_addr(libp.pthread_create))
cmd += ' --func clone '+hex(function_addr(libc.clone))
cmd += ' --func open64 '+hex(function_addr(libc.open))
cmd += ' --func sleep '+hex(function_addr(libc.sleep))
cmd += ' --func libexit '+hex(function_addr(libc.exit))
cmd += ' --func crypt '+hex(function_addr(libcpt.crypt))
cmd += ' -O0 -o test  exp_scc.c'
print(cmd)
