import r2pipe
import time
import sys
import os


start_time = time.time()

if len(sys.argv) < 2:
    print('Usage: python {} libflutter.so'.format(sys.argv[0]))
    exit(-1)

if not os.path.exists(sys.argv[1]):
    print('File "{}" not found...'.format(sys.argv[1]))
    exit(-1)

if not os.path.isfile(sys.argv[1]):
    print('"{}" is a directory, please provide a valid libflutter.so file...'.format(sys.argv[1]))
    exit(-1)

r = r2pipe.open(sys.argv[1])
info = r.cmdj('ij')

if info['core']['format'] != 'elf64':
    print('Currently only supporting Android...')
    exit(0)

if info['bin']['arch'] != 'arm':
    print('Currently only supporting ARM...')
    exit(0)

if info['bin']['bits'] != 64:
    print('Currently only supporting x64...')
    exit(0)

print('🔥 Happy MITM!!! ({}s)'.format(time.time() - start_time))
