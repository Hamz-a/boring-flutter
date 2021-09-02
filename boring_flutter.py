import r2pipe
import time
import sys
import os


start_time = time.time()
search_scalar = '0x186'  # TODO: currently HARD CODED, add argument parameter

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

print('🔥 Performing Advanced analysis (aaaa)...')
r.cmd('aaaa')

print('🔥 Searching for instructions with scalar value (/ae {},)...'.format(search_scalar))
search = r.cmd('/ae {},'.format(search_scalar))

target = ''
for hit in search.splitlines():
    if hit.startswith('0x005') and 'mov' in hit:
        target = hit.split(' ')[0]
        print('\033[31m{}\033[0m'.format(hit))
    else:
        print(hit)

if not target:
    print('Could not find a mov instruction with {} scalar value, in 0x005 region...'.format(search_scalar))
    exit(0)
else:
    print('Found "{}", a mov instruction with {} scalar value, in 0x005 region...'.format(target, search_scalar))

print('🔥 Seeking to target (s {})...'.format(target))
r.cmd('s {}'.format(target))

fcn_addr = r.cmd('afi.')
address = '0x' + fcn_addr.split('.')[1].strip()

print('🔥 Found ssl_crypto_x509_session_verify_cert_chain @ {} (afi.)...'.format(address))

with open('template_frida_hook.js') as f:
    template = f.read()

output_script = 'frida_libflutter_{}.js'.format(time.strftime("%Y.%m.%d_%H.%M.%S"))
with open(output_script, 'w') as f:
    f.write(template.replace('0x00000000', address))

print('🔥 Wrote script to {} \nHappy MITM !!! (exec time: {}s)'.format(output_script, time.time() - start_time))