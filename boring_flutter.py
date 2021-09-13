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

print('🔥 Searching for instructions with scalar value (/aij {})...'.format(search_scalar))
search = r.cmdj('/aij {},'.format(search_scalar))

mov_instructions = []
for hit in search:
    if hit['code'].startswith('mov '):
        print('\033[31m{} {}\033[0m'.format(hex(hit['offset']), hit['code']))
        mov_instructions.append(hit)
    else:
        print('{} {}'.format(hex(hit['offset']), hit['code']))

if not mov_instructions:
    print('Could not find an instruction with {} scalar value...'.format(search_scalar))
    exit(0)

print('🔥 Performing simple instruction matching to find ssl_crypto_x509_session_verify_cert_chain()...')
target = ''
for mov_instruction in mov_instructions:
    instructions = r.cmdj('pdj 3 @{}'.format(mov_instruction['offset']))
    if len(instructions) == 3 and instructions[1]['disasm'].startswith('bl ') and instructions[2]['disasm'].startswith('mov '):
        print('✅  {} {} (match)'.format(hex(mov_instruction['offset']), mov_instruction['code']))
        target = hex(mov_instruction['offset'])
        break
    else:
        print('❌  {} {} (no match)'.format(hex(mov_instruction['offset']), mov_instruction['code']))

if not target:
    print('Could not find a matching function ...')
    exit(0)

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