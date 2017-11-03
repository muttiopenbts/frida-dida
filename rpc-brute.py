'''
Guess xor challenge binary called m.
Uses frida.re to hook binary function calls dynamically.

Either enter xor key to try or allow frida script to bruteforce.

e.g. scramble is binary's label to identify xor function and 32 is xor key to try.
$ python /mnt/hgfs/frida/rpc-brute.py spawn /mnt/hgfs/frida/m scramble 32
or
$ python /mnt/hgfs/frida/rpc-brute.py spawn /mnt/hgfs/frida/m scramble

'''
from __future__ import print_function
import frida
import sys
import time


run_mode = sys.argv[1]
app_name = sys.argv[2]
''' Option runtime hook '''
function_name = None
xor_key = None

if len(sys.argv) >= 4:
    function_name = sys.argv[3]

if len(sys.argv) == 5:
    xor_key = sys.argv[4]
    print('Trying XOR key: {}'.format(xor_key))


pid = None
''' Load frida script '''
js_script = None

session = None

''' Determine mode of operation '''
if run_mode == 'spawn':
    # Start process
    pid = frida.spawn([app_name])
elif run_mode == 'attach':
    ''' Already running process '''
else:
    run_mode = None
    pid = frida.spawn([app_name])


print('Looking for function {}'.format(function_name))

with open('/mnt/hgfs/frida/frida-hook.js', 'r') as js_file:
    js_script = js_file.read() % function_name


''' This is a callback function that gets invoked on every frida send() '''
def on_message(message, data):
    print('Received something')

    if message.get('type') == 'send':
        print('Received type {} payload: {}'.format(message.get('type'), message.get('payload')))
    elif message.get('type') == 'error':
        print('[!] {} Stack: {}'.format(message.get('type'), message.get('stack')))


''' This is a callback function that gets invoked when process exits '''
def exit_callback(message, data):
    print('Process terminated')
    exit(0)


if __name__ == '__main__':
    if run_mode:
        # print(js_script)

        if pid:
            session = frida.attach(pid)
        else:
            ''' Must be attach mode '''
            session = frida.attach(app_name)

        ''' Want to be notified when process exits '''
        session.on('detached', exit_callback)

        # Create script inside frida
        script = session.create_script(js_script)

        script.on('message', on_message)
        script.load()

        if pid:
            frida.resume(pid)
            print('Resume pid {}'.format(pid))

        print('Restoring flag back to initial value')
        script.post({'type': 'restore'})

        # This will trigger entry to hooked function
        if xor_key:
            script.post({'type': 'call_me_once', 'payload': str(int(xor_key))})
        else:
            script.post({'type': 'call_me_brutus'})

        time.sleep(1)
        ''' Allow main() to reach end '''
        script.post({'type': 'main-input', 'payload': 'exit main'})

        ''' Need to pause app to prevent exit before magic happens '''
        sys.stdin.read()
    else:
        ''' Just run '''
        script = session.create_script("send(1337);")
        script.load()
        script.on('message', on_message)
        sys.stdin.read()
