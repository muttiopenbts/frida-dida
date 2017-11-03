"use strict";

var passed_arg = "%s";
var func_pointer;
var FIRST_RUN = false;

/* Help with formatting output strings.
E.g. "Value1 is {1} and value2 is {2}".format(v1, v2)
*/
String.prototype.format = function() {
  var a = this;
  for (var k in arguments) {
    a = a.replace("{" + k + "}", arguments[k])
  }
  return a
}

function keep_alive(secs) {
    for (var i = 0; i <= secs; i++){
        setTimeout(function(){
            send("Loop {0}".format(i))
        }, 1000);
    }
}

/*
Args
    byte_string     string, e.g "0923AFE9"

Returns
    bytes           byte_array, e.g. [0x09,0x23,0xAF,0xE9]
*/
function byte_string_to_bytes_array(byte_string){
    var bytes = [];
    for (var i = 0; i < byte_string.length; ++i) {
        var code = byte_string.charCodeAt(i);
        bytes = bytes.concat([code]);
    }
    return bytes
}

/*
c printf() hook
*/
var printf_hook = {
    onEnter: function (args) {
        var params_from_arr = " ";
//        var params_from_arr = Memory.readUtf8String(args[0]);
        /* Don't print literal newline */
//        params_from_arr = params_from_arr.replace(/\r?\n|\r/, '');

//        params_from_arr += " " + args[1].toString();

        send("printf onEnter: {0}".format(params_from_arr));

        console.log("Hexdump:" + hexdump(args[0], {
            offset: 0,
            length: 20,
            header: true,
            ansi: true
        }))
    },

    onLeave: function (retval) {
        send("printf onLeave: {0}".format(retval.toString())  );
        return retval;
    }
};

/*
c puts() hook
*/
var puts_hook = {
    onEnter: function (args) {
        var params_from_arr = " ";

        send("puts onEnter: {0}".format(params_from_arr));

        console.log("Hexdump:" + hexdump(args[0], {
            offset: 0,
            length: 20,
            header: true,
            ansi: true
        }))
    },

    onLeave: function (retval) {
        send("puts onLeave: {0}".format(retval.toString())  );
        return retval;
    }
};

/*
  This will be used as a generic hook to view parameteres passed to functions.
*/
var peak_hook = {
  onEnter: function (args) {
      var params_from_arr = Memory.readUtf8String(args[0]);

      send("peak onEnter: {0}".format(params_from_arr));
  },

  onLeave: function (retval) {
      send("peak onLeave: {0}".format(retval.toString())  );
      return retval;
  }
};

/*
Hook which sets up blocking recv().
*/
var func_hook = {
    onEnter: function (args) {
        send("Hook onEnter: " + args[0].toString());

        var op = recv('input', function(value) {
            send("Hook recv input: {0} ".format(value.payload))

            args[0] = ptr(value.payload);
        });
        op.wait();
        send("Hook onEnter exit: " + args[0].toString());
    },

    onLeave: function (retval) {
        send("Hook retval :" + retval.toString())

        return retval;
    }
};

/*
Main hook which sets up blocking recv().
This is an experiment to see if I can prevent the process from terminating.
*/
var main_hook = {
    onEnter: function (args) {
        send("Main hook onEnter: " + args[0].toString());
        send("Main hook onEnter exit: " + args[0].toString());
    },

    onLeave: function (retval) {
        send("Main hook retval :" + retval.toString())

        var op = recv('main-input', function(value) {
            send("Main hook recv input: {0} ".format(value.payload))
        });
        op.wait();

        return retval;
    }
};

/*
Hook with no recv() so is expected to be invoked with NativeFunction().
*/
var func_hook_no_recv = {
    onEnter: function (args) {
        send("Hook_no_recv onEnter: " + args[0].toString());
    },

    onLeave: function (retval) {
        send("Hook_no_recv onLeave retval:{0}".format(retval.toString()))

        return retval;
    }
};

/* passed_arg is callers hooked function name */
if (passed_arg != 'None') {
    func_pointer = DebugSymbol.getFunctionByName(passed_arg)
    send ("Attaching to " + func_pointer.toString());
    //Interceptor.attach(func_pointer,func_hook_no_recv);
    Interceptor.attach(func_pointer,func_hook_no_recv);
}

var puts_pointer = DebugSymbol.getFunctionByName("puts")
send ("Attaching to " + puts_pointer.toString());
/* printf hook should work for puts() too */
Interceptor.attach(puts_pointer,puts_hook);

var printf_pointer = DebugSymbol.getFunctionByName("printf")
send ("Attaching to " + printf_pointer.toString());
Interceptor.attach(printf_pointer,printf_hook);

/* Hook main() */
var main_pointer = DebugSymbol.getFunctionByName("main")
send ("Attaching to " + main_pointer.toString());
Interceptor.attach(main_pointer,main_hook);

/* Try to find memory location of flag symbol */
//var flag_addr = DebugSymbol.fromName('flag')['address']; // Doesn't work
/* Had to obtain flag address using gdb and hardcode here */
var flag_addr = ptr(0x601040);

var flag_content = Memory.readUtf8String(flag_addr);
send ("Found scambled flag {0} at {1}".format(flag_addr.toString(), flag_content));
console.log("Hexdump:" + hexdump(flag_addr, {
    offset: 0,
    length: 20,
    header: true,
    ansi: true
}))

/*
  This recv() will wait for the python script to call 'call_me_brutus' and
  pass the func_param as input to the hooked function.
  It will bruteforce the xor byte key.

  Args
    Arg.payload     int, used as starting value to bruteforce hooked function.
    func_pointer
  */
if (func_pointer) {
    recv('call_me_brutus', function onMessage(args) {
        send("call_me_brutus");

        var process_func = new NativeFunction(func_pointer, 'int', ['int']);

        for (var i = 0; i <= 255; i++){
            var r = process_func(i);
            // Restore flag back to initial value
            var bytes = byte_string_to_bytes_array(flag_content);

            Memory.writeByteArray(flag_addr, bytes)

            send("NativeFunction return: " + r.toString())
        }
    });
}


/*
Used to help restore state of memory back to before frida implants.
*/
recv('restore', function onMessage(args) {
    send("restore called.");
    /*
    flag_content was previously read from memory location.
    The test binary will have already xor'ed flag_content and changed it.
    By xor'ing with our own key will result in incorrect result.
    Restoring the scrambled flag_content back to it's initial value solve
    the problem.
    */
    var bytes = byte_string_to_bytes_array(flag_content);

    Memory.writeByteArray(flag_addr, bytes)

    console.log("Hexdump:" + hexdump(flag_addr, {
        offset: 0,
        length: 20,
        header: true,
        ansi: true
    }))
});


if (func_pointer) {
    recv('call_me_once', function onMessage(args) {
        var func_param = args.payload;
        send("call_me_once func pointer: {0}  and func param: {1}".format(
            func_pointer,
            func_param.toString()
        ));

        var process_func = new NativeFunction(func_pointer, 'int', ['int']);

        var r = process_func(parseInt(func_param));

        send("NativeFunction return: " + r.toString())
    });
}
