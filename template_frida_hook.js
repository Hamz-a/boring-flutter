function hook_ssl_crypto_x509_session_verify_cert_chain(address) {
    Interceptor.attach(address, {
        onEnter: function(args) {
            console.log('Disabling SSL validation...');
        },
        onLeave: function(retval) {
            console.log(`ssl_crypto_x509_session_verify_cert_chain: ${retval} -> 0x1`);
            retval.replace(0x1);
        }
    });
}

Java.perform(function() {
    // Early loading
    const System = Java.use('java.lang.System');
    const Runtime = Java.use('java.lang.Runtime');
    const System_loadLibrary = System.loadLibrary.overload('java.lang.String');
    const VMStack = Java.use('dalvik.system.VMStack');

    System_loadLibrary.implementation = function(library) {
        try {
            const loaded = Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library);
            if(library.includes('flutter')) { // libflutter.so
                var libflutter = Module.findBaseAddress('libflutter.so');
                console.log(`libflutter.so found @ ${libflutter}`);
                var offset = 0x00000000;
                var addr = libflutter.add(offset);
                console.log(`ssl_crypto_x509_session_verify_cert_chain @ ${addr}`);

                hook_ssl_crypto_x509_session_verify_cert_chain(addr);
            }
            return loaded;
        } catch(ex) {
            console.log(ex);
        }
    };
});