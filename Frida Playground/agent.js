function bin2String(array) {
    var result = "";
    for (var i = 0; i < array.length; i++) {
      result += String.fromCharCode(parseInt(array[i], 2));
    }
    return result;
  }


var readAddress = DebugSymbol.fromName("mbedtls_ssl_read").address;
var writeAddress = DebugSymbol.fromName("mbedtls_ssl_write").address;
var getSessionAddress = DebugSymbol.fromName("mbedtls_ssl_get_session").address;

var getSessionId = function(sslcontext){
    
    var offsetSession = Process.pointerSize * 7 + 4 +4 + 4+ +4 +4 + 4
    var sessionPointer = sslcontext.add(offsetSession).readPointer();
    var offsetSessionId = 8 + 4 + 4 +4 
    var offsetSessionLength = 8 + 4 + 4
    var idLength = sessionPointer.add(offsetSessionLength).readU32();
    
    var idData = sessionPointer.add(offsetSessionId)
    var session_id = ""
    
    for (var byteCounter = 0; byteCounter < idLength; byteCounter++){
        
        session_id = `${session_id}${idData.add(byteCounter).readU8().toString(16).toUpperCase()}`
    }

    return session_id
}

var getSocketDescriptor = function (sslcontext){
    console.log(`Pointersize: ${Process.pointerSize}`)
    var bioOffset = 48;//Documentation not valid (8 Bytes less)Process.pointerSize + 4 * 6 +  Process.pointerSize *3
    console.log(sslcontext.readByteArray(100))
    var p_bio = sslcontext.add(bioOffset).readPointer()
    console.log(`Pointer BIO: ${p_bio}`)
    var bio_value = p_bio.readS32();
    console.log(`BIO Value: ${bio_value}`)
    return bio_value
    //console.log(p_bio)
}

//https://tls.mbed.org/api/ssl_8h.html#aa2c29eeb1deaf5ad9f01a7515006ede5
Interceptor.attach(readAddress, {
    onEnter: function(args){
        var sslcontext = args[0];
        this.buffer = args[1];
        this.len = args[2];
        var sessionId = getSessionId(sslcontext)
        var socketDescriptor = getSocketDescriptor(sslcontext);
        console.log(`Session Id: ${sessionId}\nSocket descriptor: ${socketDescriptor}`)
    },

    onLeave: function(retval){
        retval |= 0 // Cast retval to 32-bit integer.
        if (retval <= 0) {
            return
        }
        var bytesRead = retval;
        console.log(`Read ${bytesRead} Bytes!`)
        //console.log(this.buffer.readAnsiString(bytesRead))
        var bytes = this.buffer.readByteArray(bytesRead);
        console.log("Test")
        console.log(bytes)
        
    }
})

//https://tls.mbed.org/api/ssl_8h.html#a5bbda87d484de82df730758b475f32e5
Interceptor.attach(writeAddress, {
    onEnter: function(args){
        console.log("write called!")
        var buffer = args[1];
        var len = args[2];
        len |= 0 // Cast retval to 32-bit integer.
        if (len <= 0) {
            return
        }
        console.log(buffer.readByteArray(len))
    }
})





