
function sendKey(label, byteArray, encoding) {
    var data;
    if (encoding === "base64") {
        data = toBase64(byteArray);
    } else {
        data = toHex(byteArray);
    }
    if (data.length === 0) {
        devlog("sendKey: empty data for label " + label);
        return;
    }
    send({
        contentType: "keylog",
        label: label,
        data: data,
        protocol: _protocol
    });
}

function sendData(byteArray, direction) {
    if (!byteArray || byteArray.byteLength === 0) {
        devlog("sendData: empty data");
        return;
    }
    send({
        contentType: "datalog",
        direction: direction,
        function: _protocol + "_" + direction,
        protocol: _protocol
    }, byteArray);
}
