export function log(str: string) {
    var message: { [key: string]: string } = {}
    message["contentType"] = "console"
    message["console"] = str
    send(message)
}