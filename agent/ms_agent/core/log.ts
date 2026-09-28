export function log(level, msg) {
    send({ type: 'log', level: level, msg: msg });
}
