import { connect } from 'cloudflare:sockets'

// configurations
const UUID = '' // vless UUID
const PROXY = '' // (optional) reverse proxy for Cloudflare websites. e.g. example.com
const LOG_LEVEL = 'info' // debug, info, error, none
const TIME_ZONE = 0 // timestamp time zone of logs

const XHTTP_PATH = '/xhttp' // URL path for xhttp protocol, empty means disabled
const XPADDING_RANGE = '100-1000' // Length range of X-Padding response header

const WS_PATH = '/ws' // URL path for ws protocol, empty means disabled

const DOH_QUERY_PATH = '' // URL path for DNS over HTTP(S), e.g. '/doh-query', empty means disabled
const UPSTREAM_DOH = 'https://dns.google/dns-query' // upstream DNS over HTTP(S) server

const IP_QUERY_PATH = '' // URL path for querying client IP information, empty means disabled

// source code
const BUFFER_SIZE = 128 * 1024 // download/upload buffer-size in bytes, must smaller than 1 MiB

const BAD_REQUEST = new Response(null, {
    status: 404,
    statusText: 'Bad Request',
})

function get_length(o) {
    return (o && (o.byteLength || o.length)) || 0
}

function to_size(size) {
    const KiB = 1024
    const min = 1.1 * KiB
    const SIZE_UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
    let i = 0
    for (; i < SIZE_UNITS.length - 1; i++) {
        if (Math.abs(size) < min) {
            break
        }
        size = size / KiB
    }
    const f = size > 0 ? Math.floor : Math.ceil
    return `${f(size)} ${SIZE_UNITS[i]}`
}

function validate_uuid(left, right) {
    for (let i = 0; i < 16; i++) {
        if (left[i] !== right[i]) {
            return false
        }
    }
    return true
}

class Counter {
    #total

    constructor() {
        this.#total = 0
    }

    get() {
        return this.#total
    }

    add(size) {
        this.#total += size
    }
}

function concat_typed_arrays(first, ...args) {
    let len = first.length
    for (let a of args) {
        len += a.length
    }
    const r = new first.constructor(len)
    r.set(first, 0)
    len = first.length
    for (let a of args) {
        r.set(a, len)
        len += a.length
    }
    return r
}

class Logger {
    #id
    #level
    #time_drift

    constructor(log_level, time_zone) {
        this.#id = random_id()
        this.#time_drift = 0
        if (time_zone && time_zone !== 0) {
            this.#time_drift = time_zone * 60 * 60 * 1000
        }

        if (typeof log_level !== 'string') {
            log_level = 'info'
        }
        const levels = ['debug', 'info', 'error', 'none']
        this.#level = levels.indexOf(log_level.toLowerCase())
    }

    debug(...args) {
        if (this.#level < 1) {
            this.#log(`[debug]`, ...args)
        }
    }

    info(...args) {
        if (this.#level < 2) {
            this.#log(`[info ]`, ...args)
        }
    }

    error(...args) {
        if (this.#level < 3) {
            this.#log(`[error]`, ...args)
        }
    }

    #log(prefix, ...args) {
        const now = new Date(Date.now() + this.#time_drift).toISOString()
        console.log(now, prefix, `(${this.#id})`, ...args)
    }
}

function random_num(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min
}

function random_id() {
    const min = 10000
    const max = min * 10 - 1
    return random_num(min, max)
}

// this function only run once per request
function random_padding(range_str) {
    if (!range_str || typeof range_str !== 'string') {
        return null
    }
    const range = range_str
        .split('-')
        .map((s) => parseInt(s))
        .filter((s) => s || s === 0)
        .slice(0, 2)
        .sort((a, b) => a - b)
    // console.log(`range of [${range_str}] is:`, range)
    if (range.length < 1 || range[0] < 1) {
        return null
    }
    const last = range[range.length - 1]
    if (last < 1) {
        return null
    }
    const n = range[0] === last ? range[0] : random_num(range[0], last)
    return '0'.repeat(n)
}

function parse_uuid(uuid) {
    uuid = uuid.replaceAll('-', '')
    const r = []
    for (let index = 0; index < 16; index++) {
        const v = parseInt(uuid.substr(index * 2, 2), 16)
        r.push(v)
    }
    return r
}

async function read_vless_header(reader, cfg_uuid_str) {
    let r = await read_atleast(reader, 1 + 16 + 1)
    let rlen = 0
    let idx = 0
    let cache = r.value
    rlen += r.value.length

    const version = cache[0]
    const uuid = cache.slice(1, 1 + 16)
    const cfg_uuid = parse_uuid(cfg_uuid_str)
    if (!validate_uuid(uuid, cfg_uuid)) {
        throw new Error(`invalid UUID`)
    }
    const pb_len = cache[1 + 16]
    const addr_plus1 = 1 + 16 + 1 + pb_len + 1 + 2 + 1

    if (addr_plus1 + 1 > rlen) {
        if (r.done) {
            throw new Error(`header too short`)
        }
        idx = addr_plus1 + 1 - rlen
        r = await read_atleast(reader, idx)
        rlen += r.value.length
        cache = concat_typed_arrays(cache, r.value)
    }

    const cmd = cache[1 + 16 + 1 + pb_len]
    if (cmd !== 1) {
        throw new Error(`unsupported command: ${cmd}`)
    }
    const port = (cache[addr_plus1 - 1 - 2] << 8) + cache[addr_plus1 - 1 - 1]
    const atype = cache[addr_plus1 - 1]

    const ADDRESS_TYPE_IPV4 = 1
    const ADDRESS_TYPE_URL = 2
    const ADDRESS_TYPE_IPV6 = 3
    let header_len = -1
    if (atype === ADDRESS_TYPE_IPV4) {
        header_len = addr_plus1 + 4
    } else if (atype === ADDRESS_TYPE_IPV6) {
        header_len = addr_plus1 + 16
    } else if (atype === ADDRESS_TYPE_URL) {
        header_len = addr_plus1 + 1 + cache[addr_plus1]
    }

    if (header_len < 0) {
        throw new Error('read address type failed')
    }

    idx = header_len - rlen
    if (idx > 0) {
        if (r.done) {
            throw new Error(`read address failed`)
        }
        r = await read_atleast(reader, idx)
        rlen += r.value.length
        cache = concat_typed_arrays(cache, r.value)
    }

    let hostname = ''
    idx = addr_plus1
    switch (atype) {
        case ADDRESS_TYPE_IPV4:
            hostname = cache.slice(idx, idx + 4).join('.')
            break
        case ADDRESS_TYPE_URL:
            hostname = new TextDecoder().decode(
                cache.slice(idx + 1, idx + 1 + cache[idx]),
            )
            break
        case ADDRESS_TYPE_IPV6:
            hostname = cache
                .slice(idx, idx + 16)
                .reduce(
                    (s, b2, i2, a) =>
                        i2 % 2
                            ? s.concat(((a[i2 - 1] << 8) + b2).toString(16))
                            : s,
                    [],
                )
                .join(':')
            break
    }

    if (hostname.length < 1) {
        throw new Error('parse hostname failed')
    }

    return {
        hostname,
        port,
        data: cache.slice(header_len),
        resp: new Uint8Array([version, 0]),
        reader,
        more: !r.done,
    }
}

async function upload_to_remote(counter, remote_writer, vless) {
    async function inner_upload(d) {
        const len = get_length(d)
        counter.add(len)
        await remote_writer.write(d)
    }

    await inner_upload(vless.data)
    while (vless.more) {
        const r = await vless.reader.read()
        if (r.value) {
            await inner_upload(r.value)
        }
        if (r.done) {
            break
        }
    }
}

function create_uploader(log, vless, remote_writable) {
    const counter = new Counter()
    const done = new Promise((resolve, reject) => {
        const remote_writer = remote_writable.getWriter()
        upload_to_remote(counter, remote_writer, vless)
            .catch(reject)
            .finally(() => remote_writer.close())
            .catch((err) => log.debug(`close upload writer error: ${err}`))
            .finally(resolve)
    })

    return {
        counter,
        done,
    }
}

function create_xhttp_downloader(log, vless, remote_readable) {
    const counter = new Counter()
    let download_buffer_stream

    const done = new Promise((resolve, reject) => {
        download_buffer_stream = new TransformStream(
            {
                start(controller) {
                    log.debug(`download vless response`)
                    counter.add(get_length(vless.resp))
                    controller.enqueue(vless.resp)
                },
                transform(chunk, controller) {
                    const len = get_length(chunk)
                    counter.add(len)
                    controller.enqueue(chunk)
                    // log.debug(`download: ${to_size(len)}`)
                },
                cancel(reason) {
                    reject(reason)
                },
            },
            null,
            new ByteLengthQueuingStrategy({ highWaterMark: BUFFER_SIZE }),
        )
        remote_readable
            .pipeTo(download_buffer_stream.writable)
            .then(resolve)
            .catch(reject)
    })

    return {
        readable: download_buffer_stream.readable,
        counter,
        done,
    }
}

async function connect_remote(log, vless, ...remotes) {
    const hostname = remotes.shift()
    if (!hostname || hostname.length < 1) {
        throw new Error('all attempts failed')
    }

    if (vless.hostname === hostname) {
        log.info(`direct connect [${vless.hostname}]:${vless.port}`)
    } else {
        log.info(
            `proxy [${vless.hostname}]:${vless.port} through [${hostname}]`,
        )
    }

    const retry = () => connect_remote(log, vless, ...remotes)
    try {
        const remote = connect({ hostname: hostname, port: vless.port })
        const info = await remote.opened
        log.debug(`connection opened:`, info.remoteAddress)
        return remote
    } catch (err) {
        log.error(`retry [${vless.hostname}] reason: ${err}`)
    }
    return await retry()
}

async function dial(cfg, log, client_readable) {
    const reader = client_readable.getReader()
    let vless
    try {
        vless = await read_vless_header(reader, cfg.UUID)
    } catch (err) {
        drain_connection(log, reader).catch((err) =>
            log.info(`drain error: ${err}`),
        )
        throw new Error(`read vless header error: ${err.message}`)
    }

    const remote = await connect_remote(log, vless, vless.hostname, cfg.PROXY)
    if (!remote) {
        throw new Error('dial to remote failed')
    }

    return {
        vless,
        remote,
    }
}

async function read_atleast(reader, n) {
    let len = 0
    const buffs = []
    let done = false
    while (len < n && !done) {
        const r = await reader.read()
        if (r.value) {
            const b = new Uint8Array(r.value)
            buffs.push(b)
            len += b ? b.length : 0
        }
        done = r.done
    }
    if (len < n) {
        throw new Error(`not enough data to read`)
    }

    const value = concat_typed_arrays(...buffs)
    return {
        value,
        done,
    }
}

function format_total(upload_counter, download_counter) {
    const upload_total = to_size(upload_counter.get())
    const download_total = to_size(download_counter.get())
    return `upload total: ${upload_total}, download total: ${download_total}`
}

async function handle_xhttp(cfg, log, client_readable) {
    const { vless, remote } = await dial(cfg, log, client_readable)
    const uploader = create_uploader(log, vless, remote.writable)
    const downloader = create_xhttp_downloader(log, vless, remote.readable)

    downloader.done
        .catch((err) => log.error(`xhttp download error: ${err}`))
        .finally(() => uploader.done)
        .catch((err) => log.debug(`xhttp upload error: ${err}`))
        .finally(() =>
            log.info(format_total(uploader.counter, downloader.counter)),
        )

    return downloader.readable
}

function create_ws_client_readable(log, client_ws_server) {
    return new ReadableStream(
        {
            start(controller) {
                client_ws_server.addEventListener('message', ({ data }) => {
                    controller.enqueue(data)
                })
                client_ws_server.addEventListener('error', (err) => {
                    controller.error(err)
                })
                client_ws_server.addEventListener('close', () => {
                    controller.close()
                })
            },
            cancel(reason) {
                log.error(`ws upload error: ${reason}`)
            },
        },
        new ByteLengthQueuingStrategy({ highWaterMark: BUFFER_SIZE }),
    )
}

function create_ws_downloader(log, vless, client_ws_server, remote_readable) {
    const counter = new Counter()
    const done = new Promise((resolve, reject) => {
        const writable = new WritableStream({
            write(chunk) {
                const len = get_length(chunk)
                counter.add(len)
                client_ws_server.send(chunk)
                // log.debug(`download: ${to_size(len)}`)
            },
            abort(reason) {
                log.error(`ws download error: ${reason}`)
            },
        })
        const writer = writable.getWriter()
        writer
            .write(vless.resp)
            .then(() => {
                writer.releaseLock()
                return remote_readable.pipeTo(writable)
            })
            .then(resolve)
            .catch(reject)
    })

    return {
        counter,
        done,
    }
}

async function handle_ws(cfg, log, client_ws_server) {
    client_ws_server.accept()
    const client_readable = create_ws_client_readable(log, client_ws_server)
    const { vless, remote } = await dial(cfg, log, client_readable)
    const uploader = create_uploader(log, vless, remote.writable)
    const downloader = create_ws_downloader(
        log,
        vless,
        client_ws_server,
        remote.readable,
    )

    downloader.done
        .catch((err) => log.error(`ws download error: ${err}`))
        .finally(() => uploader.done)
        .catch((err) => log.error(`ws upload error: ${err}`))
        .finally(() => {
            try {
                client_ws_server.close()
            } catch (err) {
                log.error(`close ws client error: ${err}`)
            }
            log.info(format_total(uploader.counter, downloader.counter))
        })
}

function append_slash(path) {
    if (!path) {
        return '/'
    }
    return path.endsWith('/') ? path : `${path}/`
}

function create_config(ctype, url, uuid) {
    const config = JSON.parse(config_template)
    const vless = config['outbounds'][0]['settings']['vnext'][0]
    const stream = config['outbounds'][0]['streamSettings']

    const host = url.hostname
    vless['users'][0]['id'] = uuid
    vless['address'] = host
    stream['tlsSettings']['serverName'] = host

    const path = append_slash(url.pathname)
    if (ctype === 'ws') {
        stream['wsSettings'] = {
            path,
            host,
        }
    } else if (ctype === 'xhttp') {
        stream['xhttpSettings'] = {
            mode: 'packet-up',
            host,
            path,
            noGRPCHeader: false,
            keepAlivePeriod: 300,
        }
    } else {
        return null
    }

    stream['network'] = ctype
    return config
}

const config_template = `{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "agentin",
      "port": 1080,
      "listen": "127.0.0.1",
      "protocol": "socks",
      "settings": {}
    }
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "localhost",
            "port": 443,
            "users": [
              {
                "id": "",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "tag": "agentout",
      "streamSettings": {
        "network": "raw",
        "security": "tls",
        "tlsSettings": {
          "serverName": "localhost",
          "alpn": [
            "h3"
          ]
        }
      }
    }
  ]
}`

async function drain_connection(log, reader) {
    log.info(`drain connection`)
    while (true) {
        const r = await reader.read()
        if (r.done) {
            break
        }
    }
}

async function handle_doh(log, request, url, upstream) {
    const mime_dnsmsg = 'application/dns-message'
    const method = request.method

    if (
        method === 'POST' &&
        request.headers.get('content-type') === mime_dnsmsg
    ) {
        log.info(`handle DoH POST request`)
        return fetch(upstream, {
            method,
            headers: {
                Accept: mime_dnsmsg,
                'Content-Type': mime_dnsmsg,
            },
            body: request.body,
        })
    }

    if (method !== 'GET') {
        return BAD_REQUEST
    }

    const mime_json = 'application/dns-json'
    if (request.headers.get('Accept') === mime_json) {
        log.info(`handle DoH GET json request`)
        return fetch(upstream + url.search, {
            method,
            headers: {
                Accept: mime_json,
            },
        })
    }

    const param = url.searchParams.get('dns')
    if (param && typeof param === 'string') {
        log.info(`handle DoH GET hex request`)
        return fetch(upstream + '?dns=' + param, {
            method,
            headers: {
                Accept: mime_dnsmsg,
            },
        })
    }

    return BAD_REQUEST
}

function get_ip_info(request) {
    const info = {
        ip: request.headers.get('cf-connecting-ip') || '',
        userAgent: request.headers.get('user-agent') || '',
    }

    const keys = [
        'asOrganization',
        'city',
        'continent',
        'country',
        'latitude',
        'longitude',
        'region',
        'regionCode',
        'timezone',
    ]

    const transforms = { asOrganization: 'organization' }
    for (let key of keys) {
        const tkey = transforms[key]
        info[tkey || key] = request.cf[key] || ''
    }
    return info
}

function handle_json(cfg, url, request) {
    if (cfg.IP_QUERY_PATH && request.url.endsWith(cfg.IP_QUERY_PATH)) {
        return get_ip_info(request)
    }

    const path = append_slash(url.pathname)
    if (url.searchParams.get('uuid') === cfg.UUID) {
        if (cfg.XHTTP_PATH && path.endsWith(cfg.XHTTP_PATH)) {
            return create_config('xhttp', url, cfg.UUID)
        }
        if (cfg.WS_PATH && path.endsWith(cfg.WS_PATH)) {
            return create_config('ws', url, cfg.UUID)
        }
    }
    return null
}

function load_settings(env) {
    const cfg = {
        UUID: env.UUID || UUID,
        PROXY: env.PROXY || PROXY,
        LOG_LEVEL: env.LOG_LEVEL || LOG_LEVEL,
        TIME_ZONE: parseInt(env.TIME_ZONE) || TIME_ZONE,

        XHTTP_PATH: env.XHTTP_PATH || XHTTP_PATH,
        WS_PATH: env.WS_PATH || WS_PATH,

        DOH_QUERY_PATH: env.DOH_QUERY_PATH || DOH_QUERY_PATH,
        UPSTREAM_DOH: env.UPSTREAM_DOH || UPSTREAM_DOH,

        // do not append slash
        IP_QUERY_PATH: env.IP_QUERY_PATH || IP_QUERY_PATH,

        XPADDING_RANGE: env.XPADDING_RANGE || XPADDING_RANGE,
    }

    const features = ['XHTTP_PATH', 'WS_PATH', 'DOH_QUERY_PATH']
    for (let feature of features) {
        cfg[feature] = cfg[feature] && append_slash(cfg[feature])
    }
    return cfg
}

async function main(request, env) {
    const cfg = load_settings(env)
    if (!cfg.UUID) {
        return new Response(`Error: UUID is empty`)
    }

    const log = new Logger(cfg.LOG_LEVEL, cfg.TIME_ZONE)
    const url = new URL(request.url)
    const path = url.pathname

    if (
        cfg.WS_PATH &&
        request.headers.get('Upgrade') === 'websocket' &&
        path.endsWith(cfg.WS_PATH)
    ) {
        const [client, server] = Object.values(new WebSocketPair())
        // Do not block here. Client is waiting for upgrade-reponse.
        handle_ws(cfg, log, server).catch((err) =>
            log.error(`handle ws client error: ${err}`),
        )
        return new Response(null, {
            status: 101,
            webSocket: client,
        })
    }

    if (
        cfg.XHTTP_PATH &&
        request.method === 'POST' &&
        path.endsWith(cfg.XHTTP_PATH)
    ) {
        try {
            const readable = await handle_xhttp(cfg, log, request.body)
            const headers = {
                'X-Accel-Buffering': 'no',
                'Cache-Control': 'no-store',
                Connection: 'Keep-Alive',
                'User-Agent': 'Go-http-client/2.0',
                'Content-Type': 'application/grpc',
                // 'Content-Type': 'text/event-stream',
                // 'Transfer-Encoding': 'chunked',
            }
            const padding = random_padding(cfg.XPADDING_RANGE)
            if (padding) {
                headers['X-Padding'] = padding
            }
            return new Response(readable, { headers })
        } catch (err) {
            log.error(`handle xhttp error: ${err}`)
        }
        return BAD_REQUEST
    }

    if (cfg.DOH_QUERY_PATH && append_slash(path).endsWith(cfg.DOH_QUERY_PATH)) {
        return handle_doh(log, request, url, cfg.UPSTREAM_DOH)
    }

    if (request.method === 'GET' && !request.headers.get('Upgrade')) {
        const o = handle_json(cfg, url, request)
        if (o) {
            return new Response(JSON.stringify(o), {
                headers: {
                    'Content-Type': 'application/json',
                },
            })
        }
        return new Response(`Hello world!`)
    }

    return BAD_REQUEST
}

export default {
    fetch: main,

    // for unit testing
    concat_typed_arrays,
    get_length,
    parse_uuid,
    random_id,
    random_padding,
    to_size,
    validate_uuid,
}
