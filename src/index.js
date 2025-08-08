import { connect } from 'cloudflare:sockets'

// ===================
// Config (env overrides supported)
// ===================
const UUID = ''                 // vless UUID (обязательно)
const PROXY = ''                // опциональный reverse proxy-хост для исходящих
const LOG_LEVEL = 'info'        // debug, info, error, none
const TIME_ZONE = 0             // смещение для timestamps (часов)
const GRPC_SERVICE = 'grpc'     // gRPC serviceName, клиент пойдёт на /{service}/Tun

const DOH_QUERY_PATH = ''       // напр. '/doh-query' — пусто = выключено
const UPSTREAM_DOH = 'https://dns.google/dns-query'

const IP_QUERY_PATH = ''        // напр. '/ip', пусто = выключено

// ===================
// Consts
// ===================
const BUFFER_SIZE = 128 * 1024 // буфер <= 1 MiB (ограничение Workers)
const BAD_REQUEST = new Response('Bad Request', { status: 404 })

// ===================
// Utils
// ===================
function get_length(o) {
  return (o && (o.byteLength || o.length)) || 0
}
function to_size(size) {
  const KiB = 1024
  const min = 1.1 * KiB
  const SIZE_UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let i = 0
  for (; i < SIZE_UNITS.length - 1; i++) {
    if (Math.abs(size) < min) break
    size = size / KiB
  }
  const f = size > 0 ? Math.floor : Math.ceil
  return `${f(size)} ${SIZE_UNITS[i]}`
}
function random_num(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min
}
function random_id() {
  const min = 10000
  const max = min * 10 - 1
  return random_num(min, max)
}
class Counter {
  #total = 0
  get() { return this.#total }
  add(n) { this.#total += n }
}
function concat_typed_arrays(first, ...args) {
  let len = first.length
  for (let a of args) len += a.length
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
    if (time_zone && time_zone !== 0) this.#time_drift = time_zone * 3600 * 1000
    if (typeof log_level !== 'string') log_level = 'info'
    const levels = ['debug', 'info', 'error', 'none']
    this.#level = levels.indexOf(log_level.toLowerCase())
  }
  debug(...args) { if (this.#level < 1) this.#log('[debug]', ...args) }
  info(...args)  { if (this.#level < 2) this.#log('[info ]', ...args) }
  error(...args) { if (this.#level < 3) this.#log('[error]', ...args) }
  #log(prefix, ...args) {
    const now = new Date(Date.now() + this.#time_drift).toISOString()
    console.log(now, prefix, `(${this.#id})`, ...args)
  }
}
// ===================
// VLESS helpers
// ===================
function validate_uuid(left, right) {
  for (let i = 0; i < 16; i++) { if (left[i] !== right[i]) return false }
  return true
}
function parse_uuid(uuid) {
  uuid = uuid.replaceAll('-', '')
  const r = []
  for (let i = 0; i < 16; i++) r.push(parseInt(uuid.substr(i * 2, 2), 16))
  return r
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
      len += b.length
    }
    done = r.done
  }
  if (len < n) throw new Error('not enough data to read')
  const value = concat_typed_arrays(...buffs)
  return { value, done }
}
async function read_vless_header(reader, cfg_uuid_str) {
  // version(1) + uuid(16) + optLen(1)
  let r = await read_atleast(reader, 1 + 16 + 1)
  let rlen = 0
  let cache = r.value
  rlen += cache.length

  const version = cache[0]
  const uuid = cache.slice(1, 17)
  const cfg_uuid = parse_uuid(cfg_uuid_str)
  if (!validate_uuid(uuid, cfg_uuid)) throw new Error('invalid UUID')

  const pb_len = cache[17]
  const addr_plus1 = 1 + 16 + 1 + pb_len + 1 + 2 + 1 // +cmd(1)+port(2)+atype(1)

  if (addr_plus1 + 1 > rlen) {
    if (r.done) throw new Error('header too short')
    const need = addr_plus1 + 1 - rlen
    r = await read_atleast(reader, need)
    rlen += r.value.length
    cache = concat_typed_arrays(cache, r.value)
  }

  const cmd = cache[1 + 16 + 1 + pb_len] // 1=tcp
  if (cmd !== 1) throw new Error(`unsupported command: ${cmd}`)
  const port = (cache[addr_plus1 - 3] << 8) + cache[addr_plus1 - 2]
  const atype = cache[addr_plus1 - 1]

  const ADDRESS_TYPE_IPV4 = 1
  const ADDRESS_TYPE_URL = 2
  const ADDRESS_TYPE_IPV6 = 3

  let header_len = -1
  if (atype === ADDRESS_TYPE_IPV4) header_len = addr_plus1 + 4
  else if (atype === ADDRESS_TYPE_IPV6) header_len = addr_plus1 + 16
  else if (atype === ADDRESS_TYPE_URL) header_len = addr_plus1 + 1 + cache[addr_plus1]

  if (header_len < 0) throw new Error('read address type failed')

  const need2 = header_len - rlen
  if (need2 > 0) {
    if (r.done) throw new Error('read address failed')
    r = await read_atleast(reader, need2)
    rlen += r.value.length
    cache = concat_typed_arrays(cache, r.value)
  }

  let hostname = ''
  let idx = addr_plus1
  switch (atype) {
    case ADDRESS_TYPE_IPV4:
      hostname = cache.slice(idx, idx + 4).join('.'); break
    case ADDRESS_TYPE_URL:
      hostname = new TextDecoder().decode(cache.slice(idx + 1, idx + 1 + cache[idx])); break
    case ADDRESS_TYPE_IPV6:
      hostname = cache.slice(idx, idx + 16).reduce(
        (s, b2, i2, a) => i2 % 2 ? s.concat(((a[i2 - 1] << 8) + b2).toString(16)) : s, []
      ).join(':')
      break
  }
  if (!hostname) throw new Error('parse hostname failed')

  return {
    hostname,
    port,
    data: cache.slice(header_len),
    resp: new Uint8Array([version, 0]),
    reader,
    more: !r.done,
  }
}

// ===================
// gRPC framing helpers
// ===================
// Разворачиваем gRPC-stream (application/grpc) в сырой байтовый поток (payload)
function grpcBodyToRawPayloadStream(body, log) {
  if (!body) throw new Error('empty gRPC body')
  const reader = body.getReader()
  let cache = new Uint8Array(0)

  async function readExactly(n) {
    while (cache.length < n) {
      const r = await reader.read()
      if (r.done) {
        return cache.length === 0 ? null : (() => { throw new Error('unexpected EOF') })()
      }
      const chunk = new Uint8Array(r.value)
      cache = cache.length === 0 ? chunk : concat_typed_arrays(cache, chunk)
    }
    const out = cache.slice(0, n)
    cache = cache.slice(n)
    return out
  }

  return new ReadableStream(
    {
      async start(controller) {
        try {
          while (true) {
            const hdr = await readExactly(5)
            if (!hdr) break
            const compressed = hdr[0]
            const len = (hdr[1] << 24) | (hdr[2] << 16) | (hdr[3] << 8) | hdr[4]
            if (compressed !== 0) throw new Error('grpc compressed messages not supported')
            if (len === 0) continue
            const payload = await readExactly(len)
            if (!payload) throw new Error('unexpected EOF in payload')
            controller.enqueue(payload)
          }
        } catch (err) {
          log.error(`grpc decode error: ${err}`)
          controller.error(err)
          return
        }
        controller.close()
      },
      cancel(reason) { log.debug(`grpc payload stream canceled: ${reason}`) },
    },
    new ByteLengthQueuingStrategy({ highWaterMark: BUFFER_SIZE }),
  )
}

// Упаковываем сырой поток (VLESS resp + данные) обратно в gRPC-кадры
function create_grpc_downloader(log, vless, remote_readable) {
  const counter = new Counter()
  const transformer = new TransformStream(
    {
      transform(chunk, controller) {
        const len = get_length(chunk)
        counter.add(len)
        // gRPC data frame: 1 byte flags + 4 bytes len (BE) + payload
        const header = new Uint8Array(5)
        header[0] = 0 // uncompressed
        header[1] = (len >>> 24) & 0xff
        header[2] = (len >>> 16) & 0xff
        header[3] = (len >>> 8) & 0xff
        header[4] = len & 0xff
        controller.enqueue(header)
        controller.enqueue(chunk)
      },
    },
    new ByteLengthQueuingStrategy({ highWaterMark: BUFFER_SIZE }),
    new ByteLengthQueuingStrategy({ highWaterMark: BUFFER_SIZE }),
  )

  const done = (async () => {
    const writer = transformer.writable.getWriter()
    try {
      // первым кадром отдадим VLESS-ответ [ver,0]
      await writer.write(vless.resp)
      writer.releaseLock()
      return remote_readable.pipeTo(transformer.writable)
    } catch (err) {
      log.error(`grpc download pipe error: ${err}`)
      throw err
    }
  })()

  return {
    readable: transformer.readable,
    counter,
    done,
  }
}

// ===================
// TCP dial/proxy
// ===================
async function upload_to_remote(counter, remote_writer, vless) {
  async function inner_upload(d) {
    const len = get_length(d)
    counter.add(len)
    await remote_writer.write(d)
  }
  // сначала — хвост данных, оставшийся после заголовка VLESS
  await inner_upload(vless.data)
  // далее — весь оставшийся поток клиента
  while (vless.more) {
    const r = await vless.reader.read()
    if (r.value) await inner_upload(r.value)
    if (r.done) break
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
  return { counter, done }
}
async function connect_remote(log, vless, ...remotes) {
  const hostname = remotes.shift()
  if (!hostname || hostname.length < 1) throw new Error('all attempts failed')

  if (vless.hostname === hostname) log.info(`direct connect [${vless.hostname}]:${vless.port}`)
  else log.info(`proxy [${vless.hostname}]:${vless.port} through [${hostname}]`)

  try {
    const remote = connect({ hostname, port: vless.port })
    const info = await remote.opened
    log.debug(`connection opened:`, info.remoteAddress)
    return remote
  } catch (err) {
    log.error(`retry [${vless.hostname}] reason: ${err}`)
    return await connect_remote(log, vless, ...remotes)
  }
}
async function dial(cfg, log, client_readable) {
  const reader = client_readable.getReader()
  let vless
  try {
    vless = await read_vless_header(reader, cfg.UUID)
  } catch (err) {
    drain_connection(log, reader).catch((e) => log.info(`drain error: ${e}`))
    throw new Error(`read vless header error: ${err.message}`)
  }
  const remote = await connect_remote(log, vless, vless.hostname, cfg.PROXY)
  if (!remote) throw new Error('dial to remote failed')
  return { vless, remote }
}
async function drain_connection(log, reader) {
  log.info(`drain connection`)
  while (true) {
    const r = await reader.read()
    if (r.done) break
  }
}

// ===================
// DoH / helpers
// ===================
async function handle_doh(log, request, url, upstream) {
  const mime_dnsmsg = 'application/dns-message'
  const method = request.method
  if (method === 'POST' && request.headers.get('content-type') === mime_dnsmsg) {
    log.info(`handle DoH POST`)
    return fetch(upstream, {
      method,
      headers: { Accept: mime_dnsmsg, 'Content-Type': mime_dnsmsg },
      body: request.body,
    })
  }
  if (method !== 'GET') return BAD_REQUEST

  const mime_json = 'application/dns-json'
  if (request.headers.get('Accept') === mime_json) {
    log.info(`handle DoH GET json`)
    return fetch(upstream + url.search, { method, headers: { Accept: mime_json } })
  }
  const param = url.searchParams.get('dns')
  if (param && typeof param === 'string') {
    log.info(`handle DoH GET hex`)
    return fetch(upstream + '?dns=' + param, { method, headers: { Accept: mime_dnsmsg } })
  }
  return BAD_REQUEST
}
function get_ip_info(request) {
  const info = {
    ip: request.headers.get('cf-connecting-ip') || '',
    userAgent: request.headers.get('user-agent') || '',
  }
  const keys = ['asOrganization', 'city', 'continent', 'country', 'latitude', 'longitude', 'region', 'regionCode', 'timezone']
  const transforms = { asOrganization: 'organization' }
  for (let key of keys) {
    const tkey = transforms[key]
    info[tkey || key] = (request.cf && request.cf[key]) || ''
  }
  return info
}

// ===================
// Config generator (client JSON)
// ===================
function append_slash(path) {
  if (!path) return '/'
  return path.endsWith('/') ? path : `${path}/`
}
function create_config_grpc(url, uuid, serviceName) {
  const config = JSON.parse(config_template)
  const vless = config['outbounds'][0]['settings']['vnext'][0]
  const stream = config['outbounds'][0]['streamSettings']

  const host = url.hostname
  vless['users'][0]['id'] = uuid
  vless['address'] = host
  stream['tlsSettings']['serverName'] = host

  stream['network'] = 'grpc'
  stream['grpcSettings'] = {
    serviceName,
    multiMode: true
  }
  return config
}
const config_template = `{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "tag": "agentin", "port": 1080, "listen": "127.0.0.1", "protocol": "socks", "settings": {} }
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          { "address": "localhost", "port": 443,
            "users": [ { "id": "", "encryption": "none" } ]
          }
        ]
      },
      "tag": "agentout",
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "serverName": "localhost",
          "alpn": ["h2"]
        },
        "grpcSettings": {
          "serviceName": "grpc",
          "multiMode": true
        }
      }
    }
  ]
}`

function handle_json(cfg, url, request) {
  // /ip endpoint
  if (cfg.IP_QUERY_PATH && request.url.endsWith(cfg.IP_QUERY_PATH)) {
    return get_ip_info(request)
  }
  // /config?uuid=<UUID> — вернуть клиентскую конфигурацию для gRPC
  if (url.searchParams.get('uuid') === cfg.UUID) {
    return create_config_grpc(url, cfg.UUID, cfg.GRPC_SERVICE)
  }
  return null
}

// ===================
// gRPC handler (VLESS over gRPC)
// ===================
function is_grpc_request(request, cfg, url) {
  const ct = request.headers.get('content-type') || ''
  // Xray обычно дергает: POST /{service}/Tun с Content-Type: application/grpc
  const path = url.pathname || '/'
  const wantPrefix = '/' + (cfg.GRPC_SERVICE || 'grpc')
  return request.method === 'POST'
    && ct.includes('application/grpc')
    && path.startsWith(wantPrefix)
}
async function handle_grpc(cfg, log, request) {
  // Разобрать gRPC-стрим в сырой поток
  const client_payload_stream = grpcBodyToRawPayloadStream(request.body, log)

  // Прочитать VLESS-заголовок и соединиться
  const { vless, remote } = await dial(cfg, log, client_payload_stream)

  // Старт отправки клиентских данных на remote
  const uploader = create_uploader(log, vless, remote.writable)

  // Скачивание из remote -> в gRPC-ответ
  const downloader = create_grpc_downloader(log, vless, remote.readable)

  // Логика закрытия/логгирования
  downloader.done
    .catch((err) => log.error(`grpc download error: ${err}`))
    .finally(() => uploader.done)
    .catch((err) => log.error(`grpc upload error: ${err}`))
    .finally(() => log.info(`done: upload ${to_size(uploader.counter.get())}, download ${to_size(downloader.counter.get())}`))

  // Ответ в формате gRPC
  // Примечание: многие клиенты (включая Xray) принимают отсутствие трейлеров,
  // но мы отдадим корректные gRPC-заголовки. Cloudflare может сам добавить grpc-status.
  const headers = new Headers({
    'content-type': 'application/grpc',
    'grpc-encoding': 'identity',
    'grpc-accept-encoding': 'identity, gzip',
    'x-content-type-options': 'nosniff',
    // 'trailer': 'grpc-status, grpc-message' // (Workers могут выставлять трейлеры; если не требуется — можно опустить)
  })
  return new Response(downloader.readable, { status: 200, headers })
}

// ===================
// Settings loader & main
// ===================
function load_settings(env) {
  const cfg = {
    UUID: env?.UUID || UUID,
    PROXY: env?.PROXY || PROXY,
    LOG_LEVEL: env?.LOG_LEVEL || LOG_LEVEL,
    TIME_ZONE: parseInt(env?.TIME_ZONE) || TIME_ZONE,

    GRPC_SERVICE: env?.GRPC_SERVICE || GRPC_SERVICE,

    DOH_QUERY_PATH: env?.DOH_QUERY_PATH || DOH_QUERY_PATH,
    UPSTREAM_DOH: env?.UPSTREAM_DOH || UPSTREAM_DOH,

    IP_QUERY_PATH: env?.IP_QUERY_PATH || IP_QUERY_PATH,
  }
  return cfg
}
async function main(request, env) {
  const cfg = load_settings(env)
  if (!cfg.UUID) return new Response('Error: UUID is empty', { status: 500 })

  const log = new Logger(cfg.LOG_LEVEL, cfg.TIME_ZONE)
  const url = new URL(request.url)

  // gRPC VLESS
  if (is_grpc_request(request, cfg, url)) {
    try {
      return await handle_grpc(cfg, log, request)
    } catch (err) {
      log.error(`handle grpc error: ${err.stack || err}`)
      return new Response('gRPC internal error', { status: 500 })
    }
  }

  // DoH
  if (cfg.DOH_QUERY_PATH && url.pathname.startsWith(cfg.DOH_QUERY_PATH)) {
    return handle_doh(log, request, url, cfg.UPSTREAM_DOH)
  }

  // JSON endpoints (/ip, /config?uuid=...)
  if (request.method === 'GET') {
    const j = handle_json(cfg, url, request)
    if (j) return Response.json(j)
  }

  // Простой health/описание
  if (request.method === 'GET') {
    const info = {
      ok: true,
      grpcService: cfg.GRPC_SERVICE,
      tips: 'POST application/grpc to /' + cfg.GRPC_SERVICE + '/Tun',
      doh: cfg.DOH_QUERY_PATH || '',
      ipInfo: cfg.IP_QUERY_PATH || '',
      uuidSet: !!cfg.UUID,
    }
    return Response.json(info)
  }

  return BAD_REQUEST
}

export default {
  async fetch(request, env, ctx) {
    return main(request, env)
  },
	   }
