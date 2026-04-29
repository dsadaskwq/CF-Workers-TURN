import { connect } from 'cloudflare:sockets';
const uuid = '2523c510-9ff0-415b-9582-93949bfae7e3', maxED = 8192;
export default { fetch: req => req.headers.get('Upgrade') === 'websocket' ? ws(req) : new Response('ok') };
const idB = Uint8Array.fromHex(uuid.replaceAll('-', '')), dec = new TextDecoder(), enc = s => new TextEncoder().encode(s);
const addr = (t, b) => t === 3 ? dec.decode(b) : t === 1 ? `${b[0]}.${b[1]}.${b[2]}.${b[3]}` : `[${Array.from({ length: 8 }, (_, i) => ((b[i * 2] << 8) | b[i * 2 + 1]).toString(16)).join(':')}]`;
const parseAddr = (b, o, t) => { const l = t === 3 ? b[o++] : t === 1 ? 4 : t === 4 ? 16 : 0; return l && o + l <= b.length ? { addrBytes: b.subarray(o, o + l), dataOffset: o + l } : null; };
const vless = c => { for (let i = 0; i < 16; i++) if (c[i + 1] !== idB[i]) return null; const o = 19 + c[17], p = (c[o] << 8) | c[o + 1], t = c[o + 2] === 1 ? 1 : c[o + 2] + 1, a = parseAddr(c, o + 3, t); return a ? { addrType: t, ...a, port: p } : null; };
const relay = async (rd, send, close) => { try { for (;;) { const { done, value } = await rd.read(); if (done) break; value?.byteLength && send(value); } } catch {} finally { rd.releaseLock(); close(); } };
const MAGIC = new Uint8Array([0x21, 0x12, 0xA4, 0x42]);
const MT = { AQ: 0x003, AO: 0x103, AE: 0x113, PQ: 0x008, PO: 0x108, CQ: 0x00A, CO: 0x10A, BQ: 0x00B, BO: 0x10B };
const AT = { USER: 0x006, MI: 0x008, ERR: 0x009, PEER: 0x012, REALM: 0x014, NONCE: 0x015, TRANSPORT: 0x019, CONNID: 0x02A };
const cat = (...a) => { const r = new Uint8Array(a.reduce((s, x) => s + x.length, 0)); a.reduce((o, x) => (r.set(x, o), o + x.length), 0); return r; };
const stunAttr = (t, v) => { const b = new Uint8Array(4 + v.length + (4 - v.length % 4) % 4), d = new DataView(b.buffer); d.setUint16(0, t); d.setUint16(2, v.length); b.set(v, 4); return b; };
const stunMsg = (t, tid, a) => { const bd = cat(...a), h = new Uint8Array(20), d = new DataView(h.buffer); d.setUint16(0, t); d.setUint16(2, bd.length); h.set(MAGIC, 4); h.set(tid, 8); return cat(h, bd); };
const xorPeer = (ip, port) => { const b = new Uint8Array(8); b[1] = 1; new DataView(b.buffer).setUint16(2, port ^ 0x2112); ip.split('.').forEach((v, i) => b[4 + i] = +v ^ MAGIC[i]); return b; };
const parseStun = d => {
  if (d.length < 20 || MAGIC.some((v, i) => d[4 + i] !== v)) return null;
  const dv = new DataView(d.buffer, d.byteOffset, d.byteLength), ml = dv.getUint16(2), attrs = {};
  for (let o = 20; o + 4 <= 20 + ml; ) { const t = dv.getUint16(o), l = dv.getUint16(o + 2); if (o + 4 + l > d.length) break; attrs[t] = d.slice(o + 4, o + 4 + l); o += 4 + l + (4 - l % 4) % 4; }
  return { type: dv.getUint16(0), attrs };
};
const parseErr = d => d?.length >= 4 ? (d[2] & 7) * 100 + d[3] : 0;
const addIntegrity = async (m, key) => { const c = new Uint8Array(m), d = new DataView(c.buffer); d.setUint16(2, d.getUint16(2) + 24); const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']); return cat(c, stunAttr(AT.MI, new Uint8Array(await crypto.subtle.sign('HMAC', k, c)))); };
const readStun = async (rd, buf) => {
  let b = buf ?? new Uint8Array(0); const pull = async () => { const { done, value } = await rd.read(); if (done) throw 0; b = cat(b, new Uint8Array(value)); };
  try { while (b.length < 20) await pull(); const n = 20 + (b[2] << 8 | b[3]); while (b.length < n) await pull();
    return [parseStun(b.subarray(0, n)), b.length > n ? b.subarray(n) : null]; } catch { return [null, null]; }
};
const resolveIP = async h => /^\d+\.\d+\.\d+\.\d+$/.test(h) ? h : (await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(h)}&type=A`, { headers: { Accept: 'application/dns-json' } }).then(r => r.json()).catch(() => ({}))).Answer?.find(a => a.type === 1)?.data ?? null;
const md5 = async s => new Uint8Array(await crypto.subtle.digest('MD5', enc(s)));
const getTurn = url => { const m = decodeURIComponent(url).match(/\/turn:\/\/([^?&#\s]*)/i); if (!m) return null; const t = m[1], at = t.lastIndexOf('@'), cred = at >= 0 ? t.slice(0, at) : '', hp = t.slice(at + 1), [host, p] = hp.split(':'), ci = cred.indexOf(':'); return p ? { host, port: +p, user: ci >= 0 ? cred.slice(0, ci) : '', pass: ci >= 0 ? cred.slice(ci + 1) : '' } : null; };
const turnConn = async ({ host, port, user, pass }, targetIp, targetPort) => {
  let ctrl = null, data = null;
  const close = () => [ctrl, data].forEach(s => { try { s?.close(); } catch {} });
  try {
    ctrl = connect({ hostname: host, port }); await ctrl.opened;
    const cw = ctrl.writable.getWriter(), cr = ctrl.readable.getReader(), tid = () => crypto.getRandomValues(new Uint8Array(12)), tp = new Uint8Array([6, 0, 0, 0]);
    await cw.write(stunMsg(MT.AQ, tid(), [stunAttr(AT.TRANSPORT, tp)]));
    let [r, ex] = await readStun(cr); if (!r) { close(); return null; }
    let key = null, aa = [];
    const sign = m => key ? addIntegrity(m, key) : m, peer = stunAttr(AT.PEER, xorPeer(targetIp, targetPort));
    if (r.type === MT.AE && user && parseErr(r.attrs[AT.ERR]) === 401) {
      const realm = dec.decode(r.attrs[AT.REALM] ?? new Uint8Array(0)), nonce = r.attrs[AT.NONCE] ?? new Uint8Array(0);
      key = await md5(`${user}:${realm}:${pass}`);
      aa = [stunAttr(AT.USER, enc(user)), stunAttr(AT.REALM, enc(realm)), stunAttr(AT.NONCE, nonce)];
      const [am, pm, cm] = await Promise.all([sign(stunMsg(MT.AQ, tid(), [stunAttr(AT.TRANSPORT, tp), ...aa])), sign(stunMsg(MT.PQ, tid(), [peer, ...aa])), sign(stunMsg(MT.CQ, tid(), [peer, ...aa]))]);
      await cw.write(cat(am, pm, cm)); data = connect({ hostname: host, port });
      [r, ex] = await readStun(cr, ex); if (r?.type !== MT.AO) { close(); return null; }
    } else if (r.type === MT.AO) {
      const [pm, cm] = await Promise.all([sign(stunMsg(MT.PQ, tid(), [peer, ...aa])), sign(stunMsg(MT.CQ, tid(), [peer, ...aa]))]);
      await cw.write(cat(pm, cm)); data = connect({ hostname: host, port });
    } else { close(); return null; }
    [r, ex] = await readStun(cr, ex); if (r?.type !== MT.PO) { close(); return null; }
    [r, ex] = await readStun(cr, ex); if (r?.type !== MT.CO || !r.attrs[AT.CONNID]) { close(); return null; }
    await data.opened; const dw = data.writable.getWriter(), dr = data.readable.getReader();
    await dw.write(await sign(stunMsg(MT.BQ, tid(), [stunAttr(AT.CONNID, r.attrs[AT.CONNID]), ...aa])));
    let extra; [r, extra] = await readStun(dr); if (r?.type !== MT.BO) { close(); return null; }
    cr.releaseLock(); cw.releaseLock(); dw.releaseLock();
    const readable = new ReadableStream({ start: c => extra?.length && c.enqueue(extra), pull: c => dr.read().then(({ done, value }) => done ? c.close() : c.enqueue(new Uint8Array(value))), cancel: () => dr.cancel() });
    return { readable, writable: data.writable, close };
  } catch { close(); return null; }
};
const ws = async req => {
  const [client, server] = Object.values(new WebSocketPair()); server.accept();
  const ed = req.headers.get('sec-websocket-protocol'), turn = getTurn(req.url);
  let w = null, sock = null, chain = Promise.resolve();
  const close = () => { try { sock?.close(); } catch {} try { server.close(); } catch {} }, send = d => { try { server.send(d); } catch {} };
  const process = async chunk => {
    if (w) return w.write(chunk);
    const v = vless(chunk); if (!v) return close(); send(new Uint8Array([chunk[0], 0]));
    const { addrType, addrBytes, dataOffset, port } = v, host = addr(addrType, addrBytes), payload = chunk.subarray(dataOffset);
    if (!turn) return close();
    const ip = addrType === 1 ? host : await resolveIP(host); if (!ip) return close();
    sock = await turnConn(turn, ip, port).catch(() => null); if (!sock) return close();
    w = sock.writable.getWriter(); payload.byteLength && await w.write(payload); relay(sock.readable.getReader(), send, close);
  };
  if (ed?.length <= maxED) chain = chain.then(() => process(Uint8Array.fromBase64(ed, { alphabet: 'base64url' }))).catch(close);
  server.addEventListener('message', e => { chain = chain.then(() => process(new Uint8Array(e.data instanceof ArrayBuffer ? e.data : e.data.buffer ?? e.data))).catch(close); });
  server.addEventListener('close', close); server.addEventListener('error', close);
  return new Response(null, { status: 101, webSocket: client, headers: ed ? { 'sec-websocket-protocol': ed } : {} });
};