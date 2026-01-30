const os = require('os');
const http = require('http');
const fs = require('fs');
const axios = require('axios');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { Buffer } = require('buffer');
const { exec, execSync } = require('child_process');
const { WebSocket, createWebSocketStream } = require('ws');

// 环境变量配置
const UUID = process.env.UUID || '5efabea4-f6d4-91fd-b8f0-17e004c89c60';
const DOMAIN = process.env.DOMAIN || '1234.abc.com'; 
const AUTO_ACCESS = process.env.AUTO_ACCESS || true;
const WSPATH = process.env.WSPATH || UUID.slice(0, 8);
const SUB_PATH = process.env.SUB_PATH || 'sub';
const NAME = process.env.NAME || '';
const PORT = process.env.PORT || 7860;

// --- Komari 监控配置 (优先从环境变量读取) ---
const KOMARI_SERVER = process.env.KOMARI_SERVER || 'https://komari.afnos86.xx.kg';
const KOMARI_TOKEN = process.env.KOMARI_TOKEN || 'uY3P0E6F5iqmYrOq6Oo7PM';
// ---------------------------------------

let ISP = '';
const GetISP = async () => {
  try {
    const res = await axios.get('https://api.ip.sb/geoip');
    const data = res.data;
    ISP = `${data.country_code}-${data.isp}`.replace(/ /g, '_');
  } catch (e) {
    ISP = 'Unknown';
  }
}
GetISP();

// HTTP 服务器
const httpServer = http.createServer((req, res) => {
  if (req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('Server is running');
    return;
  } else if (req.url === `/${SUB_PATH}`) {
    const namePart = NAME ? `${NAME}-${ISP}` : ISP;
    const vlessURL = `vless://${UUID}@${DOMAIN}:443?encryption=none&security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F${WSPATH}#${namePart}`;
    const trojanURL = `trojan://${UUID}@${DOMAIN}:443?security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F${WSPATH}#${namePart}`;
    const subscription = vlessURL + '\n' + trojanURL;
    const base64Content = Buffer.from(subscription).toString('base64');
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(base64Content + '\n');
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found\n');
  }
});

const wss = new WebSocket.Server({ server: httpServer });
const uuid = UUID.replace(/-/g, "");

// DNS 解析
function resolveHost(host) {
  return new Promise((resolve, reject) => {
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(host)) {
      resolve(host);
      return;
    }
    const dnsQuery = `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`;
    axios.get(dnsQuery, { timeout: 5000 }).then(response => {
      if (response.data.Status === 0 && response.data.Answer) {
        const ip = response.data.Answer.find(record => record.type === 1);
        if (ip) resolve(ip.data); else reject();
      } else reject();
    }).catch(() => reject());
  });
}

// VLESS & Trojan 处理逻辑
function handleVlessConnection(ws, msg) {
  const [VERSION] = msg;
  const id = msg.slice(1, 17);
  if (!id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16))) return false;
  let i = msg.slice(17, 18).readUInt8() + 19;
  const port = msg.slice(i, i += 2).readUInt16BE(0);
  const ATYP = msg.slice(i, i += 1).readUInt8();
  const host = ATYP == 1 ? msg.slice(i, i += 4).join('.') :
    (ATYP == 2 ? new TextDecoder().decode(msg.slice(i + 1, i += 1 + msg.slice(i, i + 1).readUInt8())) :
    (ATYP == 3 ? msg.slice(i, i += 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':') : ''));
  ws.send(new Uint8Array([VERSION, 0]));
  const duplex = createWebSocketStream(ws);
  resolveHost(host).then(ip => {
    net.connect({ host: ip, port }, function() { this.write(msg.slice(i)); duplex.pipe(this).pipe(duplex); });
  }).catch(() => {
    net.connect({ host, port }, function() { this.write(msg.slice(i)); duplex.pipe(this).pipe(duplex); });
  });
  return true;
}

function handleTrojanConnection(ws, msg) {
  const receivedHash = msg.slice(0, 56).toString();
  const expectedHash = crypto.createHash('sha224').update(UUID).digest('hex');
  if (receivedHash !== expectedHash) return false;
  let offset = msg[56] === 0x0d ? 58 : 56;
  const cmd = msg[offset++];
  if (cmd !== 0x01) return false;
  const atyp = msg[offset++];
  let host;
  if (atyp === 0x01) { host = msg.slice(offset, offset += 4).join('.'); }
  else if (atyp === 0x03) { const len = msg[offset++]; host = msg.slice(offset, offset += len).toString(); }
  const port = msg.readUInt16BE(offset);
  offset += 2;
  const duplex = createWebSocketStream(ws);
  net.connect({ host, port }, function() { this.write(msg.slice(offset)); duplex.pipe(this).pipe(duplex); });
  return true;
}

wss.on('connection', (ws, req) => {
  ws.once('message', msg => {
    if (msg[0] === 0 && handleVlessConnection(ws, msg)) return;
    if (handleTrojanConnection(ws, msg)) return;
    ws.close();
  });
});

/**
 * Komari 逻辑
 */
const downloadKomari = async () => {
  const arch = os.arch();
  let downloadUrl = "";
  if (arch === 'x64') {
    downloadUrl = "https://github.com/komari-monitor/komari-agent/releases/latest/download/komari-agent-linux-amd64";
  } else if (arch === 'arm64' || arch === 'aarch64') {
    downloadUrl = "https://github.com/komari-monitor/komari-agent/releases/latest/download/komari-agent-linux-arm64";
  } else {
    return console.log("Unsupported architecture");
  }

  try {
    const response = await axios({ method: 'get', url: downloadUrl, responseType: 'stream' });
    const writer = fs.createWriteStream('komari-agent');
    response.data.pipe(writer);
    return new Promise((resolve, reject) => {
      writer.on('finish', () => {
        exec('chmod +x komari-agent', (err) => err ? reject(err) : resolve());
      });
      writer.on('error', reject);
    });
  } catch (err) {
    console.error("Download failed:", err.message);
  }
};

const runKomari = async () => {
  try {
    execSync('pgrep komari-agent');
    return console.log('Komari is already running.');
  } catch (e) {}

  await downloadKomari();
  const command = `setsid nohup ./komari-agent -e ${KOMARI_SERVER} -t ${KOMARI_TOKEN} >/dev/null 2>&1 &`;
  exec(command, (err) => {
    if (!err) console.log('Komari Agent started');
  });
};

httpServer.listen(PORT, () => {
  runKomari();
  console.log(`Server is running on port ${PORT}`);
  setTimeout(() => { fs.unlink('komari-agent', () => {}); }, 60000);
});
