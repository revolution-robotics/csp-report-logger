# Log Content Security Policy violation reports

**csp-report-logger** is Koa-based web server that listens for JSON
POSTs containing a *csp-report* key, then sanitizes and writes the
report to a log file.

## Synopsis

    Usage: csp-report-logger OPTIONS
    OPTIONS:
        -c | --config=CONFIG  PATH of config file (default: /etc/default/csp-report-logger)
        -l | --log=PATH       PATH of log file (default: /var/log/csp.log)
        -p | --port=N         Port to listen on (default: 8080)
        -h | --help           Print this help, then exit
        -v | --version        Print version, then exit
