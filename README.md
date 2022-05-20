# Log Content Security Policy violation reports

**csp-report-logger** is Koa-based web server that listens for JSON
POSTs containing a *csp-report* key, then sanitizes and writes the
report to a log file.

## Synopsis

    Usage: csp-report-logger OPTIONS
    OPTIONS:
        --config=CONFIG  PATH of config file (default: /etc/default/csp-report-logger)
        --log=PATH       PATH of log file (default: /var/log/csp.log)
        --port=N         Port to listen on (default: 8080)
        --help           Print this help, then exit
        --version        Print version, then exit
