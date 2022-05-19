# Logger for Content Security Policy violation reports

**csp-report-logger** is Koa-based web server that listens for JSON
POSTs containing a *csp-report* key, sanitizes the report and writes
it to a log file.

# To Install

Clone the repository and run `yarn install` or `npm i`:

```
git clone https://github.com/revolution-robotics/csp-logger.git
cd csp-logger
yarn install
yarn run server
```
