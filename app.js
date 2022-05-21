#!/usr/bin/env node
//
// @(#) csp-report-logger
//
// Copyright © 2022 Revolution Robotics, Inc.
//
// This script sanitizes and logs Content Security Policy violation
// reports - see, e.g.: https://w3c.github.io/webappsec-csp/
//
import http from 'http'
import https from 'https'
import Koa from 'koa'
import koaBodyParser from 'koa-bodyparser'
import parseArgs from 'minimist'
import ini from 'ini'
import fs from 'fs'
import fsPromises from 'fs/promises'

const app = new Koa()
const argv = parseArgs(process.argv.slice(2))
const pkgJson = JSON.parse(fs.readFileSync('package.json', 'utf8'))

if (argv.h || argv.help) {
  console.log(`Usage: ${pkgJson.name} OPTIONS`)
  console.log(`OPTIONS:
    -c | --config=PATH   PATH of config file
                         (default: /etc/default/csp-report-logger)
    -l | --log=PATH      PATH of log file (default: /var/log/csp.log)
    -p | --port=N        Port to listen on (default: 8080)
    -h | --help          Print this help, then exit
    -v | --version       Print version, then exit`)
  process.exit(0)
} else if (argv.v || argv.version) {
  console.log(`${pkgJson.name} v${pkgJson.version}`)
  process.exit(0)
}

const configfile = argv.c || argv.config || '/etc/default/csp-report-logger'

if (fs.existsSync(configfile)) {
  const config = ini.parse(fs.readFileSync(argv.config, 'utf-8'))

  // Command-line arguments override settings in config file, so
  // assign values to argv only if they're missing.
  for (const [key, value] of Object.entries(config)) {
    if (!argv[key]) {
      argv[key] = value
    }
  }
}

const port = argv.p || argv.port || 8080
const logfile = argv.l || argv.log || '/var/log/csp.log'
const allowedReportKeys = [
  'blocked-uri',
  'column-number',
  'document-uri',
  'line-number',
  'original-policy',
  'disposition',
  'referrer',
  'status-code',
  'script-sample',
  'source-file',
  'effective-directive'
]

const requiredReportKeys = [
  'blocked-uri',
  'document-uri',
  'effective-directive'
]

const validateCSPReport = (json) => {
  if (!('csp-report' in json)) {
    throw new Error('Invalid CSP object')
  }

  const cspReport = {}

  // Sanitize CSP report.
  allowedReportKeys.forEach(key => {
    if (key in json['csp-report']) {
      cspReport[key] = json['csp-report'][key]
    }
  })

  // Firefox uses the old 'violated-directive' key.
  if ('violated-directive' in json['csp-report']) {
    cspReport['effective-directive'] = json['csp-report']['violated-directive']
  }

  // Sanity check CSP report.
  requiredReportKeys.forEach(key => {
    if (!(key in cspReport)) {
      throw new Error(`CSP object missing required key ${key}`)
    }
  })

  return cspReport
}

app.use(koaBodyParser())
app.use(async ctx => {
  let cspReport = {}

  try {
    cspReport = await validateCSPReport(JSON.parse(ctx.request.rawBody))
  } catch (err) {
    console.log(`csp-report-logger: ${err.name}: ${err.message}`)
    return (ctx.status = 422)
  }

  const serializedCspReport = JSON.stringify({ 'csp-report': cspReport }, null, 2) + '\n'

  // Node file I/O uses asynchronous I/O (e.g., POSIX aio(7)), which
  // queues I/O operations, so file writes should be atomic.
  await fsPromises.appendFile(logfile, serializedCspReport, {
    flags: 'a+',
    encoding: 'utf-8',
    mode: 0o600
  })
  return (ctx.status = 200)
})

const server = http.createServer(app.callback())

server.on('error', err => {
  if (err.code === 'EADDRINUSE') {
    console.log(`csp-report-logger: Error: Address already in use :::${port}`)
    process.exit(1)
  }

  throw err
})

server.on('listening', () => {
  console.log(`csp-report-logger
* Listening on http://0.0.0.0:${port}
* Listening on http://[::]:${port}`)
})

server.listen(port)
