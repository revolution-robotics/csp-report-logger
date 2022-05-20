#!/usr/bin/env node
//
// @(#) csp-report-logger
//
// Copyright © 2022 Revolution Robotics, Inc.
//
// This script sanitizes and logs Content Security Policy violation
// reports - see, e.g.: https://w3c.github.io/webappsec-csp/
//
import Koa from 'koa'
import koaBodyParser from 'koa-bodyparser'
import parseArgs from 'minimist'
import ini from 'ini'
import fs from 'fs'
import fsPromises from 'fs/promises'

const app = new Koa()
const pgm = process.argv[1].replace(/^.*\//, '')
const argv = parseArgs(process.argv.slice(2))

if (argv.help || argv.h) {
  console.log(`Usage: ${pgm} OPTIONS`)
  console.log(`OPTIONS:
    --config=CONFIG  PATH of config file (default: /etc/default/csp-report-logger)
    --log=PATH       PATH of log file (default: /var/log/csp.log)
    --port=N         Port to listen on (default: 8080)`)
  process.exit(0)
}

const configfile = argv.config || '/etc/default/csp-report-logger'

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

const port = argv.port || 8080
const logfile = argv.log || '/var/log/csp.log'
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

console.log(`Listening on port: ${port}`)

const validateCSPReport = (json) => {
  if (!('csp-report' in json)) {
    return null
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

  let validReport = true

  // Sanity check CSP report.
  requiredReportKeys.forEach(key => {
    if (!(key in cspReport)) {
      validReport = false
    }
  })

  return validReport ? cspReport : null
}

app.use(koaBodyParser())
app.use(async ctx => {
  let cspReport = {}

  try {
    cspReport = await validateCSPReport(JSON.parse(ctx.request.rawBody))
  } catch (SyntaxError) {
    return (ctx.status = 422)
  }

  if (!cspReport) {
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
app.listen(port)
