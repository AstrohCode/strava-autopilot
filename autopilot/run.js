#!/usr/bin/env node
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { DateTime } from 'luxon'
import nacl from 'tweetnacl'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

// ---------- Config / Settings ----------
const SETTINGS_PATH = path.join(__dirname, 'settings.json')
const SETTINGS_EXAMPLE_PATH = path.join(__dirname, 'settings.example.json')

// ---------- Env ----------
const STRAVA_CLIENT_ID = process.env.STRAVA_CLIENT_ID
const STRAVA_CLIENT_SECRET = process.env.STRAVA_CLIENT_SECRET
let STRAVA_REFRESH_TOKEN = process.env.STRAVA_REFRESH_TOKEN
const GH_PAT = process.env.GH_PAT
const GITHUB_REPOSITORY = process.env.GITHUB_REPOSITORY // owner/repo (set in Actions)

// ---------- Helpers ----------
function log(msg) {
  console.log(`[${new Date().toISOString()}] ${msg}`)
}

function fail(msg) {
  console.error(msg)
  process.exitCode = 1
}

function loadSettings() {
  const source = fs.existsSync(SETTINGS_PATH) ? SETTINGS_PATH : SETTINGS_EXAMPLE_PATH
  if (!fs.existsSync(source)) {
    throw new Error('No settings.json or settings.example.json found.')
  }
  const raw = fs.readFileSync(source, 'utf-8')
  return JSON.parse(raw)
}

function parseTimeHM(text) {
  const [h, m] = text.split(':').map((v) => Number(v))
  if (!Number.isFinite(h) || !Number.isFinite(m)) return null
  return { hour: h, minute: m }
}

function nowInTz(settings) {
  return DateTime.now().setZone(settings.timezone)
}

function isWithinActiveHours(settings, now) {
  const start = parseTimeHM(settings.activeHours.start)
  const end = parseTimeHM(settings.activeHours.end)
  if (!start || !end) return true // be permissive
  const startMinutes = start.hour * 60 + start.minute
  const endMinutes = end.hour * 60 + end.minute
  const nowMinutes = now.hour * 60 + now.minute
  return nowMinutes >= startMinutes && nowMinutes <= endMinutes
}

function startOfWeek(dt, weekStart) {
  // weekStart: 'monday' | 'sunday'
  const weekday = dt.weekday // 1..7 (Mon..Sun)
  const diff = weekStart === 'sunday' ? weekday % 7 : weekday - 1
  return dt.startOf('day').minus({ days: diff })
}

function weekKey(dt, weekStart) {
  return startOfWeek(dt, weekStart).toISODate()
}

function parsePace(value) {
  const trimmed = value.trim()
  if (!trimmed) return null
  if (trimmed.includes(':')) {
    const [m, s] = trimmed.split(':').map(Number)
    if (!Number.isFinite(m) || !Number.isFinite(s) || s < 0 || s >= 60 || m < 0) return null
    return m + s / 60
  }
  const num = Number(trimmed)
  if (!Number.isFinite(num) || num <= 0) return null
  return num
}

function paceRangeFromSettings(settings) {
  const fastest = parsePace(settings.paceRange.fastest)
  const slowest = parsePace(settings.paceRange.slowest)
  if (fastest == null || slowest == null) return null
  return {
    fastest: Math.min(fastest, slowest),
    slowest: Math.max(fastest, slowest),
  }
}

function isDefaultName(name, defaults) {
  return defaults.includes(name)
}

function isAlreadyRenamed(name) {
  if (!name) return false
  if (/Easy Run/i.test(name)) return true
  if (/Week Total:\s*/i.test(name)) return true
  if (/^\d+:\d{2}\s+x\s+\d+/i.test(name)) return true
  return false
}

function looksLikeRun(type) {
  if (!type) return false
  return type.toLowerCase().includes('run')
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

// ---------- Strava API ----------
async function refreshAccessToken() {
  const body = new URLSearchParams({
    client_id: STRAVA_CLIENT_ID,
    client_secret: STRAVA_CLIENT_SECRET,
    grant_type: 'refresh_token',
    refresh_token: STRAVA_REFRESH_TOKEN,
  })
  const resp = await fetch('https://www.strava.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  })
  if (!resp.ok) {
    throw new Error(`Failed to refresh token: ${resp.status} ${await resp.text()}`)
  }
  const data = await resp.json()
  const accessToken = data.access_token
  const newRefresh = data.refresh_token
  if (newRefresh && newRefresh !== STRAVA_REFRESH_TOKEN) {
    log('Refresh token rotated; attempting to update GitHub secret...')
    await updateSecretIfPossible('STRAVA_REFRESH_TOKEN', newRefresh)
    STRAVA_REFRESH_TOKEN = newRefresh
  }
  return accessToken
}

async function updateSecretIfPossible(name, value) {
  if (!GH_PAT || !GITHUB_REPOSITORY) {
    log('GH_PAT or GITHUB_REPOSITORY missing; cannot update secret automatically.')
    return
  }
  const [owner, repo] = GITHUB_REPOSITORY.split('/')
  const keyResp = await fetch(`https://api.github.com/repos/${owner}/${repo}/actions/secrets/public-key`, {
    headers: { Authorization: `Bearer ${GH_PAT}`, 'User-Agent': 'strava-autopilot' },
  })
  if (!keyResp.ok) {
    throw new Error(`Failed to get repo public key: ${keyResp.status} ${await keyResp.text()}`)
  }
  const keyData = await keyResp.json()
  const encrypted = encryptSecret(value, keyData.key)
  const putResp = await fetch(`https://api.github.com/repos/${owner}/${repo}/actions/secrets/${name}`, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${GH_PAT}`,
      'User-Agent': 'strava-autopilot',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      encrypted_value: encrypted,
      key_id: keyData.key_id,
    }),
  })
  if (!putResp.ok) {
    throw new Error(`Failed to update secret ${name}: ${putResp.status} ${await putResp.text()}`)
  }
  log(`Updated GitHub secret ${name}.`)
}

function encryptSecret(secretValue, base64PublicKey) {
  const publicKey = Buffer.from(base64PublicKey, 'base64')
  const messageBytes = Buffer.from(secretValue)
  const encryptedBytes = nacl.box.seal(messageBytes, publicKey)
  return Buffer.from(encryptedBytes).toString('base64')
}

async function stravaGet(url, accessToken) {
  const resp = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } })
  return resp
}

async function stravaPutActivity(id, payload, accessToken) {
  const body = new URLSearchParams()
  if (payload.name != null) body.append('name', payload.name)
  if (payload.description != null) body.append('description', payload.description)
  const resp = await fetch(`https://www.strava.com/api/v3/activities/${id}`, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
  })
  return resp
}

// ---------- Workout / description logic ----------
function paceMinutesPerUnit(meters, seconds, unitSystem) {
  if (meters <= 0) return null
  const units = unitSystem === 'mi' ? meters / 1609.344 : meters / 1000
  return (seconds / 60) / units
}

function formatPace(meters, seconds, unitSystem) {
  const pace = paceMinutesPerUnit(meters, seconds, unitSystem)
  if (pace == null || !Number.isFinite(pace)) return '-'
  const totalSeconds = Math.round(pace * 60)
  const mins = Math.floor(totalSeconds / 60)
  const secs = totalSeconds % 60
  return `${mins}:${secs.toString().padStart(2, '0')} ${unitSystem === 'mi' ? 'min/mi' : 'min/km'}`
}

function formatDuration(seconds) {
  const mins = Math.floor(seconds / 60)
  const secs = Math.floor(seconds % 60)
  return `${mins}:${secs.toString().padStart(2, '0')}`
}

function snapToMinuteIfClose(seconds, toleranceSeconds = 2) {
  const nearestMinute = Math.round(seconds / 60) * 60
  return Math.abs(seconds - nearestMinute) <= toleranceSeconds ? nearestMinute : seconds
}

function mergeLapsByPace(laps, paceRange, unitSystem) {
  const merged = []
  let group = []

  const flushGroup = () => {
    if (group.length === 0) return
    if (group.length === 1) {
      merged.push(group[0])
    } else {
      const distanceMeters = group.reduce((sum, lap) => sum + lap.distance, 0)
      const movingTimeSeconds = group.reduce((sum, lap) => sum + lap.moving_time, 0)
      const start = group[0].lap_index
      const end = group[group.length - 1].lap_index
      merged.push({
        ...group[0],
        lap_index: group[0].lap_index,
        name: `Merged laps ${start}-${end}`,
        distance: distanceMeters,
        moving_time: movingTimeSeconds,
        merged: true,
      })
    }
    group = []
  }

  for (const lap of laps) {
    const pace = paceMinutesPerUnit(lap.distance, lap.moving_time, unitSystem)
    const qualifies = pace != null && pace >= paceRange.fastest && pace <= paceRange.slowest
    if (qualifies) {
      group.push(lap)
    } else {
      flushGroup()
      merged.push(lap)
    }
  }
  flushGroup()
  return merged
}

function generateWorkoutDescription(laps, paceRange, unitSystem) {
  if (!laps || laps.length === 0) return null
  const segments = mergeLapsByPace(laps, paceRange, unitSystem)
  const isWork = (seg) => {
    const pace = paceMinutesPerUnit(seg.distance, seg.moving_time, unitSystem)
    return pace != null && pace >= paceRange.fastest && pace <= paceRange.slowest
  }
  const firstFastIdx = segments.findIndex(isWork)
  if (firstFastIdx < 0) return null
  let lastFastIdx = -1
  for (let i = segments.length - 1; i >= 0; i--) {
    if (isWork(segments[i])) {
      lastFastIdx = i
      break
    }
  }
  if (lastFastIdx < 0) return null

  const reps = []
  for (let i = firstFastIdx; i <= lastFastIdx; i++) {
    const seg = segments[i]
    if (isWork(seg)) {
      reps.push({ fast: seg, restSeconds: 0 })
    } else if (reps.length > 0) {
      reps[reps.length - 1].restSeconds += seg.moving_time
    }
  }
  if (reps.length === 0) return null

  const cooldownSeconds = segments.slice(lastFastIdx + 1).reduce((sum, seg) => sum + seg.moving_time, 0)
  const repTimesRounded = reps.map((rep) => snapToMinuteIfClose(rep.fast.moving_time))
  const totalFastMeters = reps.reduce((sum, rep) => sum + rep.fast.distance, 0)
  const totalFastSecondsRounded = repTimesRounded.reduce((sum, s) => sum + s, 0)
  const fastAvgPace = formatPace(totalFastMeters, totalFastSecondsRounded, unitSystem)

  const median = (values) => {
    const sorted = [...values].sort((a, b) => a - b)
    const mid = Math.floor(sorted.length / 2)
    return sorted.length % 2 === 1 ? sorted[mid] : Math.round((sorted[mid - 1] + sorted[mid]) / 2)
  }
  const typicalRepSeconds = median(repTimesRounded)
  const header = `${formatDuration(typicalRepSeconds)} x ${reps.length} (avg ${fastAvgPace})`

  const lines = [header]
  reps.forEach((rep, idx) => {
    const repSeconds = snapToMinuteIfClose(rep.fast.moving_time)
    const repPace = formatPace(rep.fast.distance, repSeconds, unitSystem)
    const base = `${idx + 1}) ${formatDuration(repSeconds)} @ ${repPace}`
    if (rep.restSeconds > 0 && idx < reps.length - 1) {
      const restSeconds = snapToMinuteIfClose(rep.restSeconds)
      lines.push(`${base} + rest ${formatDuration(restSeconds)}`)
      return
    }
    if (idx === reps.length - 1 && cooldownSeconds > 0) {
      lines.push(`${base} + CD`)
      return
    }
    lines.push(base)
  })

  return {
    name: header,
    description: lines.slice(1).join('\n'),
  }
}

function formatAvgHrDescription(avgHr, maxHr) {
  const rounded = Math.round(avgHr)
  if (!maxHr) return `Avg HR: ${rounded} bpm`
  const pct = Math.round((rounded / maxHr) * 100)
  return `Avg HR: ${rounded} bpm (${pct}% max)`
}

function appendWeekTotalSuffix(name, suffix) {
  const cleaned = name.replace(/\s*\(Week Total: [^)]+\)\s*$/i, '').trim()
  return `${cleaned} ${suffix}`.trim()
}

function formatWeekTotalSuffix(totalMeters, unitSystem) {
  const units = unitSystem === 'mi' ? totalMeters / 1609.344 : totalMeters / 1000
  const value = units.toFixed(1)
  const label = unitSystem === 'mi' ? 'mi' : 'km'
  return `(Week Total: ${value} ${label})`
}

// ---------- Main processing ----------
async function main() {
  const settings = loadSettings()
  const now = nowInTz(settings)
  if (!isWithinActiveHours(settings, now)) {
    log('Outside active hours; exiting without API calls.')
    return
  }

  const retryPolicy = {
    lapRetryIntervalSeconds: settings.retryPolicy?.lapRetryIntervalSeconds ?? 60,
    lapRetryMaxMinutes: settings.retryPolicy?.lapRetryMaxMinutes ?? 30,
    maxReadsPerRun: settings.retryPolicy?.maxReadsPerRun ?? 90,
  }

  if (!STRAVA_CLIENT_ID || !STRAVA_CLIENT_SECRET || !STRAVA_REFRESH_TOKEN) {
    throw new Error('Missing STRAVA_CLIENT_ID/STRAVA_CLIENT_SECRET/STRAVA_REFRESH_TOKEN env vars.')
  }

  const paceRange = paceRangeFromSettings(settings)
  if (!paceRange) {
    throw new Error('Invalid paceRange in settings.')
  }

  const accessToken = await refreshAccessToken()
  let readsUsed = 0

  const midnight = now.startOf('day')
  const afterEpoch = Math.floor(midnight.toSeconds())
  const perPage = 50

  const listResp = await stravaGet(
    `https://www.strava.com/api/v3/athlete/activities?per_page=${perPage}&after=${afterEpoch}`,
    accessToken,
  )
  readsUsed += 1
  if (!listResp.ok) {
    throw new Error(`Failed to list activities: ${listResp.status} ${await listResp.text()}`)
  }
  const activities = await listResp.json()

  const defaultNames = settings.defaultRunNames ?? []

  for (const summary of activities) {
    if (readsUsed >= retryPolicy.maxReadsPerRun) {
      log('Read cap reached; stopping further processing.')
      break
    }
    if (!looksLikeRun(summary.type) && !looksLikeRun(summary.sport_type)) continue
    if (isAlreadyRenamed(summary.name)) continue
    if (!isDefaultName(summary.name, defaultNames)) continue

    const detailResp = await stravaGet(`https://www.strava.com/api/v3/activities/${summary.id}`, accessToken)
    readsUsed += 1
    if (!detailResp.ok) {
      log(`Skipping ${summary.id}: failed to get details (${detailResp.status})`)
      continue
    }
    const detail = await detailResp.json()
    if (detail.workout_type === 1) {
      log(`Skipping race ${detail.id}`)
      continue
    }
    if (!isDefaultName(detail.name, defaultNames)) {
      continue
    }

    const laps = await fetchLapsWithRetry(detail.id, accessToken, retryPolicy, () => {
      readsUsed += 1
      return readsUsed < retryPolicy.maxReadsPerRun
    })
    if (!laps) {
      log(`Laps not ready for ${detail.id}; skipping for now.`)
      continue
    }

    const update = buildUpdate(detail, laps, paceRange, settings)
    if (!update) {
      log(`No update built for ${detail.id}`)
      continue
    }

    const putResp = await stravaPutActivity(detail.id, update, accessToken)
    if (!putResp.ok) {
      log(`Failed to update ${detail.id}: ${putResp.status} ${await putResp.text()}`)
      continue
    }
    log(`Updated ${detail.id} → ${update.name}`)
  }

  // Week totals: run only early in the active window on week boundary to avoid spam
  if (settings.features?.weekTotals) {
    await maybeFinalizePreviousWeek(now, settings, accessToken, () => {
      readsUsed += 1
      return readsUsed < retryPolicy.maxReadsPerRun
    })
  }
}

async function fetchLapsWithRetry(activityId, accessToken, retryPolicy, canContinue) {
  const intervalMs = (retryPolicy.lapRetryIntervalSeconds ?? 60) * 1000
  const maxMinutes = retryPolicy.lapRetryMaxMinutes ?? 30
  const maxAttempts = Math.max(1, Math.floor((maxMinutes * 60 * 1000) / intervalMs))

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    if (!canContinue()) return null
    const resp = await stravaGet(`https://www.strava.com/api/v3/activities/${activityId}/laps`, accessToken)
    if (!resp.ok) {
      log(`laps attempt ${attempt} for ${activityId} failed (${resp.status}); will retry.`)
    } else {
      const laps = await resp.json()
      if (Array.isArray(laps) && laps.length > 0) {
        return laps
      }
      log(`laps attempt ${attempt} for ${activityId} empty; will retry.`)
    }
    if (attempt < maxAttempts) {
      await sleep(intervalMs)
    }
  }
  return null
}

function buildUpdate(activity, laps, paceRange, settings) {
  const unitSystem = settings.unitSystem === 'km' ? 'km' : 'mi'
  const maxHr = settings.maxHr && Number.isFinite(Number(settings.maxHr)) ? Number(settings.maxHr) : null

  const workout = generateWorkoutDescription(laps, paceRange, unitSystem)
  if (workout) {
    return { name: workout.name, description: workout.description }
  }

  // Non-workout
  const avgHr = activity.average_heartrate
  const description = avgHr != null ? formatAvgHrDescription(avgHr, maxHr) : ''
  return { name: 'Easy Run', description }
}

async function maybeFinalizePreviousWeek(now, settings, accessToken, consumeRead) {
  // Only run in the first 30 minutes of the active window to avoid repeated calls.
  const start = parseTimeHM(settings.activeHours.start)
  const nowMinutes = now.hour * 60 + now.minute
  const startMinutes = start ? start.hour * 60 + start.minute : 0
  if (nowMinutes > startMinutes + 30) {
    return
  }

  const currentWeekStart = startOfWeek(now, settings.weekStart === 'sunday' ? 'sunday' : 'monday')
  const previousWeekStart = currentWeekStart.minus({ days: 7 })
  const previousWeekEnd = currentWeekStart

  const after = Math.floor(previousWeekStart.toSeconds())
  const before = Math.floor(previousWeekEnd.toSeconds())

  let page = 1
  const perPage = 200
  let activities = []
  while (true) {
    if (!consumeRead()) return
    const resp = await stravaGet(
      `https://www.strava.com/api/v3/athlete/activities?per_page=${perPage}&page=${page}&after=${after}&before=${before}`,
      accessToken,
    )
    if (!resp.ok) {
      log(`Week total listing failed page ${page}: ${resp.status}`)
      return
    }
    const batch = await resp.json()
    activities = activities.concat(batch)
    if (batch.length < perPage) break
    page += 1
  }

  if (activities.length === 0) return

  const runs = activities.filter((a) => looksLikeRun(a.type) || looksLikeRun(a.sport_type))
  if (runs.length === 0) return

  const totalMeters = runs.reduce((sum, a) => sum + (a.distance ?? 0), 0)
  const lastRun = runs
    .filter((a) => a.start_date)
    .sort((a, b) => new Date(b.start_date).getTime() - new Date(a.start_date).getTime())
    .find((a) => a.workout_type !== 1)
  if (!lastRun) return

  const suffix = formatWeekTotalSuffix(totalMeters, settings.unitSystem === 'km' ? 'km' : 'mi')
  if (lastRun.name && lastRun.name.includes(suffix)) {
    return
  }
  const newName = appendWeekTotalSuffix(lastRun.name ?? 'Run', suffix)

  const putResp = await stravaPutActivity(lastRun.id, { name: newName }, accessToken)
  if (!putResp.ok) {
    log(`Failed to apply week total to ${lastRun.id}: ${putResp.status}`)
    return
  }
  log(`Applied week total to ${lastRun.id}: ${newName}`)
}

// ---------- Run ----------
main().catch((err) => {
  fail(err.message || String(err))
})
