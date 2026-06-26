import puppeteer from 'puppeteer-core'
import fs from 'fs'
import path from 'path'

const CHROME_PROFILE_DIR = process.env.CHROME_PROFILE_DIR || '/app/chrome-profile'
const PKC_URL = 'https://proverkacheka.com'
const YANDEX_OAUTH_ID = process.env.YANDEX_OAUTH_ID

async function launchBrowser(headless = true, useProfile = true) {
  const args = [
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    '--window-size=1280,800'
  ]

  if (useProfile && fs.existsSync(CHROME_PROFILE_DIR)) {
    args.push(`--user-data-dir=${CHROME_PROFILE_DIR}`)
  }

  return puppeteer.launch({
    headless: headless ? 'new' : false,
    executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/google-chrome-stable',
    args,
    protocolTimeout: 60000
  })
}

export async function isLoggedIn() {
  let browser
  try {
    browser = await launchBrowser(true, true)
    const page = await browser.newPage()
    await page.setRequestInterception(true)
    page.on('request', req => {
      if (['image', 'stylesheet', 'font'].includes(req.resourceType())) req.abort()
      else req.continue()
    })
    await page.goto(PKC_URL, { waitUntil: 'networkidle2', timeout: 30000 })
    const url = page.url()
    if (url.includes('passport.yandex.ru') || url.includes('oauth.yandex.ru')) {
      return false
    }
    const cookies = await page.cookies()
    const sessionid2 = cookies.find(c => c.name === 'sessionid2')
    if (!sessionid2) return false
    return !sessionid2.value.includes('fakesign')
  } catch (err) {
    console.log('[pkc-browser] isLoggedIn check error:', err.message)
    return false
  } finally {
    if (browser) await browser.close()
  }
}

export async function getCookiesFromBrowser() {
  let browser
  try {
    browser = await launchBrowser(true, true)
    const page = await browser.newPage()
    await page.goto(PKC_URL, { waitUntil: 'networkidle2', timeout: 30000 })
    const url = page.url()
    if (url.includes('passport.yandex.ru') || url.includes('oauth.yandex.ru')) {
      return null
    }
    const cookies = await page.cookies()
    return cookies
  } catch (err) {
    console.log('[pkc-browser] getCookies error:', err.message)
    return null
  } finally {
    if (browser) await browser.close()
  }
}

export async function doYandexLogin(yandexLoginUrl) {
  let browser
  try {
    browser = await launchBrowser(true, false)
    const page = await browser.newPage()

    console.log('[pkc-browser] Opening Yandex login URL...')
    await page.goto(yandexLoginUrl, { waitUntil: 'domcontentloaded', timeout: 60000 })

    console.log('[pkc-browser] Current URL:', page.url())

    const currentUrl = page.url()
    if (currentUrl.includes('proverkacheka.com') && !currentUrl.includes('passport.yandex.ru')) {
      const cookies = await page.cookies()
      const cookieStr = cookies.map(c => `${c.name}=${c.value}`).join('; ')
      return { success: true, cookies: cookieStr, alreadyLoggedIn: true }
    }

    console.log('[pkc-browser] Waiting for redirect to proverkacheka.com (max 120s)...')
    await page.waitForFunction(
      () => {
        const h = window.location.href
        return h.includes('proverkacheka.com') &&
               !h.includes('passport.yandex.ru') &&
               !h.includes('oauth.yandex.ru') &&
               !h.includes('yandex.ru')
      },
      { timeout: 120000 }
    )

    console.log('[pkc-browser] Login successful! URL:', page.url())

    const cookies = await page.cookies()
    const cookieStr = cookies.map(c => `${c.name}=${c.value}`).join('; ')
    console.log('[pkc-browser] Got', cookies.length, 'cookies')

    return { success: true, cookies: cookieStr, alreadyLoggedIn: false }
  } catch (err) {
    console.log('[pkc-browser] Login error:', err.message)
    return { success: false, error: err.message }
  } finally {
    if (browser) await browser.close()
  }
}

export async function refreshSessionIfNeeded(userId, getSessionFn, setSessionFn) {
  const loggedIn = await isLoggedIn()
  if (loggedIn) {
    const cookies = await getCookiesFromBrowser()
    if (cookies) {
      const cookieObj = {}
      for (const c of cookies) cookieObj[c.name] = c.value
      setSessionFn(userId, cookieObj)
      return { refreshed: true, method: 'existing_profile' }
    }
  }
  return { refreshed: false, method: 'none', needsAuth: true }
}
