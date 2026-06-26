import puppeteer from 'puppeteer'

const CHROME_PATH = '/home/alvik/.cache/puppeteer/chrome/linux-148.0.7778.97/chrome-linux64/chrome'

async function pkcLogin() {
  const browser = await puppeteer.launch({
    headless: 'new',
    executablePath: CHROME_PATH,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
  })

  const page = await browser.newPage()

  console.log('Opening proverkacheka.com/auth...')
  await page.goto('https://proverkacheka.com/auth', { waitUntil: 'domcontentloaded', timeout: 60000 })

  const currentUrl = page.url()
  console.log('Current URL:', currentUrl)

  if (currentUrl.includes('passport.yandex.ru') || currentUrl.includes('oauth.yandex.ru')) {
    console.log('REDIRECT_URL:' + currentUrl)
    console.log('STATUS:auth_required')
    await browser.close()
    return
  }

  const cookies = await page.cookies()
  const cookieStr = cookies.map(c => `${c.name}=${c.value}`).join('; ')
  console.log('COOKIES:' + cookieStr)
  console.log('STATUS:ok')

  await browser.close()
}

pkcLogin().catch(err => {
  console.error('Error:', err.message)
  process.exit(1)
})
