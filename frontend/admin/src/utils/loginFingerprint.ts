const LOGIN_PATHS = new Set(['/admin/login', '/admin/login/verify-2fa'])

let cached: Promise<string> | null = null

export function isAdminLoginFingerprintPath(path: string): boolean {
  return LOGIN_PATHS.has(path)
}

export function resetLoginFingerprintCache(): void {
  cached = null
}

function canvasSignature(): string {
  try {
    const canvas = document.createElement('canvas')
    canvas.width = 240
    canvas.height = 60
    const context = canvas.getContext('2d')
    if (!context) return ''
    context.textBaseline = 'alphabetic'
    context.font = '16px Arial'
    context.fillStyle = '#f60'
    context.fillRect(10, 1, 62, 20)
    context.fillStyle = '#069'
    context.fillText('dujiao-admin', 2, 15)
    context.fillStyle = 'rgba(102, 204, 0, 0.7)'
    context.fillText('dujiao-admin', 4, 17)
    return canvas.toDataURL()
  } catch {
    return ''
  }
}

function fingerprintSource(): string {
  const nav = typeof navigator === 'undefined' ? undefined : navigator
  const screenInfo = typeof screen === 'undefined' ? undefined : screen
  const languages = nav?.languages?.length ? nav.languages.join(',') : nav?.language || ''
  let timezone = ''
  try {
    timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || ''
  } catch {
    timezone = ''
  }
  return [
    nav?.userAgent || '',
    languages,
    timezone,
    String(screenInfo?.width ?? ''),
    String(screenInfo?.height ?? ''),
    String(screenInfo?.colorDepth ?? ''),
    String(window.devicePixelRatio ?? ''),
    canvasSignature(),
  ].join('\n')
}

async function sha256Hex(value: string): Promise<string> {
  const subtle = globalThis.crypto?.subtle
  if (!subtle) return ''
  const digest = await subtle.digest('SHA-256', new TextEncoder().encode(value))
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

export function loginFingerprint(): Promise<string> {
  if (!cached) {
    cached = sha256Hex(fingerprintSource()).catch(() => '')
  }
  return cached
}
