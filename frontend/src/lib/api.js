export async function api(path, options = {}) {
  const token = localStorage.getItem('ls_token')
  const headers = { 'Content-Type': 'application/json', ...options.headers }
  if (token) headers['Authorization'] = `Bearer ${token}`
  const res = await fetch(`/api${path}`, { ...options, headers })
  if (res.status === 401) {
    localStorage.removeItem('ls_token')
    window.location.href = '/login'
    throw new Error('Unauthorized')
  }
  if (!res.ok) {
    throw new Error(`${res.status} ${await res.text()}`)
  }
  return res.json()
}

async function guard(res) {
  if (res.status === 401) {
    localStorage.removeItem('ls_token')
    window.location.href = '/login'
    throw new Error('Unauthorized')
  }
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`)
  return res
}

export async function apiText(path, options = {}) {
  const token = localStorage.getItem('ls_token')
  const headers = { ...options.headers }
  if (token) headers['Authorization'] = `Bearer ${token}`
  return (await guard(await fetch(`/api${path}`, { ...options, headers }))).text()
}

export async function apiForm(path, formData) {
  const token = localStorage.getItem('ls_token')
  const headers = {}
  if (token) headers['Authorization'] = `Bearer ${token}`
  return (await guard(await fetch(`/api${path}`, { method: 'POST', body: formData, headers }))).json()
}

export async function apiDownload(path, defaultName) {
  const token = localStorage.getItem('ls_token')
  const headers = {}
  if (token) headers['Authorization'] = `Bearer ${token}`
  const res = await fetch(`/api${path}`, { headers })
  if (res.status === 401) {
    localStorage.removeItem('ls_token')
    window.location.href = '/login'
    throw new Error('Unauthorized')
  }
  if (!res.ok) throw new Error(`${res.status}`)
  const blob = await res.blob()
  const cd = res.headers.get('Content-Disposition') || ''
  const match = cd.match(/filename="?([^";]+)"?/)
  const filename = match ? match[1] : defaultName
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

export function classNames(...xs) {
  return xs.filter(Boolean).join(' ')
}
