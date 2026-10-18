import { useEffect, useState } from 'react'
import { checkBackendHealth, getScanHistory } from './services/api'
import api from './services/api'
import jsQR from 'jsqr'

import {
ShieldCheck,
LoaderCircle,
ShieldAlert,
Globe,
Mail,
MessageSquare,
QrCode,
ArrowRight,
LockKeyhole,
Activity,
Search,
CheckCircle2,
Menu,
X,
} from 'lucide-react'

const scannerOptions = [
{
title: 'Website Scanner',
description: 'Check URLs for suspicious patterns and potential phishing threats.',
icon: Globe,
color: 'blue',
label: 'Scan a website',
},
{
title: 'Email Analyzer',
description: 'Inspect email messages for phishing indicators and suspicious links.',
icon: Mail,
color: 'purple',
label: 'Analyze an email',
},
{
title: 'SMS Analyzer',
description: 'Identify suspicious messages, payment requests, and scam indicators.',
icon: MessageSquare,
color: 'cyan',
label: 'Analyze an SMS',
},
{
title: 'QR Code Scanner',
description: 'Decode QR codes and inspect their destinations for potential risks.',
icon: QrCode,
color: 'emerald',
label: 'Scan a QR code',
},
]

const features = [
{
icon: ShieldCheck,
title: 'Security Intelligence',
description:
'Combine security checks and available threat intelligence to assess potential risks.',
},
{
icon: Activity,
title: 'Evidence-Based Scoring',
description:
'Understand the security findings behind a website risk assessment.',
},
{
icon: LockKeyhole,
title: 'Privacy-Conscious Analysis',
description:
'Build with secure data handling and responsible analysis practices in mind.',
},
]

function App() {
const [url, setUrl] = useState('')
const [menuOpen, setMenuOpen] = useState(false)
const [message, setMessage] = useState('')
const [scanResult, setScanResult] = useState(null)
const [isScanning, setIsScanning] = useState(false)
const [scanHistory, setScanHistory] = useState([])
const [historyLoading, setHistoryLoading] = useState(false)
const [historyError, setHistoryError] = useState('')
const [backendStatus, setBackendStatus] = useState('Checking...')
const [smsText, setSmsText] = useState('')
const [smsResult, setSmsResult] = useState(null)
const [isSmsScanning, setIsSmsScanning] = useState(false)
const [smsError, setSmsError] = useState('')
const [emailText, setEmailText] = useState('')
const [emailResult, setEmailResult] = useState(null)
const [isEmailScanning, setIsEmailScanning] = useState(false)
const [emailError, setEmailError] = useState('')
const [qrResult, setQrResult] = useState(null)
const [qrImage, setQrImage] = useState(null)
const [qrLoading, setQrLoading] = useState(false)
async function loadScanHistory() {
  setHistoryLoading(true)
  setHistoryError('')

  try {
    const history = await getScanHistory()
    setScanHistory(history)
  } catch (error) {
    console.error('Scan history error:', error)

    setHistoryError(
      'Could not load scan history. Please check the backend.'
    )
  } finally {
    setHistoryLoading(false)
  }
}

async function handleSmsScan() {
  if (!smsText.trim()) {
    setSmsError('Please enter an SMS message to analyze.')
    setSmsResult(null)
    return
  }

  setIsSmsScanning(true)
  setSmsError('')
  setSmsResult(null)

  try {
    const response = await api.post('/scan/sms', {
      message: smsText.trim(),
    })

    setSmsResult(response.data)
  } catch (error) {
    console.error('SMS scan error:', error)

    setSmsError(
      error.response?.data?.detail ||
        'Unable to analyze the SMS. Please check that the backend is running.'
    )
  } finally {
    setIsSmsScanning(false)
  }
}
async function handleEmailScan() {
  if (!emailText.trim()) {
    setEmailError('Please enter email content to analyze.')
    setEmailResult(null)
    return
  }

  setIsEmailScanning(true)
  setEmailError('')
  setEmailResult(null)

  try {
    const response = await api.post('/scan/email', {
      email_content: emailText.trim(),
    })

    setEmailResult(response.data)

    // Refresh history after the email scan
    await loadScanHistory()
  } catch (error) {
    console.error('Email scan error:', error)

    setEmailError(
      error.response?.data?.detail ||
        'Unable to analyze the email. Please check that the backend is running.'
    )
  } finally {if (code) {
  const scannedValue = code.data.trim()
  const isHttpUrl = /^https?:\/\/\S+$/i.test(scannedValue)

if (!isHttpUrl) {
  setQrResult({
    url: scannedValue,
    error: 'This QR code does not contain a valid HTTP or HTTPS URL.',
  })
  return
}

  setQrResult(`QR Code detected: ${scannedValue}`)

  try {
    const response = await api.post('/scan/url', {
      url: scannedValue,
    })

    setQrResult({
      url: scannedValue,
      analysis: response.data,
    })

    await loadScanHistory()
  } catch (error) {
    const message =
      error.response?.data?.detail ||
      'Unable to analyze this QR code URL.'

    setQrResult({
      url: scannedValue,
      error: typeof message === 'string'
        ? message
        : 'The URL could not be validated.',
    })
  }
} else {
  setQrResult('QR code not detected. Try a clearer image.')
}
    setIsEmailScanning(false)
  }
}

const handleQrScan = async () => {
  if (!qrImage) {
    setQrResult('Please upload a QR code image first.')
    return
  }

  setQrLoading(true)

  const imageUrl = URL.createObjectURL(qrImage)
  const image = new Image()

  image.onload = async () => {
    try {
      const canvas = document.createElement('canvas')
      const context = canvas.getContext('2d')

      if (!context) {
        setQrResult('Unable to process the image.')
        return
      }

      canvas.width = image.naturalWidth
      canvas.height = image.naturalHeight

      context.drawImage(image, 0, 0)

      const imageData = context.getImageData(
        0,
        0,
        canvas.width,
        canvas.height
      )

      const code = jsQR(
        imageData.data,
        imageData.width,
        imageData.height,
        { inversionAttempts: 'attemptBoth' }
      )

      if (!code) {
        setQrResult('QR code not detected. Try a clearer image.')
        return
      }

      const scannedValue = code.data.trim()

      // Validate HTTP or HTTPS URL
      if (!/^https?:\/\/\S+$/i.test(scannedValue)) {
        setQrResult({
          url: scannedValue,
          error: 'This QR code does not contain a valid HTTP or HTTPS URL.',
        })
        return
      }

      // Analyze the URL using the backend
      const response = await api.post('/scan/url', {
        url: scannedValue,
      })

      setQrResult({
        url: scannedValue,
        analysis: response.data,
      })

      // Refresh history after the scan
      await loadScanHistory()
    } catch (error) {
      console.error('QR scan error:', error)

      const detail = error.response?.data?.detail

      setQrResult({
        error:
          typeof detail === 'string'
            ? detail
            : 'Unable to process or analyze the QR code. Please try again.',
      })
    } finally {
      URL.revokeObjectURL(imageUrl)
      setQrLoading(false)
    }
  }

  image.onerror = () => {
    URL.revokeObjectURL(imageUrl)
    setQrResult('Unable to load the selected image.')
    setQrLoading(false)
  }

  image.src = imageUrl
}


  useEffect(() => {
    loadScanHistory()
    checkBackendHealth()
      .then(() => {
        setBackendStatus('Connected')
      })
      .catch(() => {
        setBackendStatus('Disconnected')
      })
  }, [])

  async function handleScan(event) {
    event.preventDefault();

    if (!url.trim()) {
      setMessage('Please enter a website URL to continue.');
      setScanResult(null);
      return;
    }

    let scanUrl = url.trim();

    if (!/^https?:\/\//i.test(scanUrl)) {
      scanUrl = `https://${scanUrl}`;
    }

    setIsScanning(true);
    setScanResult(null);
    setMessage('Analyzing the URL...');

    try {
      const response = await api.post('/scan/url', { url: scanUrl });
      setScanResult(response.data);
      setMessage('Basic URL analysis completed. Review the findings below.');
    } catch (error) {
      console.error('URL scan error:', error);

      if (error.response) {
        setMessage(
          `Backend error: ${error.response.status} - ${JSON.stringify(error.response.data)}`
        );
      } else {
        setMessage(
          `Connection error: ${error.message}. Check that the backend is running.`
        );
      }
    } finally {
      setIsScanning(false);
    }
  }

  function handleComingSoon(scannerName) {
    setMessage(`${scannerName} will be implemented in a later development phase.`);
  }

  return ( <div className="min-h-screen overflow-hidden bg-[#050816] text-slate-100"> <header className="sticky top-0 z-50 border-b border-white/10 bg-[#050816]/90 backdrop-blur-xl"> <div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-4 lg:px-8"> <a href="#home" className="flex items-center gap-3"> <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-blue-500/15 ring-1 ring-blue-400/30"> <ShieldCheck className="h-6 w-6 text-cyan-300" /> </div>

        <div>
          <p className="text-sm font-bold tracking-wide text-white sm:text-base">
            Digital Trust
          </p>
          <p className="text-xs text-slate-400">Security Intelligence Platform</p>
        </div>
      </a>

      <nav className="hidden items-center gap-8 md:flex">
        <a href="#home" className="text-sm text-slate-300 transition hover:text-cyan-300">
          Home
        </a>
        <a href="#scanners" className="text-sm text-slate-300 transition hover:text-cyan-300">
          Scanners
        </a>
        <a href="#features" className="text-sm text-slate-300 transition hover:text-cyan-300">
          Features
        </a>
        <a href="#how-it-works" className="text-sm text-slate-300 transition hover:text-cyan-300">
          How it works
        </a>
          <a
            href="#history"
            className="text-sm text-slate-300 transition hover:text-cyan-300"
        >
          Scan History
       </a>
<a
  href="#email-scanner"
  className="text-sm font-medium text-slate-300 transition hover:text-white"
>
  Email Analyzer
</a>
<a
  href="#sms-scanner"
  className="text-sm font-medium text-slate-300 transition hover:text-white"
>
  SMS Analyzer
</a>
      </nav>

      <a
        href="#scanner"
        className="hidden rounded-xl bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white transition hover:bg-blue-500 md:inline-flex"
      >
        Start scanning
      </a>
      <div className="hidden items-center gap-2 text-xs sm:flex">
  <span
    className={`h-2 w-2 rounded-full ${
      backendStatus === 'Connected' ? 'bg-green-400' :
      backendStatus === 'Disconnected' ? 'bg-red-400' :
      'bg-yellow-400'
    }`}
  />
  <span className="text-slate-400">
    Backend: {backendStatus}
  </span>
</div>

      <button
        type="button"
        onClick={() => setMenuOpen(!menuOpen)}
        aria-label={menuOpen ? 'Close navigation menu' : 'Open navigation menu'}
        className="rounded-lg border border-white/10 p-2 md:hidden"
      >
        {menuOpen ? <X size={22} /> : <Menu size={22} />}
      </button>
    </div>

    {menuOpen && (
      <nav className="space-y-1 border-t border-white/10 px-5 py-4 md:hidden">
        {[
          ['Home', '#home'],
          ['Scanners', '#scanners'],
          ['Features', '#features'],
          ['How it works', '#how-it-works'],
          ['Scan History', '#history'],
        ].map(([label, href]) => (
          <a
            key={label}
            href={href}
            onClick={() => setMenuOpen(false)}
            className="block rounded-lg px-3 py-3 text-sm text-slate-300 hover:bg-white/5 hover:text-cyan-300"
          >
            {label}
          </a>
        ))}
      </nav>
    )}
  </header>

  <main>
    <section id="home" className="relative isolate">
      <div className="pointer-events-none absolute inset-0 -z-10">
        <div className="absolute left-1/2 top-0 h-96 w-96 -translate-x-1/2 rounded-full bg-blue-600/15 blur-[120px]" />
        <div className="absolute right-0 top-48 h-72 w-72 rounded-full bg-cyan-500/10 blur-[100px]" />
      </div>

      <div className="mx-auto grid max-w-7xl items-center gap-14 px-5 py-20 sm:py-24 lg:grid-cols-[1.15fr_0.85fr] lg:px-8 lg:py-28">
        <div>
          <div className="mb-7 inline-flex items-center gap-2 rounded-full border border-cyan-400/20 bg-cyan-400/5 px-4 py-2 text-xs font-medium text-cyan-200 sm:text-sm">
            <span className="h-2 w-2 rounded-full bg-cyan-400" />
            AI-powered digital security assessment
          </div>

          <h1 className="max-w-3xl text-4xl font-bold leading-tight tracking-tight text-white sm:text-5xl lg:text-6xl">
            Know what you trust.
            <span className="mt-2 block bg-gradient-to-r from-cyan-300 via-blue-400 to-indigo-400 bg-clip-text text-transparent">
              Detect digital risks.
            </span>
          </h1>

          <p className="mt-6 max-w-2xl text-base leading-8 text-slate-400 sm:text-lg">
            Assess suspicious websites, phishing emails, fraudulent SMS
            messages, and QR-code destinations with one unified digital
            trust platform.
          </p>

          <div className="mt-8 flex flex-wrap gap-3 text-sm text-slate-300">
            <span className="flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2">
              <CheckCircle2 size={16} className="text-cyan-300" />
              Security checks
            </span>
            <span className="flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2">
              <CheckCircle2 size={16} className="text-cyan-300" />
              Risk assessment
            </span>
            <span className="flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2">
              <CheckCircle2 size={16} className="text-cyan-300" />
              Clear findings
            </span>
          </div>

          <a
            href="#scanner"
            className="mt-9 inline-flex items-center gap-2 rounded-xl bg-blue-600 px-6 py-3.5 font-semibold text-white shadow-lg shadow-blue-950/40 transition hover:bg-blue-500"
          >
            Check a website
            <ArrowRight size={18} />
          </a>

          <p className="mt-4 text-xs leading-6 text-slate-500">
            Risk assessments are indicators, not guarantees of website safety.
          </p>
        </div>

        <div className="relative mx-auto w-full max-w-lg">
          <div className="absolute -inset-5 rounded-[2rem] bg-blue-500/10 blur-2xl" />

          <div className="relative rounded-3xl border border-white/10 bg-[#0c1225]/95 p-6 shadow-2xl shadow-black/30 sm:p-8">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-sm text-slate-400">Platform overview</p>
                <h2 className="mt-2 text-xl font-semibold text-white">
                  Digital threat assessment
                </h2>
              </div>

              <div className="rounded-xl border border-cyan-400/20 bg-cyan-400/10 p-3">
                <ShieldCheck className="h-6 w-6 text-cyan-300" />
              </div>
            </div>

            <div className="mt-8 rounded-2xl border border-white/10 bg-white/[0.025] p-5">
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-400">Analysis modules</span>
                <span className="text-xs text-slate-500">4 categories</span>
              </div>

              <div className="mt-5 space-y-4">
                {scannerOptions.map((scanner) => {
                  const Icon = scanner.icon

                  return (
                    <div key={scanner.title} className="flex items-center gap-3">
                      <div className="rounded-lg bg-white/5 p-2.5">
                        <Icon className="h-5 w-5 text-cyan-300" />
                      </div>

                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-medium text-slate-200">
                          {scanner.title}
                        </p>
                        <p className="mt-1 text-xs text-slate-500">
                          {scanner.label}
                        </p>
                      </div>

                      <ArrowRight className="h-4 w-4 text-slate-600" />
                    </div>
                  )
                })}
              </div>
            </div>

            <div className="mt-5 flex items-start gap-3 rounded-xl border border-blue-400/15 bg-blue-500/5 p-4">
              <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-blue-300" />
              <p className="text-xs leading-6 text-slate-400">
                Scan results will be based on available security checks,
                configured reputation services, and supported detection models.
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section id="scanner" className="mx-auto max-w-5xl scroll-mt-24 px-5 py-12 lg:px-8">
      <div className="rounded-3xl border border-blue-400/20 bg-gradient-to-br from-blue-500/10 via-[#0c1225] to-cyan-500/5 p-6 sm:p-10">
        <div className="mx-auto max-w-3xl text-center">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl border border-blue-400/20 bg-blue-500/10">
            <Search className="h-6 w-6 text-cyan-300" />
          </div>

          <h2 className="mt-5 text-2xl font-bold text-white sm:text-3xl">
            Analyze a website
          </h2>

          <p className="mt-3 text-sm leading-7 text-slate-400 sm:text-base">
            Enter a website address to begin a security assessment.
          </p>

          <form onSubmit={handleScan} className="mt-7">
            <label htmlFor="website-url" className="sr-only">
              Website URL
            </label>

            <div className="flex flex-col gap-3 sm:flex-row">
              <input
                id="website-url"
                type="text"
                inputMode="url"
                autoComplete="url"
                placeholder="https://example.com"
                value={url}
                onChange={(event) => {
                  setUrl(event.target.value)
                  setMessage('')
                }}
                className="min-w-0 flex-1 rounded-xl border border-white/10 bg-[#050816] px-4 py-4 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-blue-400 focus:ring-2 focus:ring-blue-400/10"
              />

              <button
                type="submit"
                disabled={isScanning}
                className="inline-flex items-center justify-center gap-2 rounded-xl bg-blue-600 px-6 py-4 text-sm font-semibold text-white transition hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {isScanning ? 'Analyzing...' : 'Scan Website'}
                {!isScanning && <ArrowRight size={17} />}
              </button>
            </div>

            {message && (
              <p role="status" className="mt-4 text-left text-sm leading-6 text-cyan-200">
                {message}
              </p>
            )}

            {scanResult && (
              <div className="mt-6 rounded-2xl border border-white/10 bg-[#050816]/80 p-5 text-left sm:p-6">
                <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                  <div className="min-w-0">
                    <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                      Analysis result
                    </p>
                    <h3 className="mt-2 break-all text-lg font-semibold text-white">
                      {scanResult.hostname || scanResult.url}
                    </h3>
                    <p className="mt-1 break-all text-sm text-slate-400">
                      {scanResult.url}
                    </p>
                  </div>
                  <span className={`inline-flex w-fit rounded-full px-3 py-1 text-sm font-semibold ${
                    scanResult.risk_level === 'High'
                      ? 'bg-red-500/10 text-red-300 ring-1 ring-red-400/20'
                      : scanResult.risk_level === 'Medium'
                      ? 'bg-amber-500/10 text-amber-300 ring-1 ring-amber-400/20'
                      : 'bg-emerald-500/10 text-emerald-300 ring-1 ring-emerald-400/20'
                  }`}>
                    {scanResult.risk_level || 'Unknown'} Risk
                  </span>
                </div>

                <div className="mt-5 grid gap-3 sm:grid-cols-2">
                  <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
                    <p className="text-sm text-slate-400">Trust Score</p>
                    <p className="mt-2 text-3xl font-bold text-cyan-300">
                      {scanResult.trust_score ?? 'N/A'}
                      <span className="ml-1 text-sm font-medium text-slate-500">/ 100</span>
                    </p>
                  </div>
                  <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
                    <p className="text-sm text-slate-400">Risk Score</p>
                    <p className="mt-2 text-3xl font-bold text-white">
                      {scanResult.risk_score ?? 'N/A'}
                      <span className="ml-1 text-sm font-medium text-slate-500">/ 100</span>
                    </p>
                  </div>
                </div>

                <div className="mt-5">
                  <h4 className="font-semibold text-white">Security checks</h4>
                  {Array.isArray(scanResult.checks) && scanResult.checks.length > 0 ? (
                    <ul className="mt-3 space-y-3">
                      {scanResult.checks.map((check, index) => (
                        <li key={`${check.name}-${index}`} className="flex gap-3 rounded-xl border border-white/10 p-3">
                          <span className={`mt-0.5 h-2.5 w-2.5 shrink-0 rounded-full ${
                            check.status === 'pass' ? 'bg-emerald-400' :
                            check.status === 'warning' ? 'bg-amber-400' : 'bg-slate-500'
                          }`} />
                          <div>
                            <p className="text-sm font-medium text-slate-200">{check.name}</p>
                            <p className="mt-1 text-sm leading-6 text-slate-400">{check.details}</p>
                          </div>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="mt-2 text-sm text-slate-400">No individual checks were returned.</p>
                  )}
                </div>

                {Array.isArray(scanResult.risk_factors) && (
                  <div className="mt-5">
                    <h4 className="font-semibold text-white">Risk factors</h4>
                    {scanResult.risk_factors.length > 0 ? (
                      <ul className="mt-2 list-disc space-y-1 pl-5 text-sm leading-6 text-amber-200">
                        {scanResult.risk_factors.map((factor, index) => (
                          <li key={`${factor}-${index}`}>{factor}</li>
                        ))}
                      </ul>
                    ) : (
                      <p className="mt-2 text-sm text-emerald-300">No risk factors were detected by these basic checks.</p>
                    )}
                  </div>
                )}
            {Array.isArray(scanResult.recommendations) && (
              <div className="mt-5">
                <h4 className="font-semibold text-white">
                  Security Recommendations
                </h4>

                {scanResult.recommendations.length > 0 ? (
                  <ul className="mt-2 list-disc space-y-1 pl-5 text-sm leading-6 text-cyan-200">
                    {scanResult.recommendations.map((recommendation, index) => (
                      <li key={`${recommendation}-${index}`}>
                        {recommendation}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="mt-2 text-sm text-emerald-300">
                    No additional recommendations were returned.
                  </p>
                )}
              </div>
            )}


                <p className="mt-5 border-t border-white/10 pt-4 text-xs leading-6 text-slate-500">
                  {scanResult.message || 'This preliminary rule-based assessment is not a guarantee of website safety.'}
                  {' '}HTTPS and a low risk score do not prove that a website is trustworthy.
                </p>
              </div>
            )}
          </form>

          <p className="mt-4 text-xs leading-6 text-slate-500">
            Results currently use basic URL-pattern checks. The submitted website itself is not fetched or fully inspected.
          </p>
        </div>
      </div>
    </section>
<section
  id="qr-scanner"
  className="mx-auto max-w-7xl scroll-mt-24 px-5 py-20 lg:px-8"
>
  <div className="mx-auto max-w-3xl">
    <div className="mb-8">
      <p className="text-sm font-semibold uppercase tracking-[0.2em] text-emerald-300">
        QR Code Security Analysis
      </p>

      <h2 className="mt-4 text-3xl font-bold tracking-tight text-white sm:text-4xl">
        Scan a QR Code
      </h2>

      <p className="mt-4 leading-7 text-slate-400">
        Upload a QR code image to inspect its decoded destination.
      </p>
    </div>

    <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-6">
      <label
        htmlFor="qr-image"
        className="mb-3 block text-sm font-medium text-slate-200"
      >
        Upload QR Code Image
      </label>

      <input
        id="qr-image"
        type="file"
        accept="image/*"
        onChange={(event) => {
          setQrImage(event.target.files?.[0] || null)
          setQrResult(null)
        }}
        className="block w-full rounded-xl border border-white/10 bg-[#050816] p-3 text-sm text-slate-300 file:mr-4 file:rounded-lg file:border-0 file:bg-emerald-500/10 file:px-4 file:py-2 file:font-medium file:text-emerald-300"
      />

      {qrImage && (
        <p className="mt-3 break-all text-sm text-slate-400">
          Selected image: {qrImage.name}
        </p>
      )}

<button
  type="button"
  onClick={handleQrScan}
  disabled={qrLoading}
  className={`flex w-full items-center justify-center gap-2 rounded-xl px-5 py-3 font-semibold transition-all duration-200 ${
    qrLoading
      ? 'cursor-not-allowed bg-slate-600 text-slate-300'
      : 'bg-blue-600 text-white shadow-lg shadow-blue-600/20 hover:bg-blue-500 active:scale-[0.98]'
  }`}
>
  {qrLoading ? (
    <>
      <LoaderCircle className="h-5 w-5 animate-spin" />
      Analyzing QR Code...
    </>
  ) : (
    <>
      <ShieldCheck className="h-5 w-5" />
      Decode QR Code
    </>
  )}
</button>
    {qrResult && (
  <div className="mt-5 rounded-xl border border-white/10 bg-[#050816] p-4">
    <h3 className="font-semibold text-white">QR Code Analysis</h3>

    {typeof qrResult === 'string' ? (
      <p className="mt-2 break-all text-sm text-slate-300">
        {qrResult}
      </p>
    ) : (
      <>
        <p className="mt-3 text-sm text-slate-400">Scanned URL</p>
        <p className="mt-1 break-all text-sm text-white">
          {qrResult.url}
        </p>

        {qrResult.error ? (
          <div className="mt-4 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3">
            <p className="text-sm text-amber-300">
              Analysis could not be completed: {qrResult.error}
            </p>
          </div>
        ) : qrResult.analysis ? (
          <>
            <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="rounded-lg border border-white/10 bg-white/5 p-4">
                <p className="text-sm text-slate-400">Digital Trust Score</p>
                <p className="mt-2 text-3xl font-bold text-white">
                  {qrResult.analysis.trust_score ?? 'N/A'}
                  {qrResult.analysis.trust_score != null ? '/100' : ''}
                </p>
              </div>

              <div className="rounded-lg border border-white/10 bg-white/5 p-4">
                <p className="text-sm text-slate-400">Risk Level</p>
                <p className="mt-2 text-2xl font-bold text-white">
                  {qrResult.analysis.risk_level ?? 'N/A'}

                </p>
              </div>
            </div>
                        {/* QR Risk Warning Banner */}

            <div
                className={`mt-4 rounded-xl border p-4 ${
                qrResult.analysis.risk_level?.toLowerCase() === 'high'
                    ? 'border-red-500/50 bg-red-500/15'
                    : qrResult.analysis.risk_level?.toLowerCase() === 'medium'
                      ? 'border-orange-500/50 bg-orange-500/15'
                      : 'border-emerald-500/50 bg-emerald-500/15'
                }`}
            >
              <h4 className="font-semibold text-white">
                {qrResult.analysis.risk_level?.toLowerCase() === 'high'
                  ? '⚠️ High Risk Detected'
                  : qrResult.analysis.risk_level?.toLowerCase() === 'medium'
                    ? '⚠️ Potential Risk Detected'
                    : '✓ Low Risk — Basic Checks Passed'}
              </h4>

              <p className="mt-2 text-sm text-slate-300">
                Trust Score: {qrResult.analysis.trust_score ?? 'N/A'}/100
              </p>

              <p className="mt-1 text-sm text-slate-300">
                Risk Level: {qrResult.analysis.risk_level ?? 'Unknown'}
              </p>

              <p className="mt-3 text-xs text-slate-400">
                This is a preliminary automated assessment, not a guarantee
                that the website is safe. Verify the website before sharing
                personal or financial information.
              </p>
            </div>

            {Array.isArray(qrResult.analysis.checks) && (
              <div className="mt-5">
                <h4 className="font-semibold text-white">Security Checks</h4>

                <div className="mt-3 space-y-3">
                  {qrResult.analysis.checks.map((check, index) => (
                    <div
                      key={`${check.name}-${index}`}
                      className="rounded-lg border border-white/10 p-3"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="text-sm font-medium text-white">
                          {check.name}
                        </span>

                        <span
                          className={`rounded-full px-2 py-1 text-xs ${
                            check.status === 'pass'
                              ? 'bg-emerald-500/10 text-emerald-300'
                              : 'bg-amber-500/10 text-amber-300'
                          }`}
                        >
                          {check.status}
                        </span>
                      </div>

                      <p className="mt-2 text-sm text-slate-400">
                        {check.details}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {Array.isArray(qrResult.analysis.risk_factors) &&
              qrResult.analysis.risk_factors.length > 0 && (
                <div className="mt-5">
                  <h4 className="font-semibold text-amber-300">Risk Factors</h4>
                  <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-slate-300">
                    {qrResult.analysis.risk_factors.map((factor, index) => (
                      <li key={index}>{factor}</li>
                    ))}
                  </ul>
                </div>
              )}

            {Array.isArray(qrResult.analysis.recommendations) &&
              qrResult.analysis.recommendations.length > 0 && (
                <div className="mt-5">
                  <h4 className="font-semibold text-white">Recommendations</h4>
                  <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-slate-300">
                    {qrResult.analysis.recommendations.map((item, index) => (
                      <li key={index}>{item}</li>
                    ))}
                  </ul>
                </div>
              )}

            <p className="mt-4 text-xs text-slate-500">
              This is a preliminary, rule-based assessment—not a guarantee
              that the website is safe.
            </p>
          </>
        ) : null}
      </>
    )}
  </div>
)}
    </div>
  </div>
</section>

    <section id="sms-scanner" className="mx-auto max-w-7xl scroll-mt-24 px-5 py-20 lg:px-8">
  <div className="mx-auto max-w-3xl">
    <div className="mb-8">
      <p className="text-sm font-semibold uppercase tracking-[0.2em] text-cyan-300">
        SMS Security Analysis
      </p>

      <h2 className="mt-4 text-3xl font-bold tracking-tight text-white sm:text-4xl">
        Detect SMS Fraud
      </h2>

      <p className="mt-4 leading-7 text-slate-400">
        Analyze suspicious SMS messages to identify potential fraud indicators.
      </p>
    </div>

    <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-6 sm:p-8">
      <label
        htmlFor="sms-message"
        className="mb-3 block text-sm font-medium text-slate-200"
      >
        Enter SMS message
      </label>

      <textarea
        id="sms-message"
        value={smsText}
        onChange={(event) => setSmsText(event.target.value)}
        placeholder="Paste a suspicious SMS message here..."
        rows={5}
        maxLength={5000}
        className="w-full resize-y rounded-xl border border-white/10 bg-[#0c1225] p-4 text-sm leading-7 text-white outline-none transition placeholder:text-slate-500 focus:border-cyan-400/50"
      />

      <div className="mt-2 text-right text-xs text-slate-500">
        {smsText.length}/5000 characters
      </div>

      <button
        type="button"
        onClick={handleSmsScan}
        disabled={isSmsScanning}
        className="mt-5 rounded-xl bg-blue-600 px-6 py-3 font-semibold text-white transition hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
      >
        {isSmsScanning ? 'Analyzing SMS...' : 'Analyze SMS'}
      </button>

      {smsError && (
        <div
          role="alert"
          className="mt-5 rounded-xl border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-300"
        >
          {smsError}
        </div>
      )}

      {smsResult && (
        <div className="mt-8 rounded-xl border border-white/10 bg-[#0c1225] p-5 sm:p-6">
          <h3 className="text-xl font-semibold text-white">
            SMS Analysis Result
          </h3>

          <div className="mt-5 grid gap-4 sm:grid-cols-3">
            <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
              <p className="text-sm text-slate-400">Trust Score</p>
              <p className="mt-2 text-2xl font-bold text-emerald-400">
                {smsResult.trust_score}/100
              </p>
            </div>

            <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
              <p className="text-sm text-slate-400">Risk Score</p>
              <p className="mt-2 text-2xl font-bold text-amber-400">
                {smsResult.risk_score}/100
              </p>
            </div>

            <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
              <p className="text-sm text-slate-400">Risk Level</p>
              <p className="mt-2 text-2xl font-bold text-white">
                {smsResult.risk_level}
              </p>
            </div>
          </div>

          <div className="mt-6">
            <h4 className="font-semibold text-white">Detected Risk Factors</h4>

            {smsResult.risk_factors.length > 0 ? (
              <ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-slate-300">
                {smsResult.risk_factors.map((factor, index) => (
                  <li key={index}>{factor}</li>
                ))}
              </ul>
            ) : (
              <p className="mt-3 text-sm text-slate-400">
                No configured suspicious patterns were detected. This does not guarantee that the SMS is safe.
              </p>
            )}
          </div>

          <div className="mt-6">
            <h4 className="font-semibold text-white">Recommendations</h4>

            <ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-slate-300">
              {smsResult.recommendations.map((recommendation, index) => (
                <li key={index}>{recommendation}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      <p className="mt-5 text-xs leading-6 text-slate-500">
        This prototype uses predefined suspicious patterns. Results are
        indicators only and cannot guarantee that a message is safe or fraudulent.
      </p>
    </div>
  </div>
</section>

<section
  id="email-scanner"
  className="mx-auto max-w-7xl scroll-mt-24 px-5 py-20 lg:px-8"
>
  <div className="mx-auto max-w-3xl">
    <div className="mb-8">
      <p className="text-sm font-semibold uppercase tracking-[0.2em] text-cyan-300">
        Email Security Analysis
      </p>

      <h2 className="mt-4 text-3xl font-bold tracking-tight text-white sm:text-4xl">
        Detect Email Phishing
      </h2>

      <p className="mt-4 leading-7 text-slate-400">
        Analyze suspicious email content to identify potential phishing indicators.
      </p>
    </div>

    <div className="rounded-2xl border border-white/10 bg-white/[0.025] p-6 sm:p-8">
      <label
        htmlFor="email-content"
        className="mb-3 block text-sm font-medium text-slate-200"
      >
        Enter email content
      </label>

      <textarea
        id="email-content"
        value={emailText}
        onChange={(event) => setEmailText(event.target.value)}
        placeholder="Paste the suspicious email content here..."
        rows={7}
        maxLength={10000}
        className="w-full resize-y rounded-xl border border-white/10 bg-[#0c1225] p-4 text-sm leading-7 text-white outline-none transition placeholder:text-slate-500 focus:border-cyan-400/50"
      />

      <div className="mt-2 text-right text-xs text-slate-500">
        {emailText.length}/10000 characters
      </div>

      <button
        type="button"
        onClick={handleEmailScan}
        disabled={isEmailScanning}
        className="mt-5 rounded-xl bg-blue-600 px-6 py-3 font-semibold text-white transition hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
      >
        {isEmailScanning ? 'Analyzing Email...' : 'Analyze Email'}
      </button>

      {emailError && (
        <div
          role="alert"
          className="mt-5 rounded-xl border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-300"
        >
          {emailError}
        </div>
      )}

      {emailResult && (
        <div className="mt-8 rounded-xl border border-white/10 bg-[#0c1225] p-5 sm:p-6">
          <h3 className="text-xl font-semibold text-white">
            Email Analysis Result
          </h3>

          <div className="mt-5 grid gap-4 sm:grid-cols-3">
            <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
              <p className="text-sm text-slate-400">Trust Score</p>
              <p className="mt-2 text-2xl font-bold text-emerald-400">
                {emailResult.trust_score}/100
              </p>
            </div>

            <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
              <p className="text-sm text-slate-400">Risk Score</p>
              <p className="mt-2 text-2xl font-bold text-amber-400">
                {emailResult.risk_score}/100
              </p>
            </div>

            <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
              <p className="text-sm text-slate-400">Risk Level</p>
              <p className="mt-2 text-2xl font-bold text-white">
                {emailResult.risk_level}
              </p>
            </div>
          </div>

          <div className="mt-6">
            <h4 className="font-semibold text-white">
              Detected Risk Factors
            </h4>

            {Array.isArray(emailResult.risk_factors) &&
            emailResult.risk_factors.length > 0 ? (
              <ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-slate-300">
                {emailResult.risk_factors.map((factor, index) => (
                  <li key={index}>{factor}</li>
                ))}
              </ul>
            ) : (
              <p className="mt-3 text-sm text-slate-400">
                No configured suspicious patterns were detected. This does not guarantee that the email is safe.
              </p>
            )}
          </div>

          <div className="mt-6">
            <h4 className="font-semibold text-white">
              Recommendations
            </h4>

            <ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-slate-300">
              {Array.isArray(emailResult.recommendations) &&
                emailResult.recommendations.map((recommendation, index) => (
                  <li key={index}>{recommendation}</li>
                ))}
            </ul>
          </div>
        </div>
      )}

      <p className="mt-5 text-xs leading-6 text-slate-500">
        This prototype uses predefined suspicious patterns. Results are indicators
        only and cannot guarantee that an email is safe or fraudulent.
      </p>
    </div>
  </div>
</section>

    <section id="scanners" className="mx-auto max-w-7xl scroll-mt-24 px-5 py-20 lg:px-8">
      <div className="max-w-2xl">
        <p className="text-sm font-semibold uppercase tracking-[0.2em] text-cyan-300">
          One platform, multiple threats
        </p>
        <h2 className="mt-4 text-3xl font-bold tracking-tight text-white sm:text-4xl">
          Your digital security toolkit
        </h2>
        <p className="mt-4 leading-7 text-slate-400">
          Choose an analysis category. Each scanner will be connected to its
          corresponding backend service as development progresses.
        </p>
      </div>

      <div className="mt-10 grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
        {scannerOptions.map((scanner) => {
          const Icon = scanner.icon

          return (
            <button
              key={scanner.title}
              type="button"
              onClick={() => handleComingSoon(scanner.title)}
              className="group rounded-2xl border border-white/10 bg-white/[0.025] p-6 text-left transition duration-200 hover:-translate-y-1 hover:border-blue-400/30 hover:bg-blue-500/[0.04]"
            >
              <div className="flex items-center justify-between">
                <div className="rounded-xl border border-blue-400/15 bg-blue-500/10 p-3">
                  <Icon className="h-6 w-6 text-cyan-300" />
                </div>
                <ArrowRight className="h-5 w-5 text-slate-600 transition group-hover:translate-x-1 group-hover:text-cyan-300" />
              </div>

              <h3 className="mt-6 text-lg font-semibold text-white">
                {scanner.title}
              </h3>

              <p className="mt-3 text-sm leading-7 text-slate-400">
                {scanner.description}
              </p>

              <span className="mt-6 inline-block text-sm font-medium text-cyan-300">
                {scanner.label}
              </span>
            </button>
          )
        })}
      </div>
    </section>

    <section id="features" className="border-y border-white/5 bg-white/[0.015]">
      <div className="mx-auto max-w-7xl px-5 py-20 lg:px-8">
        <div className="mx-auto max-w-2xl text-center">
          <p className="text-sm font-semibold uppercase tracking-[0.2em] text-cyan-300">
            Built around evidence
          </p>
          <h2 className="mt-4 text-3xl font-bold text-white sm:text-4xl">
            Understand the risks, not just the score
          </h2>
          <p className="mt-4 leading-7 text-slate-400">
            The platform is designed to explain the indicators behind each
            assessment and distinguish confirmed findings from unavailable checks.
          </p>
        </div>

        <div className="mt-12 grid gap-6 md:grid-cols-3">
          {features.map((feature) => {
            const Icon = feature.icon

            return (
              <article
                key={feature.title}
                className="rounded-2xl border border-white/10 bg-[#0c1225]/70 p-7"
              >
                <div className="inline-flex rounded-xl border border-cyan-400/15 bg-cyan-400/10 p-3">
                  <Icon className="h-6 w-6 text-cyan-300" />
                </div>

                <h3 className="mt-5 text-lg font-semibold text-white">
                  {feature.title}
                </h3>

                <p className="mt-3 text-sm leading-7 text-slate-400">
                  {feature.description}
                </p>
              </article>
            )
          })}
        </div>
      </div>
    </section>

    <section id="how-it-works" className="mx-auto max-w-7xl scroll-mt-24 px-5 py-20 lg:px-8">
      <div className="grid gap-12 lg:grid-cols-2 lg:items-center">
        <div>
          <p className="text-sm font-semibold uppercase tracking-[0.2em] text-cyan-300">
            Simple workflow
          </p>

          <h2 className="mt-4 text-3xl font-bold text-white sm:text-4xl">
            From submitted target to security findings
          </h2>

          <p className="mt-5 leading-8 text-slate-400">
            The intended workflow combines input validation, security checks,
            available intelligence, and a transparent risk assessment.
          </p>
        </div>

        <div className="space-y-4">
          {[
            ['01', 'Submit a target', 'Enter a URL or choose a supported analysis type.'],
            ['02', 'Run security checks', 'Evaluate supported indicators and available evidence.'],
            ['03', 'Review the findings', 'Read the risk assessment and recommended next steps.'],
          ].map(([number, title, description]) => (
            <div
              key={number}
              className="flex gap-5 rounded-2xl border border-white/10 bg-white/[0.025] p-5"
            >
              <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-blue-500/10 text-sm font-bold text-cyan-300">
                {number}
              </div>

              <div>
                <h3 className="font-semibold text-white">{title}</h3>
                <p className="mt-2 text-sm leading-7 text-slate-400">
                  {description}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  </main>

  <footer className="border-t border-white/10">
  <section id="history" className="border-t border-white/10 py-16">
  <div className="mx-auto max-w-7xl px-5 lg:px-8">
    <div className="mb-8 flex flex-wrap items-center justify-between gap-4">
      <div>
        <h2 className="text-3xl font-bold text-white">
          Scan History
        </h2>
        <p className="mt-2 text-slate-400">
          View your previously scanned websites and their trust scores.
        </p>
      </div>

      <button
        onClick={loadScanHistory}
        disabled={historyLoading}
        className="rounded-lg border border-white/10 bg-white/5 px-4 py-2 text-sm font-medium text-white transition hover:bg-white/10 disabled:opacity-50"
      >
        {historyLoading ? 'Loading...' : 'Refresh History'}
      </button>
    </div>

    {historyError && (
      <p className="mb-4 rounded-lg border border-red-500/20 bg-red-500/10 p-4 text-red-300">
        {historyError}
      </p>
    )}

    {historyLoading && scanHistory.length === 0 ? (
      <p className="text-slate-400">Loading scan history...</p>
    ) : scanHistory.length === 0 ? (
      <div className="rounded-xl border border-white/10 bg-white/5 p-8 text-center">
        <p className="text-slate-300">No scan history found.</p>
        <p className="mt-2 text-sm text-slate-500">
          Scan a website to see its results here.
        </p>
      </div>
    ) : (
      <div className="overflow-x-auto rounded-xl border border-white/10">
        <table className="w-full min-w-[700px] text-left text-sm">
          <thead className="bg-white/5 text-slate-300">
            <tr>
              <th className="px-5 py-4 text-left">Scan Type</th>
              <th className="px-5 py-4">Website</th>
              <th className="px-5 py-4">Trust Score</th>
              <th className="px-5 py-4">Risk Score</th>
              <th className="px-5 py-4">Risk Level</th>
              <th className="px-5 py-4">Scanned At</th>
            </tr>
          </thead>

          <tbody className="divide-y divide-white/10">
{scanHistory.map((record) => {
  const isSms = record.scanned_url?.startsWith('SMS:')
  const isEmail = record.scanned_url?.startsWith('EMAIL:')

  return (
    <tr key={record.id} className="text-slate-300">
      {/* Scan Type */}
      <td className="px-5 py-4">
        <span
          className={`rounded-full border px-3 py-1 text-xs font-semibold ${
          isSms
              ? 'border-purple-400/30 bg-purple-400/10 text-purple-300'
              : isEmail
                  ? 'border-amber-400/30 bg-amber-400/10 text-amber-300'
                  : 'border-cyan-400/30 bg-cyan-400/10 text-cyan-300'
          }`}
        >
          {isSms ? '📱 SMS Scan' : '🌐 Website Scan'}
        </span>
      </td>

      {/* URL or SMS Message */}
      <td className="max-w-xs break-all px-5 py-4">
        {isSms
  ? record.scanned_url.slice(4).trim()
  : isEmail
    ? record.scanned_url.slice(6).trim()
    : record.scanned_url}
      </td>

      {/* Trust Score */}
      <td className="px-5 py-4 font-semibold text-emerald-400">
        {record.trust_score}/100
      </td>

      {/* Risk Score */}
      <td className="px-5 py-4 font-semibold text-amber-400">
        {record.risk_score}/100
      </td>

      {/* Risk Level */}
      <td className="px-5 py-4">
        <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1">
          {record.risk_level}
        </span>
      </td>

      {/* Scan Date */}
      <td className="whitespace-nowrap px-5 py-4 text-slate-400">
        {record.scanned_at
          ? new Date(record.scanned_at).toLocaleString()
          : 'N/A'}
      </td>
    </tr>
  )
})}
          </tbody>
        </table>
      </div>
    )}
  </div>
</section>
    <div className="mx-auto flex max-w-7xl flex-col gap-4 px-5 py-8 text-sm text-slate-500 sm:flex-row sm:items-center sm:justify-between lg:px-8">
      <p>© {new Date().getFullYear()} Digital Trust Score Platform</p>
      <p>Academic project · Security assessments are not guarantees of safety.</p>
    </div>
  </footer>
</div>
  );
}

export default App
