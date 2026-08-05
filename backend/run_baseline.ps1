# =============================================================================
#  Baseline Testing Script v2 — Secure File-Upload Filter (Graduation Project)
#  التحديث: تحكّم يدوي بالـ Content-Type لكل عيّنة (عبر HttpClient)
#           + إضافة فئة Content-Type/Extension mismatch (spoofing)
# =============================================================================

Add-Type -AssemblyName System.Net.Http

# --- إعدادات أساسية ---
$ApiUrl     = "http://localhost:5170/api/upload"
$SamplesDir = "C:\Users\ellio\Desktop\senior 2\webapp\test-samples"
$OutputCsv  = "C:\Users\ellio\Desktop\senior 2\webapp\backend\baseline_results.csv"

# -----------------------------------------------------------------------------
#  المصفوفة المرجعية (Ground Truth):
#  كل عيّنة: الاسم، الفئة، الـ Content-Type اللي نرسله، هل يجب رفضها؟، نوع الاختبار
#  ShouldReject = $true  → عيّنة يجب أن يرفضها الفلتر (خبيثة أو تلاعب)
#  ShouldReject = $false → عيّنة سليمة يجب أن يقبلها الفلتر
# -----------------------------------------------------------------------------
$Samples = @(
    # --- فئة profile (صور) ---
    @{ File="legit_photo.jpg"; Category="profile"; ContentType="image/jpeg";    ShouldReject=$false; Attack="Benign image"        }
    @{ File="active.svg";      Category="profile"; ContentType="image/svg+xml"; ShouldReject=$true;  Attack="SVG-XSS"             }
    @{ File="polyglot.png";    Category="profile"; ContentType="image/png";     ShouldReject=$true;  Attack="Polyglot"            }
    @{ File="shell.php.jpg";   Category="profile"; ContentType="image/jpeg";    ShouldReject=$true;  Attack="Double extension"    }
    @{ File="malware.png";     Category="profile"; ContentType="image/png";     ShouldReject=$true;  Attack="Malicious marker"    }

    # عيّنة الحجم الزائد (Oversize) — تُرفض بسبب تجاوز حد 5 ميغا
    @{ File="large.jpg";       Category="profile"; ContentType="image/jpeg";    ShouldReject=$true;  Attack="Oversize"            }

    # عيّنة magic-byte mismatch الجديدة (صغيرة) — تعدّي فحص الحجم، تُكشف فقط بالمحتوى
    @{ File="fake_image.jpg";  Category="profile"; ContentType="image/jpeg";    ShouldReject=$true;  Attack="Magic-byte mismatch" }

    # --- فئة id (ملفات) ---
    @{ File="legit_document.pdf"; Category="id"; ContentType="application/pdf"; ShouldReject=$false; Attack="Benign document"     }
    @{ File="legit_report.pdf";   Category="id"; ContentType="application/pdf"; ShouldReject=$false; Attack="Benign document"     }
    @{ File="js_embedded.pdf";    Category="id"; ContentType="application/pdf"; ShouldReject=$true;  Attack="PDF-embedded JS"     }
    @{ File="fake.pdf";           Category="id"; ContentType="application/pdf"; ShouldReject=$true;  Attack="Magic-byte mismatch" }

    # --- فئة Content-Type/Extension mismatch (spoofing) ---
    @{ File="legit_photo.jpg"; Category="profile"; ContentType="application/pdf"; ShouldReject=$true; Attack="Content-Type spoofing" }
)

# --- قائمة لتخزين النتائج ---
$Results = @()

Write-Host "`n=== بدء اختبار الـ Baseline على $($Samples.Count) عينات ===`n" -ForegroundColor Cyan

# -----------------------------------------------------------------------------
#  دالة رفع تتحكّم بالـ Content-Type يدوياً
#  ترجع كود الحالة HTTP + نص الرد
# -----------------------------------------------------------------------------
function Send-Upload {
    param($FilePath, $Category, $ContentType)

    $client  = [System.Net.Http.HttpClient]::new()
    $content = [System.Net.Http.MultipartFormDataContent]::new()

    try {
        # --- إضافة الملف مع الـ Content-Type المحدّد يدوياً ---
        $bytes       = [System.IO.File]::ReadAllBytes($FilePath)
        $fileContent = [System.Net.Http.ByteArrayContent]::new($bytes)
        $fileContent.Headers.ContentType =
            [System.Net.Http.Headers.MediaTypeHeaderValue]::new($ContentType)

        $fileName = [System.IO.Path]::GetFileName($FilePath)
        # اسم الحقل "file" لازم يطابق الباراميتر بالـ Controller
        $content.Add($fileContent, "file", $fileName)

        # --- إضافة حقل category ---
        $catContent = [System.Net.Http.StringContent]::new($Category)
        $content.Add($catContent, "category")

        # --- إرسال الطلب ---
        $response   = $client.PostAsync($ApiUrl, $content).GetAwaiter().GetResult()
        $statusCode = [int]$response.StatusCode
        $body       = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()

        return @{ Status = $statusCode; Body = $body }
    }
    finally {
        $content.Dispose()
        $client.Dispose()
    }
}

# -----------------------------------------------------------------------------
#  الحلقة الرئيسية
# -----------------------------------------------------------------------------
foreach ($s in $Samples) {
    $path = Join-Path $SamplesDir $s.File

    if (-not (Test-Path $path)) {
        Write-Host "⚠️  ملف مفقود: $($s.File) — تم تخطّيه" -ForegroundColor Yellow
        continue
    }

    try {
        $result     = Send-Upload -FilePath $path -Category $s.Category -ContentType $s.ContentType
        $statusCode = $result.Status
    }
    catch {
        Write-Host "❌ خطأ اتصال عند رفع $($s.File): $_" -ForegroundColor Red
        $statusCode = -1
    }

    # تفسير كود الحالة: 200=قُبِل، 422=رُفِض، 400=خطأ إدخال
    switch ($statusCode) {
        200     { $accepted = $true;  $decision = "ACCEPTED" }
        422     { $accepted = $false; $decision = "REJECTED" }
        400     { $accepted = $false; $decision = "BAD_REQUEST (400!)" }
        default { $accepted = $false; $decision = "ERROR ($statusCode)" }
    }

    # -------------------------------------------------------------------------
    #  تصنيف Confusion Matrix:
    #  يجب-رفضها + رُفض   → TP (مسكة صحيحة)
    #  يجب-رفضها + قُبِل  → FN (فشل — فاتت على الفلتر)  ← الأخطر
    #  سليمة + قُبِل      → TN (سماح صحيح)
    #  سليمة + رُفض       → FP (رفض خاطئ لملف سليم)
    # -------------------------------------------------------------------------
    if ($s.ShouldReject) {
        if (-not $accepted) { $outcome = "TP" } else { $outcome = "FN" }
    } else {
        if ($accepted)      { $outcome = "TN" } else { $outcome = "FP" }
    }

    # طباعة السطر بلون حسب النتيجة
    $color = switch ($outcome) {
        "TP" { "Green" }; "TN" { "Green" }
        "FN" { "Red"   }; "FP" { "Red"   }
    }
    $label = if ($s.ShouldReject) { "يُرفض" } else { "سليم" }
    Write-Host ("[{0}] {1,-22} ({2,-6}) CT={3,-17} {4,-9} → {5}" -f `
                $outcome, $s.File, $label, $s.ContentType, $decision, $s.Attack) `
                -ForegroundColor $color

    # تخزين النتيجة
    $Results += [PSCustomObject]@{
        File          = $s.File
        Category      = $s.Category
        SentType      = $s.ContentType
        AttackType    = $s.Attack
        ExpectedLabel = if ($s.ShouldReject) { "ShouldReject" } else { "Benign" }
        StatusCode    = $statusCode
        Decision      = $decision
        Outcome       = $outcome
    }
}

# -----------------------------------------------------------------------------
#  حساب المقاييس الإجمالية
# -----------------------------------------------------------------------------
$TP = ($Results | Where-Object Outcome -eq "TP").Count
$FN = ($Results | Where-Object Outcome -eq "FN").Count
$TN = ($Results | Where-Object Outcome -eq "TN").Count
$FP = ($Results | Where-Object Outcome -eq "FP").Count

$Recall    = if (($TP+$FN) -gt 0) { [math]::Round($TP/($TP+$FN), 3) } else { 0 }
$Precision = if (($TP+$FP) -gt 0) { [math]::Round($TP/($TP+$FP), 3) } else { 0 }
$F1        = if (($Precision+$Recall) -gt 0) { [math]::Round(2*($Precision*$Recall)/($Precision+$Recall), 3) } else { 0 }
$FPR       = if (($FP+$TN) -gt 0) { [math]::Round($FP/($FP+$TN), 3) } else { 0 }

# طباعة الملخص
Write-Host "`n=== ملخص النتائج (Confusion Matrix) ===" -ForegroundColor Cyan
Write-Host "TP (يجب رفضها، ورُفضت): $TP" -ForegroundColor Green
Write-Host "FN (يجب رفضها، لكن قُبلت): $FN" -ForegroundColor Red
Write-Host "TN (سليمة، وقُبلت):     $TN" -ForegroundColor Green
Write-Host "FP (سليمة، لكن رُفضت):  $FP" -ForegroundColor Red
Write-Host "`n--- المقاييس ---" -ForegroundColor Cyan
Write-Host "Recall (كشف ما يجب رفضه): $Recall"
Write-Host "Precision (دقة الرفض):    $Precision"
Write-Host "F1-Score:                 $F1"
Write-Host "FPR (رفض السليم خطأً):    $FPR"

# تصدير النتائج لملف CSV
$Results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
Write-Host "`n✅ تم تصدير النتائج التفصيلية إلى:" -ForegroundColor Green
Write-Host "   $OutputCsv`n"