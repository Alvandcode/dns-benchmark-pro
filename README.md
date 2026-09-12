# DNS Benchmark Pro

[![Stars](https://img.shields.io/github/stars/Alvandcode/dns-benchmark-pro?style=flat-square)](https://github.com/Alvandcode/dns-benchmark-pro/stargazers) [![License](https://img.shields.io/github/license/Alvandcode/dns-benchmark-pro?style=flat-square)](./LICENSE) [![Last commit](https://img.shields.io/github/last-commit/Alvandcode/dns-benchmark-pro?style=flat-square)](https://github.com/Alvandcode/dns-benchmark-pro/commits)

> Advanced DNS benchmark (UDP, DoH, DoT) with scoring, latency stats and HTML/JSON/CSV reports.

<div dir="rtl">

## ابزار تست و مقایسه DNS

ابزار پیشرفته برای تست و مقایسه سرعت سرورهای DNS با پشتیبانی از UDP و DoH و DoT؛ همراه با امتیازدهی، آمار تأخیر و گزارش HTML و JSON و CSV.

</div>

---

# 🚀 DNS Benchmark Pro

## 📌 معرفی پروژه

DNS Benchmark Pro یک ابزار برای تست و مقایسه سرعت DNS سرورها است که به شما کمک می‌کند بهترین DNS را از نظر سرعت، پایداری و میزان خطا انتخاب کنید.

---

## ✨ قابلیت‌ها

- تست همزمان DNSها با کنترل همروندی (`--concurrency`)
- پشتیبانی واقعی از UDP و DoH و DoT (`--protocol udp|doh|dot`)
- محاسبه دقیق عملکرد:
  - میانگین زمان پاسخ
  - میانه (Median)
  - صدک 95 (P95, مرتب‌شده)
  - Packet Loss
  - min/max/stdev
- سیستم امتیازدهی مستند برای رتبه‌بندی DNSها
- خروجی گرفتن از نتایج:
  - CSV (utf-8-sig برای اکسل فارسی)
  - JSON (utf-8)
  - HTML (با جدول کامل + نمودار matplotlib)

---

## ⚙️ نصب

```bash
pip install -r requirements.txt
```

## ▶️ نحوه اجرا

اجرای ساده:

```bash
python main.py
```

اجرای پیشرفته:

```bash
python main.py --queries 20 --timeout 3 --protocol udp
python main.py --dns 1.1.1.1 8.8.8.8 178.22.122.100 --queries 30 --protocol doh
python main.py --protocol dot --output-dir results --seed 42 --concurrency 20
python main.py --qtype AAAA --domains google.com github.com aparat.com --verbose
python -m dns_benchmark --protocol udp --queries 5
```

## 🇮🇷 پریست ایران و مقایسه پایدار

```bash
python main.py --list-presets
python main.py --preset ir --queries 20 --seed 42
python main.py --preset ir --domain-group internal --queries 20
python main.py --preset ir --domain-group external --queries 20
# repeat N times and rank by mean score with 95% confidence interval:
python main.py --preset ir --queries 20 --runs 3 --run-delay 2 --seed 42
```

خروجی حالت مقایسه (`score=94.47±10.44` یعنی ناپایدار؛ `±0.11` یعنی پایدار) در `results/compare_runs.json` هم ذخیره می‌شود.

## 🕵️ تشخیص hijack (پروکسی شفاف)

روی پروتکل `udp` به‌صورت پیش‌فرض برای هر سرور یک پروب `.invalid` (طبق RFC 2606 حتماً باید NXDOMAIN بدهد) فرستاده می‌شود:

- `clean` → پاسخی سالم، interception دیده نشد
- `HIJACKED (...)` → مسیر UDP هایجک شده؛ عددهای UDP یعنی «تأخیر پروکسی» نه سرور واقعی — با `--protocol doh` مقایسه کنید
- با `--no-hijack-check` می‌توانید ردش کنید

## 📖 راهنمای تفسیر نتیجه

- `loss > 5%` یعنی قطع‌ووصلی؛ برای گیم/تماس بد است حتی اگر میانگین خوب باشد.
- اختلاف زیاد `p95` با `average` یعنی ناپایداری (جیتر)؛ در جدول مقایسه به `±` دقت کنید.
- عدد خیلی خوب ولی مشکوک (مثلاً 0.6ms برای سرور خارجی) را با ستون `hijack` و یک ران `doh` راستی‌آزمایی کنید.
- یک ران کافی نیست: حداقل `--runs 3 --queries 20` و در ساعت‌های مختلف تکرار کنید.

نمایش همه گزینه‌ها:

```bash
python main.py --help
```

---

## 📊 خروجی‌ها

بعد از اجرا، فایل‌های زیر ساخته می‌شوند (هر اجرا بازنویسی می‌شود):

```text
results/result.csv
results/result.json
results/report.html
results/chart.png
results/compare_runs.json   # only with --runs N (N>1)
```

---

## 📈 نمونه خروجی

```text
1. 1.1.1.1 → 96.4 (A+)
2. 8.8.8.8 → 92.1 (A)
3. 9.9.9.9 → 88.7 (B)
```

---

## 🧠 نحوه عملکرد و فرمول امتیاز

این ابزار به ترتیب زیر کار می‌کند:

1. تولید درخواست DNS (دامنه‌های واقعی؛ با `--bypass-cache` ساب‌دامین تصادفی)
2. ارسال همزمان درخواست‌ها به سرورها (UDP/53 یا DoH/443 یا DoT/853)
3. اندازه‌گیری زمان پاسخ
4. تحلیل نتایج (average/median/p95/loss)
5. امتیازدهی و رتبه‌بندی
6. تولید گزارش نهایی

فرمول امتیاز (0 تا 100):

```text
loss >= 100% یا بدون نمونه موفق → 0
وگرنه: 100 - loss*0.7 - min(avg/4, 20) - min(max(p95-avg,0)/10, 10)
```

فقط پاسخ NOERROR (RCODE 0) موفق حساب می‌شود؛ NXDOMAIN موفق نیست.

---

## ⚠️ نکات شبکه و حریم خصوصی

- در ویندوز/ایران ممکن است UDP/53 توسط فایروال یا ISP محدود شود؛ در این صورت `TIMEOUT` می‌گیرید. با `--protocol doh` یا `dot` دوباره امتحان کنید.
- کوئری‌ها به سرورهای ثالث ارسال می‌شود؛ دامنه‌های حساس را بنچمارک نکنید.
- برای نتیجه پایدار چند بار اجرا کنید و `--seed` بدهید تا قابل بازتولید شود.

---

## 📁 ساختار پروژه

```text
dns_benchmark/
├── cli.py
├── async_engine.py
├── dns_client.py
├── doh_client.py
├── dot_client.py
├── dns_packet.py
├── statistics.py
├── scoring.py
├── exporter.py
├── dashboard.py
├── advisor.py
├── hijack.py
├── compare.py
├── presets.py
├── qtypes.py
└── query_generator.py
tests/
presets/ir.json
.github/workflows/ci.yml
```

اجرای تست‌ها:

```bash
pytest -q
```

---

## ⭐ حمایت از پروژه

اگر این پروژه برایت مفید بود، می‌توانی:

به پروژه در GitHub ستاره بدهی

آن را با دیگران به اشتراک بگذاری

---

## 📢 کانال ارتباطی

@a_c_official

---

## 📄 لایسنس

MIT License

---

## 👨‍💻 توسعه‌دهنده

این پروژه برای تحلیل و تست عملکرد DNS سرورها توسعه داده شده است.

---

## Contributing / مشارکت

- EN: Issues and Pull Requests are welcome. Please see `CONTRIBUTING.md`.
- FA: برای گزارش مشکل یا پیشنهاد قابلیت جدید، لطفا ایشو یا پول‌ریکوئست ثبت کنید.

## License / لایسنس

MIT — see [LICENSE](./LICENSE).

## Contact / ارتباط

- Telegram: https://t.me/a_c_official
- Website: https://alvandcode.github.io
