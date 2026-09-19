# 🚀 DNS Benchmark Pro

[![Stars](https://img.shields.io/github/stars/Alvandcode/dns-benchmark-pro?style=flat-square)](https://github.com/Alvandcode/dns-benchmark-pro/stargazers)
[![CI](https://img.shields.io/github/actions/workflow/status/Alvandcode/dns-benchmark-pro/ci.yml?style=flat-square&label=CI)](https://github.com/Alvandcode/dns-benchmark-pro/actions)
[![Python](https://img.shields.io/badge/python-%3E%3D3.9-blue?style=flat-square)](./pyproject.toml)
[![License](https://img.shields.io/github/license/Alvandcode/dns-benchmark-pro?style=flat-square)](./LICENSE)
[![Last commit](https://img.shields.io/github/last-commit/Alvandcode/dns-benchmark-pro?style=flat-square)](https://github.com/Alvandcode/dns-benchmark-pro/commits)

> **EN:** Find your fastest DNS. Benchmark UDP, DoH & DoT resolvers with honest scoring, hijack detection, multi-run comparison and 24/7 monitoring.
>
> **FA:** سریع‌ترین DNS را پیدا کن. مقایسه دقیق ریزالورها روی UDP و DoH و DoT با امتیازدهی شفاف، تشخیص هایجک، مقایسه چندرانه و مانیتورینگ دائمی.

<div dir="rtl" lang="fa">

## ابزاری برای انتخاب بهترین DNS — نه حدس، با عدد

کدام DNS برای تو بهتر است؟ گوگل؟ کلادفلر؟ شکان؟ الکترو؟ این ابزار به هر کدام **امتیاز ۰ تا ۱۰۰** می‌دهد تا با عدد تصمیم بگیری — نه با شنیده‌ها.

</div>

<p align="center">
  <a href="https://alvandcode.github.io/dns-benchmark-pro/tutorial.html"><b>🎓 آموزش قدم‌به‌قدم با گوشی و کامپیوتر — کلیک کنید</b></a>
  <br/>
  <sub>Step-by-step tutorial (phone & desktop) — live page, or open <code>docs/tutorial.html</code> in your browser after cloning.</sub>
</p>

---

## 🎓 Tutorial | آموزش تصویری

**New here? Start with the visual step-by-step tutorial** (Persian, phone & desktop separated): **[📖 Open the tutorial](https://alvandcode.github.io/dns-benchmark-pro/tutorial.html)** — after cloning you can also just open `docs/tutorial.html` in any browser.

<div dir="rtl" lang="fa">

**تازه واردی؟ از آموزش تصویری شروع کن** (فارسی، تفکیک‌شده برای گوشی و کامپیوتر): **[📖 باز کردن صفحه آموزش](https://alvandcode.github.io/dns-benchmark-pro/tutorial.html)** — آفلاین هم می‌توانی فایل `docs/tutorial.html` را بعد از کلون در مرورگر باز کنی.

</div>

---

## 📑 Contents | فهرست

- [🎓 Tutorial | آموزش تصویری](#-tutorial--آموزش-تصویری)
- [✨ Features | قابلیت‌ها](#-features--قابلیتها)
- [✅ Prerequisites | پیش‌نیازها](#-prerequisites--پیشنیازها)
- [⚡ Quick Start | شروع سریع](#-quick-start--شروع-سریع)
- [🇮🇷 Iran Preset | پریست ایران](#-iran-preset--پریست-ایران)
- [🕵️ Hijack Detection | تشخیص هایجک](#️-hijack-detection--تشخیص-هایجک)
- [📈 Compare & Monitor | مقایسه و مانیتورینگ](#-compare--monitor--مقایسه-و-مانیتورینگ)
- [📊 Sample Output | نمونه خروجی](#-sample-output--نمونه-خروجی)
- [🧠 How Scoring Works | فرمول امتیاز](#-how-scoring-works--فرمول-امتیاز)
- [📁 Project Structure | ساختار پروژه](#-project-structure--ساختار-پروژه)
- [🤝 Contributing | مشارکت](#-contributing--مشارکت)
- [⭐ Support | حمایت](#-support--حمایت)
- [📢 Contact | ارتباط](#-contact--ارتباط)
- [📄 License | لایسنس](#-license--لایسنس)

---

## ✨ Features | قابلیت‌ها

| | EN | FA |
|---|---|---|
| 🔀 | **3 protocols**: UDP, DNS-over-HTTPS, DNS-over-TLS | **۳ پروتکل**: UDP و DoH و DoT |
| 📊 | **Honest stats**: mean, median, sorted P95, loss, stdev | **آمار صادقانه**: میانگین، میانه، P95 واقعی، لاس، انحراف معیار |
| 🏆 | **Documented 0–100 score** + grades A+…F | **امتیاز مستند ۰ تا ۱۰۰** + گرید از A+ تا F |
| 🕵️ | **Hijack detection** via `.invalid` probe (RFC 2606) | **تشخیص هایجک** مسیر UDP با پروب `.invalid` |
| 🔁 | **Multi-run compare** with 95% confidence intervals | **مقایسه چندرانه** با فاصله اطمینان ۹۵٪ |
| 🇮🇷 | **Iran preset**: Shecan, Electro, 403.online + public resolvers; internal vs external domains | **پریست ایران**: شکان، الکترو، 403 + عمومی؛ تفکیک دامنه داخلی/خارجی |
| 📡 | **Monitoring mode**: SQLite history + score trend chart | **مانیتورینگ**: تاریخچه SQLite + نمودار روند امتیاز |
| 📄 | **Reports**: CSV (Excel-friendly), JSON, HTML + charts | **گزارش**: CSV، JSON، HTML همراه نمودار |
| 🛡️ | **Safe by design**: NXDOMAIN never counts as success, input validation, no secret leaks | **امنیت در طراحی**: NXDOMAIN موفق حساب نمی‌شود، اعتبارسنجی ورودی |

---

## ✅ Prerequisites | پیش‌نیازها

**EN:** You need **Python ≥3.9** (per `requires-python` in `pyproject.toml`), **pip** (ships with Python) and **git** to clone the repo:

```bash
python --version   # must be 3.9+
pip --version
git --version
```

<div dir="rtl" lang="fa">

**FA:** به **پایتون ۳.۹ یا جدیدتر** (طبق `pyproject.toml`)، ابزار **pip** (همراه پایتون نصب می‌شود) و **git** برای کلون کردن ریپو نیاز داری:

```bash
python --version   # باید 3.9 به بالا باشد
pip --version
git --version
```

</div>

---

## ⚡ Quick Start | شروع سریع

```bash
pip install -r requirements.txt

# Simple: benchmark 3 popular resolvers
python main.py

# Advanced: 20 queries, DoH protocol, reproducible seed
python main.py --queries 20 --protocol doh --seed 42 --verbose

# Your own servers, IPv6-ready, AAAA records
python main.py --dns 1.1.1.1 8.8.8.8 178.22.122.100 --qtype AAAA

# Everything is documented:
python main.py --help
# ...or as a module:
python -m dns_benchmark --queries 5
```

<div dir="rtl" lang="fa">

```bash
pip install -r requirements.txt

# ساده: تست ۳ ریزالور معروف
python main.py

# حرفه‌ای: ۲۰ کوئری با پروتکل DoH و سید ثابت (نتیجه قابل تکرار)
python main.py --queries 20 --protocol doh --seed 42 --verbose
```

</div>

---

## 🇮🇷 Iran Preset | پریست ایران

**EN:** One flag loads Iranian resolvers (Shecan ×2, Electro ×2, 403.online ×2 — the last only routable from Iranian IPs) plus Cloudflare/Google/Quad9, with a query pool split into **internal** (aparat, digikala, divar, shaparak) and **external** domains. Find out which DNS is better for Iranian sites vs the rest of the web:

```bash
python main.py --list-presets
python main.py --preset ir --queries 20 --seed 42
python main.py --preset ir --domain-group internal --queries 20
python main.py --preset ir --domain-group external --queries 20
```

<div dir="rtl" lang="fa">

**FA:** با یک فلگ، ریزالورهای ایرانی (شکان، الکترو، 403) به‌علاوه عمومی‌ها لود می‌شود و دامنه‌ها به **داخلی** و **خارجی** تقسیم شده‌اند. این‌طوری می‌فهمی کدام DNS برای سایت‌های داخلی بهتر است و کدام برای بقیه وب:

```bash
python main.py --preset ir --queries 20 --seed 42
python main.py --preset ir --domain-group internal --queries 20
python main.py --preset ir --domain-group external --queries 20
```

> نکته: آی‌پی‌های `10.202.10.x` مخصوص 403 فقط از داخل ایران جواب می‌دهند؛ بیرون ایران `TIMEOUT` می‌گیری که طبیعی است.

</div>

---

## 🕵️ Hijack Detection | تشخیص هایجک

**EN:** On UDP (on by default, `--no-hijack-check` to skip), each server gets a probe for `<random>.example.invalid`. Per RFC 2606 `.invalid` can never exist, so a *clean* path must answer NXDOMAIN. If a server answers NOERROR with an IP, your UDP traffic is intercepted and the latency numbers mean *"proxy latency"*, not the real server — the report flags it as `HIJACKED` and tells you to cross-check with `--protocol doh`:

```bash
python main.py --dns 1.1.1.1 8.8.8.8 --queries 10
# hijack=clean  →  numbers trusted |  hijack=HIJACKED (10.0.0.1)  →  verify with DoH
```

<div dir="rtl" lang="fa">

**FA:** روی UDP به‌صورت خودکار برای هر سرور یک پروب `.invalid` فرستاده می‌شود؛ این دامنه طبق استاندارد هیچ‌وقت وجود ندارد پس جواب سالم حتماً باید NXDOMAIN باشد. اگر سروری آی‌پی برگرداند یعنی مسیر UDP شنود/هایجک شده و عددهایش یعنی «تأخیر پروکسی» نه سرور واقعی — گزارش آن را `HIJACKED` می‌زند و پیشنهاد می‌کند با DoH راستی‌آزمایی کنی.

</div>

---

## 📈 Compare & Monitor | مقایسه و مانیتورینگ

**EN:** One run is noisy — routing, cache state and rate limits move the numbers. Repeat and compare:

```bash
# 3 runs, ranked by mean score with 95% CI (wide ± means unstable!)
python main.py --preset ir --queries 20 --runs 3 --run-delay 2 --seed 42

# 24/7 monitoring: tick every 5 min into SQLite, Ctrl+C stops safely
python main.py --preset ir --queries 10 --watch 300 --seed 42
# 6 ticks, 60s apart (great for cron / Task Scheduler):
python main.py --dns 1.1.1.1 8.8.8.8 --watch 60 --watch-count 6

# inspect history:
python main.py --history 10
python main.py --trend            # all servers + results/trend.png
python main.py --trend 1.1.1.1    # one server
```

<div dir="rtl" lang="fa">

**FA:** یک ران نویز دارد — مسیریابی و کش و لیمیت، عددها را جابه‌جا می‌کنند. راه درست: تکرار و مقایسه با فاصله اطمینان، یا مانیتورینگ دائمی با تاریخچه SQLite و نمودار روند. (مثال: امتیاز `94.47±10.44` یعنی ناپایدار، ولی `99.75±0.11` یعنی پایدار.)

</div>

---

## 📊 Sample Output | نمونه خروجی

```text
COMPARISON (3 runs, 95% CI)
1.                1.1.1.1  score=99.75±0.11  grade=A+ avg=0.95±0.32ms loss=0.0% hijack=clean
2.                8.8.8.8  score=94.47±10.44 grade=A  avg=12.86±23.63ms loss=0.0% hijack=clean

BEST:
{'recommended': '1.1.1.1', 'score': 99.75, 'grade': 'A+', ...}

FILES:
results/result.csv
results/result.json
results/compare_runs.json
results/report.html
```

Reports land in `results/` (overwritten each run, git-ignored): `result.csv` (Excel-friendly `utf-8-sig`), `result.json`, `report.html` (full table + avg-vs-P95 chart), `chart.png`, `compare_runs.json` (multi-run mode; in `--watch` mode per-tick history goes to SQLite instead), `history.db` + `trend.png` (monitoring mode).

**EN:** To see the HTML report, open the freshly generated `results/report.html` in your browser after a run — there is no committed sample report/chart file in the repo yet, so the text sample above is the reference for now; screenshots coming soon.

<div dir="rtl" lang="fa">

**FA:** برای دیدن گزارش HTML، بعد از هر اجرا فایل تازه‌ساخته‌شده `results/report.html` را در مرورگر باز کن — هنوز فایل نمونه کامیت‌شده‌ای در ریپو نیست، پس فعلاً همین نمونه متنی بالا مبناست؛ اسکرین‌شات به‌زودی اضافه می‌شود.

</div>

---

## 🧠 How Scoring Works | فرمول امتیاز

**EN:** Only `NOERROR` (RCODE 0) counts as success — NXDOMAIN never does. Packet loss hurts most, then average speed, then tail instability:

```text
loss >= 100% or zero successful samples  →  score = 0
otherwise:
  score = 100 - loss×0.7 - min(avg/4, 20) - min(max(p95-avg, 0)/10, 10)
```

Grades: `A+ ≥95 · A ≥90 · B ≥80 · C ≥65 · D ≥40 · F <40`.

<div dir="rtl" lang="fa">

**FA:** فقط جواب سالم (`NOERROR`) موفق حساب می‌شود؛ NXDOMAIN هرگز. بیشترین جریمه برای قطعی (loss) است، بعد میانگین تأخیر، بعد ناپایداری (فاصله P95 تا میانگین). اگر سروری ۱۰۰٪ لاس بدهد امتیازش **صفر** می‌شود — تعارف نداریم!

</div>

---

## ⚠️ Network & Privacy Notes | نکات شبکه و حریم خصوصی

- **EN:** On some networks (notably Iran) UDP/53 is filtered or proxied — `TIMEOUT` or suspiciously perfect numbers? Check the `hijack` column and retry with `--protocol doh`/`dot`.
- **FA:** در بعضی شبکه‌ها (مخصوصاً ایران) پورت UDP/53 فیلتر یا پروکسی می‌شود؛ اگر `TIMEOUT` گرفتی یا عددها زیادی خوب بودند، ستون hijack را ببین و با DoH دوباره تست بگیر.
- Queries go to third-party resolvers — don't benchmark sensitive domains. / کوئری‌ها به سرور ثالث می‌رود؛ دامنه حساس تست نکن.
- Reproducible runs: always pass `--seed`. / برای نتیجه قابل تکرار همیشه `--seed` بده.

---

## 📁 Project Structure | ساختار پروژه

```text
dns_benchmark/
├── cli.py            # flags, runs, watch/history/trend wiring
├── __main__.py       # `python -m dns_benchmark` entry
├── async_engine.py   # concurrent engine (UDP/DoH/DoT)
├── dns_client.py     # UDP + TCP fallback
├── doh_client.py     # DNS-over-HTTPS
├── dot_client.py     # DNS-over-TLS
├── dns_packet.py     # builder, validator, response parser
├── hijack.py         # transparent-proxy detection
├── compare.py        # multi-run aggregation (mean ± 95% CI)
├── monitor.py        # watch loop + trend chart
├── store.py          # SQLite history
├── presets.py        # named presets (--preset ir)
├── statistics.py     # mean/median/sorted-P95/loss/…
├── scoring.py        # 0–100 score + grades
├── exporter.py       # CSV / JSON
├── dashboard.py      # HTML report
├── advisor.py        # best-pick + warnings
├── qtypes.py         # A/AAAA normalisation
└── query_generator.py# real-domain pool (+IR sites), seedable
presets/ir.json
tests/               # 70 tests (pytest -q)
.github/workflows/ci.yml
```

```bash
pip install -r requirements.txt   # requests, matplotlib
pytest -q                         # run the test suite
pip install -e .                  # install the `dns-benchmark` command
```

---

## 🤝 Contributing | مشارکت

**EN:** Issues and Pull Requests are welcome! Please read [`CONTRIBUTING.md`](./CONTRIBUTING.md): fork, create a branch (`feat/my-feature`), add tests for your change, and open a PR against `main`. Bug reports with repro steps and logs get fixed fastest — use the Bug Report template.

<div dir="rtl" lang="fa">

**FA:** ایشو و پول‌ریکوئست همیشه خوش‌آمد است! لطفاً اول [`CONTRIBUTING.md`](./CONTRIBUTING.md) را بخوان: فورک کن، برنچ بساز، برای تغییرت تست اضافه کن و PR بزن. گزارش باگ با قدم‌های بازتولید و لاگ، سریع‌تر فیکس می‌شود.

</div>

---

## ⭐ Support | حمایت

**EN:** If this tool saved you from a slow DNS, support it — it takes 10 seconds:

- ⭐ **Star the repo** — it keeps the project alive and visible
- 📣 **Share it** with anyone still guessing their DNS
- 🐛 **Report bugs & ideas** via Issues — every report makes it better

<div dir="rtl" lang="fa">

**FA:** اگر این ابزار تو را از شر یک DNS کند نجات داد، حمایتش کن — فقط ۱۰ ثانیه طول می‌کشد:

- ⭐ **به ریپو ستاره بده** — همین ستاره انگیزه ادامه و دیده‌شدن پروژه است
- 📣 **با بقیه به اشتراک بذار** — هر کسی که هنوز DNSاش را شانسی انتخاب می‌کند
- 🐛 **باگ و ایده را ایشو کن** — هر گزارش، پروژه را بهتر می‌کند

</div>

---

## 📢 Contact | ارتباط

- 💬 Telegram channel: **[@a_c_official](https://t.me/a_c_official)** — news, updates and support
- 🌐 Website: [alvandcode.github.io](https://alvandcode.github.io)
- 🛡️ Security issues? **Do NOT open a public issue** — see [`SECURITY.md`](./SECURITY.md)

<div dir="rtl" lang="fa">

- 💬 کانال تلگرام: **[@a_c_official](https://t.me/a_c_official)** — اخبار، آپدیت‌ها و پشتیبانی
- 🌐 وب‌سایت: [alvandcode.github.io](https://alvandcode.github.io)

</div>

---

## 📄 License | لایسنس

MIT — see [LICENSE](./LICENSE).

👨‍💻 Built for everyone who refuses to guess their DNS. / ساخته‌شده برای همه کسانی که DNSشان را شانسی انتخاب نمی‌کنند.
