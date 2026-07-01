from pathlib import Path

def generate_html_report(results):

    file = Path("results/report.html")

    html = "<h1>DNS Benchmark</h1><table border=1>"

    html += "<tr><th>IP</th><th>Score</th><th>Grade</th></tr>"

    for r in results:
        html += f"<tr><td>{r['ip']}</td><td>{r['score']}</td><td>{r['grade']}</td></tr>"

    html += "</table>"

    file.write_text(html)

    return file
