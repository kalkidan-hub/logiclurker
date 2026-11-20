# Neuro-Symbolic SQL Injection Analysis

An experimental project exploring how language models and symbolic reasoning can complement one another when reviewing SQL injection (SQLi) scanner results. ZAP traffic is used to identify candidates; an optional Gemini pass triages them, and a Z3-based rule check evaluates observable evidence. The notebooks are research prototypes, not a production security product.

## Project layout

| Path | Purpose |
| --- | --- |
| `neuro_symbolic_tool/llm_with_symbolic_verifier.ipynb` | Main pipeline: load ZAP JSON, identify candidates, optionally use Gemini, and apply symbolic checks. |
| `neuro_symbolic_tool/exp_wiz_z3.ipynb` | Standalone Z3 rule experiments and report generation. |
| `neuro_symbolic_tool/here_and_there_exp.ipynb` | Early Gemini classification experiment. |
| `rule_based_tool/sqliZap.py` | Connects to a running ZAP instance, runs an active SQLi scan, and exports traffic, alerts, and an HTML report. |
| `scanner/` | Earlier scanner and ZAP-session record-building prototypes. |

## Setup

Use Python 3.10 or later. From the repository root, install the packages used by the notebooks and scanner:

```powershell
python -m pip install jupyter pandas python-dotenv google-generativeai z3-solver python-owasp-zap-v2.4 requests
```

For Gemini triage, create a local `.env` file in the repository root:

```text
GOOGLE_API_KEY=your_api_key
GEMINI_MODEL=gemini-2.0-flash
```

The notebook also accepts `GEMINI_API_KEY`. Keep API keys out of source control. The Gemini step sends selected request/response details to the configured model provider; remove credentials, personal data, and other sensitive information before using it.

## Running the main notebook

1. Start Jupyter from the repository root:

   ```powershell
   jupyter lab
   ```

2. Open `neuro_symbolic_tool/llm_with_symbolic_verifier.ipynb`.
3. Ensure `zap_alerts.json` and `zap_scan_traffic.json` are available in `rule_based_tool/`. The notebook reads both files from that directory. The scanner script writes them to its current working directory, so copy or move the generated files there before running the notebook.
4. Run the notebook cells in order. Without a Gemini API key, LLM triage is skipped; the notebook may not emit confirmed findings because its final output requires both LLM and symbolic checks to pass.

## Generating ZAP data

`rule_based_tool/sqliZap.py` connects to an already-running ZAP instance. Configure `ZAP_HOST`, `ZAP_PORT`, and `ZAP_API_KEY` as needed, and set `TARGET_URL` to an intentionally vulnerable application that you own or are authorized to test. Its default target is a local lab URL. Run from the repository root:

```powershell
python rule_based_tool/sqliZap.py
```

The script writes `zap_scan_traffic.json`, `zap_alerts.json`, and `zap_report.html` to the current directory. Active scans send attack traffic; only scan systems for which you have explicit permission, preferably in an isolated local lab.

## Interpreting results

The Z3 checks encode explicit rules over payload features and response signals such as SQL-error-like text and HTTP status. They do not model a database or prove that a vulnerability is exploitable. A “confirmed” result is therefore a prototype classification, not a guarantee; validate findings against the application and its behavior.
