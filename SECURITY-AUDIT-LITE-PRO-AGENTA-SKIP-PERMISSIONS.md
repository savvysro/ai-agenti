# Jednoduchý noční bezpečnostní audit (LITE) — návod pro agenta

> **Komu je to určené:** autonomnímu agentovi (Codex / Claude Code / Hermes / Antigravity)
> běžícímu na **virtuálním serveru (Linux/VPS)**. Cílem je postavit **jednoduchý**, ale
> dostatečně dobrý **noční bezpečnostní audit**, který každou noc zkontroluje hlavní hrozby
> + zanalyzuje nová rizika (CVE), a **ráno dá laikovi lidsky vědět**: buď „✅ vše v pořádku",
> nebo srozumitelně popíše problém a **zeptá se, jestli to má vyřešit**.
>
> Záměrně **JEDNODUCHÉ**: vynech FIM (file integrity monitoring) i Lynis. Žádný žargon.

---

## 0. POKYN PRO AGENTA — postav to celé sám (od A do Z)

**Uživatel je laik**, není to expert na bezpečnost ani na příkazovou řádku. **Nezatěžuj ho
technickými dotazy.** Máš na server práva, tak to celé **nastav, otestuj a rozjeď sám**:
- Vše si odvoď z běžícího systému (jaký OS, co běží, jaký firewall). Když něco nevíš, zvol
  rozumný default, ne dotaz.
- Audit je **READ-ONLY** – jen čte a analyzuje, sám od sebe nic nemění. Měnit (instalovat
  update, zavřít port) smíš jen **po výslovném ANO od uživatele** v ranní zprávě.
- **NIKDY nevypínej a neměň `--dangerously-*` / `--skip-permissions` / `--bypass-approvals`
  režimy agentů (Claude Code, Codex, Antigravity, OpenClaw, Hermes).** Jsou ZÁMĚRNÉ a NUTNÉ pro
  autonomní provoz – ber je jako **vědomě akceptované riziko**, ne jako nález k opravě. Smíš je
  nanejvýš zmínit v sekci „vědomě akceptováno", ale **nikdy je nezakazuj ani neomezuj** – ani
  po „ano" od uživatele (tahle položka je z auto-oprav natvrdo vyňatá). Vypnout je = rozbít
  celý multiagentní systém.
- **NEŘEŠ přihlašování přes SSH heslem.** Na těchto serverech se lidé přihlašují **jménem a
  heslem** – je to ZÁMĚRNÉ a **vědomě akceptované riziko**. Neoznačuj `passwordauthentication yes`
  jako nález, nenavrhuj přechod na jen‑klíče ani to nevypínej (ani po „ano"). U SSH řeš jen
  vypnutý root‑login a ochranu proti brute‑force (fail2ban) – ne způsob přihlášení.
- Ranní zpráva musí být **lidská a krátká** (semafor 🟢/🟡/🔴, žádné odborné pojmy).
- Na konci uživateli napiš jen jednu větu: že audit běží a kdy mu chodí ranní souhrn.

---

## 1. Jak to funguje — 3 kroky denně (cron)

```
  03:00  noční audit     →  read-only kontroly + analýza nových CVE  →  report na disk
  07:30  failsafe        →  když ráno report chybí, pošli 1 upozornění (nezávislé na AI)
  07:45  ranní souhrn    →  ze reportu vytáhni semafor a pošli lidsky na Telegram
```

- **Noční audit:** cron spustí skript, který posbírá fakta o stavu serveru (porty, updaty,
  firewall, SSH, přihlášení…), pak je **agent (LLM)** zanalyzuje + dohledá čerstvé CVE a
  napíše report s ranním semaforem.
- **Failsafe:** deterministická pojistka bez AI – kdyby audit z jakéhokoli důvodu nepoběžel,
  ráno to nezůstane tiše.
- **Ranní souhrn:** pošle uživateli krátký semafor; když je vše OK, jeden řádek „vše v pořádku".

---

## 2. Co audit kontroluje (hlavní hrozby — jednoduše, bez FIM/Lynis)

Noční read-only skript (`audit_collect.sh`) posbírá fakta; příkazy pro Linux/VPS:

| Oblast | Co a proč | Příkaz (read-only) |
|--------|-----------|--------------------|
| **1. Updaty / patche** | neaktualizovaný software = hlavní riziko | `apt-get -s upgrade` nebo `apt list --upgradable`; bezpečnostní: `unattended-upgrade --dry-run` / `ls /var/run/reboot-required` |
| **2. Vystavené porty** | co poslouchá do internetu (0.0.0.0) | `ss -tulnp` (porovnej s očekávaným; cokoli navíc na 0.0.0.0 = flag) |
| **3. Firewall** | je vůbec zapnutý? | `ufw status verbose` (nebo `nft list ruleset` / `iptables -S`) |
| **4. SSH** | nejčastější vstupní brána | z `sshd -T`: `permitrootlogin` (ideál: root no). **Přihlašování heslem (`passwordauthentication yes`) je u těchto serverů ZÁMĚRNÉ a vědomě akceptované – NEhlásit jako problém ani nenavrhovat vypnutí / přechod na klíče** (viz §0). Sleduj jen root‑login a brute‑force ochranu (bod 5). |
| **5. Pokusy o vloupání** | brute-force na SSH | `journalctl -u ssh --since "24 hours ago" | grep -ci "failed\|invalid"`; je fail2ban? `systemctl is-active fail2ban` |
| **6. Účty & přístup** | kdo má sudo, kdo se přihlásil | `getent group sudo`; `last -5`; nové/neznámé účty v `/etc/passwd` (UID ≥ 1000) |
| **7. Persistence (lehce)** | nové cron joby / služby (známka napadení) | `crontab -l`; `ls /etc/cron.*`; nové `systemctl list-units --type=service --state=running` |
| **8. Podezřelé procesy/spojení** | neznámý proces s odchozím spojením | `ps aux --sort=-%cpu | head`; `ss -tunp state established` (výběrově) |
| **9. Disk & zálohy** | plný disk = výpadek; je záloha? | `df -h /`; existuje a běží nějaká záloha? |

> Skript jen **vypíše fakta do souboru** (`/var/log/audit-lite/facts-<datum>.txt`). Nic nemění.
> Pokud chybí nástroj (ufw apod.), poznamenej to a pokračuj – nepadej.

---

## 3. Noční analýza novych rizik (CVE) — povinná, ale krátká

Po sběru faktů **agent** (LLM) udělá:
1. Přečte si posbíraná fakta + **minulý report** (dělá diff: co je nové/vyřešené).
2. **Dohledá čerstvé CVE/advisories** (poslední týden) pro tenhle stack – web search +
   ideálně ověř 1–2 přes `https://services.nvd.nist.gov/rest/json/cves/2.0` nebo
   `https://api.osv.dev/v1/querybatch`. Cíl: OS (Ubuntu/Debian), běžící služby (nginx,
   ssh, databáze…), runtime (Node/Python), a to, co reálně běží na vystavených portech.
   **Strop ~6 dotazů**, žádné zahrabávání.
3. U každého nálezu: *riziko – jestli se nás týká (běží to tu? je to vystavené?) – co dělat*.

---

## 4. Ranní report (pro laika!) — formát

**Vše jde na TELEGRAM.** Komunikace s uživatelem je výhradně přes Telegram bota:
- ráno **semafor souhrn** (7:45),
- **failsafe upozornění**, když audit nedoběhl (7:30),
- a **interakce „mám to vyřešit? → ano"** taky přes Telegram (uživatel odpoví v chatu).

Agent zapíše report na disk a na konec dá **„## Shrnutí pro Telegram"** = semafor. Ranní
skript ho pošle botem uživateli.

**JAZYK: ČESKY**, lidsky, bez žargonu. **Formát = řádky pod sebou**, na každém:
> **`🟢/🟡/🔴 – popis`** (emoji, mezera, česká pomlčka „–", mezera, krátký popis problému).

Jeden řádek = jedna věc. Pravidla:
- **Pořadí podle závažnosti:** nejdřív **všechny 🔴**, pak **všechny 🟡**, nakonec **🟢** (nejdůležitější nahoře).
- **Vše v pořádku → jen zelené řádky a ŽÁDNÁ otázka.** (Klidně jen jeden.)
- Jakmile je nějaký 🟡/🔴: vypiš všechny řádky pod sebou a **na úplný konec dej JEDNU otázku**:
  `❓ Mám opravit vše, co půjde? (napiš ano)` — NE otázku ke každé položce zvlášť.
- Po odpovědi **„ano"** agent **opraví vše, co umí** (updaty, zapnutí firewallu, SSH jen na
  klíče, fail2ban…); co nejde opravit automaticky, jen krátce vypíše. Pak potvrdí, co opravil.
  Bez „ano" nemění nic.

**Příklad – vše v pořádku:**
```
🟢 – Vše v pořádku, server je v bezpečí. Žádné nové hrozby.
```

**Příklad – jsou problémy (pod sebou + jedna otázka na konci):**
```
🔴 – Na internetu je vystavená databáze (port 5432 na 0.0.0.0), měla by být jen lokálně
🟡 – K dispozici 3 bezpečnostní aktualizace
🟢 – Firewall zapnutý, za 24 h žádný pokus o vloupání

❓ Mám opravit vše, co půjde? (napiš ano)
```

---

## 4b. 🚦 Vizuální dashboard se semafory

Kromě Telegramu nech audit i **vizuálně** – jednoduchá webová stránka se **semafory**
(jako náš monitoring dashboard). Princip: noční agent kromě reportu zapíše malý
**`status.json`**, který stránka jen vykresluje. Žádný backend netřeba.

**Noční agent navíc zapíše `status.json`** (vedle reportu) – stav každé oblasti + celkový:
```json
{
  "updated": "2026-06-17 03:04",
  "overall": "green",
  "areas": [
    {"name": "Aktualizace", "status": "yellow", "note": "3 bezpečnostní updaty k instalaci"},
    {"name": "Firewall", "status": "green", "note": "zapnutý (ufw)"},
    {"name": "SSH", "status": "green", "note": "přihlášení heslem (záměrné, akceptováno), root‑login vypnutý"},
    {"name": "Pokusy o vloupání", "status": "green", "note": "0 za 24 h"},
    {"name": "Účty a přihlášení", "status": "green", "note": "beze změn"},
    {"name": "Vystavené porty", "status": "green", "note": "jen očekávané"},
    {"name": "Procesy / cron", "status": "green", "note": "nic nového"},
    {"name": "Nové hrozby (CVE)", "status": "green", "note": "žádné relevantní"},
    {"name": "Disk / zálohy", "status": "green", "note": "42 % místa, záloha OK"}
  ]
}
```

**Stránka `index.html`** (jeden soubor, statická, servíruj přes `python3 -m http.server`
na portu jen v rámci VPN/LAN) – velký celkový semafor nahoře + karta s 🟢/🟡/🔴 tečkou
na každou oblast, auto-refresh 60 s:
```html
<!doctype html><html lang="cs"><head><meta charset="utf-8">
<title>🛡️ Bezpečnost serveru</title>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-slate-50 text-slate-800 p-5 max-w-2xl mx-auto">
<h1 class="text-xl font-bold mb-1">🛡️ Bezpečnost serveru</h1>
<p id="overall" class="text-lg font-semibold mb-4">načítání…</p>
<div id="areas" class="grid gap-2"></div>
<p id="foot" class="text-xs text-slate-400 mt-4"></p>
<script>
const DOT={green:"bg-emerald-500",yellow:"bg-amber-500",red:"bg-rose-500"};
const TXT={green:"🟢 Vše v pořádku",yellow:"🟡 Něco ke zvážení",red:"🔴 Vyžaduje pozornost"};
async function load(){
  const d=await (await fetch("status.json?_="+Date.now())).json();
  document.getElementById("overall").textContent=TXT[d.overall]||"—";
  document.getElementById("areas").innerHTML=d.areas.map(a=>
    `<div class="flex items-center gap-3 rounded-lg border bg-white px-3 py-2">
       <span class="h-3 w-3 rounded-full ${DOT[a.status]||'bg-slate-300'} shrink-0"></span>
       <span class="font-medium w-44">${a.name}</span>
       <span class="text-sm text-slate-500">${a.note||""}</span></div>`).join("");
  document.getElementById("foot").textContent="aktualizováno "+d.updated+" · auto-refresh 60 s";
}
load(); setInterval(load,60000);
</script></body></html>
```
- **Barvy = ty samé semafory jako na Telegramu** (zelená/žlutá/červená) – laik na první pohled vidí, jestli je vše OK.
- Stránku dej **jen do VPN/LAN** (ne veřejně) – je to o stavu serveru.
- Volitelně: ranní Telegram zpráva může obsahovat i odkaz na ten dashboard.

---

## 5. Failsafe (pojistka bez AI)

Jednoduchý skript v 07:30: ověří, že **dnešní report existuje a není prázdný**. Když chybí,
pošle uživateli **jedno** upozornění („⚠️ Noční bezpečnostní audit dnes neproběhl, mrknu na
to."). Tím se tichý výpadek nezamlčí. Idempotentní (jeden alert za den).

---

## 6. Setup checklist (co agent udělá)

1. Vytvoř adresář `/var/log/audit-lite/` + skripty:
   - `audit_collect.sh` – sběr faktů (§2) do `facts-<datum>.txt`.
   - `audit_run.sh` – spustí collect, pak řekne agentovi „analyzuj fakta + CVE a napiš report
     `report-<datum>.md` (sekce + Shrnutí pro Telegram) **a `status.json`** (semafory pro
     dashboard, §4b)". (Trigger do tvé vlastní session / `hermes -z` / obdoba.)
   - `audit_failsafe.py` – kontrola existence dnešního reportu → Telegram alert.
   - `audit_digest.py` – vytáhne „## Shrnutí pro Telegram" a pošle **na Telegram**.
   - `index.html` + `status.json` – vizuální dashboard se semafory (§4b).
2. **Telegram** (povinné – tudy chodí vše uživateli): bot token + chat_id uživatele
   (ranní souhrn, failsafe, interakce ano/ne). `chmod 600` na config.
3. **Dashboard:** servíruj složku se `status.json`+`index.html` přes `python3 -m http.server`
   na portu jen v VPN/LAN; přidej do cronu `@reboot` keepalive, ať běží i po restartu.
4. Cron (uživatelský, bez roota kde to jde):
   ```cron
   0 3 * * *   /bin/bash /opt/audit-lite/audit_run.sh
   30 7 * * *  /usr/bin/python3 /opt/audit-lite/audit_failsafe.py
   45 7 * * *  /usr/bin/python3 /opt/audit-lite/audit_digest.py
   @reboot     /bin/bash /opt/audit-lite/serve_dashboard.sh
   ```
5. **Test:** spusť `audit_run.sh` ručně → musí vzniknout dnešní report + `status.json`,
   dorazit ranní semafor **na Telegram**, a dashboard ukázat semafory.
6. Uživateli napiš jednu větu: „Hotovo – každé ráno ti pošlu na Telegram krátký bezpečnostní souhrn se semafory (a je i vizuální stránka); když bude něco potřeba, zeptám se."

---

## 7. Co NEdělat (ať to zůstane jednoduché)
- ❌ Žádný FIM (hashování souborů), žádný Lynis – vynecháno záměrně.
- ❌ Audit **sám od sebe nic nemění** – jen po „ano" od uživatele.
- ❌ **NIKDY nevypínej `--dangerously-*` / `--skip-permissions` / `--bypass-approvals` režimy
  agentů** – jsou záměrné a nutné, vědomě akceptované riziko. Ani je nenavrhuj k vypnutí, ani
  po „ano". Vypnout je = rozbít celý multiagentní systém.
- ❌ **Neřeš přihlašování přes SSH heslem** – je záměrné a vědomě akceptované. Nehlásit, nenavrhovat
  jen‑klíče, nevypínat. U SSH řeš jen root‑login a brute‑force ochranu.
- ❌ Žádné dlouhé technické reporty uživateli – ten dostane jen semafor + lidskou větu.
- ✅ Drž to malé: ~9 kontrol + krátká CVE rešerše + ranní semafor. To je „dost dobrý" audit pro VPS laika.

---

### Shrnutí jednou větou
> Každou noc agent read-only zkontroluje hlavní hrozby (updaty, porty, firewall, SSH, útoky,
> účty, persistence) + dohledá nové CVE, a ráno pošle laikovi **semafor**: buď „🟢 vše v pořádku",
> nebo srozumitelně popíše problém a **zeptá se, jestli ho má vyřešit**. Bez FIM, bez Lynisu, bez žargonu.
