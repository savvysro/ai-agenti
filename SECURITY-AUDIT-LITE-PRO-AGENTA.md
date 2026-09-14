# Noční security audit + ranní report — zadání

## 0. Rozsah

Audit se týká **výhradně stroje, na kterém běží AI agent** (tento server) — ne serverů obecně a ne jiné infrastruktury. Cílem je hlídat bezpečnost prostředí, ve kterém agent sám operuje.

Toto zadání počítá s agentem běžícím **bez `--dangerously-skip-permissions`** (tzn. v normálním režimu se schvalováním akcí) — o zapnutí/vypnutí takových režimů rozhoduje výhradně uživatel v daný okamžik, nikdy to není pevné pravidlo tohoto auditu.

## 1. Základní pravidla

- Systém je **read-only**: audit jen sbírá fakta a analyzuje, nic na serveru nemění.
- Žádné automatické opravy bez výslovného souhlasu uživatele ke **každé konkrétní** akci zvlášť. Souhlas se získává vždy znovu, nikdy se nepředpokládá z dřívějška.
- Všechna zjištění se hlásí tak, jak jsou – žádná kategorie rizika se natrvalo neignoruje ani neskrývá (pokud uživatel u konkrétního rizika řekne „tohle vědomě akceptuji, dál to nehlas", zapíše se to jako jeho explicitní rozhodnutí, ne jako pevné pravidlo agenta).
- Report v češtině, bez žargonu, se semaforem 🟢/🟡/🔴.

## 2. Časový plán

- **03:00** – noční audit: sběr faktů + CVE analýza → report na disk (diff oproti včerejšku)
- **07:30** – failsafe: kontrola, že dnešní report vznikl → pokud ne, upozornění do Telegramu
- **07:45** – ranní report do Telegramu (stejný chat, přes který se zadává toto zadání)

## 3. Pravidlo odesílání

- Report se posílá **jen když se liší od reportu z předchozího dne** (nová/zmizelá rizika, změna semaforu apod.).
- **Výjimka: v neděli se report posílá vždy**, i když je stejný jako v sobotu.

## 4. Co audit kontroluje

| Oblast | Příkaz |
|---|---|
| Dostupné aktualizace | `apt-get -s upgrade` / `apt list --upgradable` |
| Vystavené porty | `ss -tulnp` |
| Firewall | `ufw status verbose` |
| SSH konfigurace (root login, heslo vs. klíč) | `sshd -T` |
| Pokusy o přihlášení | `journalctl -u ssh --since "24 hours ago"` |
| Účty a přístupy | `getent group sudo`; `last -5` |
| Cron / služby | `crontab -l`; `ls /etc/cron.*` |
| Procesy | `ps aux --sort=-%cpu` |
| Disk | `df -h /` |

## 5. CVE analýza

Diff faktů oproti předchozímu dni, dohledání relevantních CVE k běžícím verzím (NVD/OSV API), jen k tomu, co se skutečně týká daného stacku.

## 6. Formát reportu (Telegram)

Vše v pořádku:

```
🟢 – Vše v pořádku, server je v bezpečí.
```

Nalezené problémy:

```
🔴 – Port 5432 vystavený na internetu
🟡 – 3 bezpečnostní aktualizace k dispozici
🟢 – Firewall aktivní

❓ Mám s něčím z tohoto pomoct opravit? Napiš, co konkrétně.
```

Žádná automatická oprava se nespouští jen na základě odpovědi „ano" – ke každé opravě je potřeba konkrétní potvrzení, co přesně se má udělat.

## 7. Failsafe

Pokud v 07:30 chybí dnešní report, pošle se do Telegramu zpráva: „⚠️ Noční bezpečnostní audit dnes neproběhl."

## 8. Doručení

Telegram – **stejný bot/chat, který se používá pro toto zadání a běžnou komunikaci s uživatelem**, ne nový ani jinak neověřený bot. Token a chat_id se použijí ty, které už tato integrace používá; pokud se zakládá nový bot, jeho token/chat_id musí uživatel sám potvrdit jako svůj vlastní. Žádný jiný/třetí kanál.

## 9. Setup checklist

1. `/var/log/audit-lite/` – ukládání denních reportů (pro diff)
2. Skripty: sběr faktů → report + porovnání s včerejškem → e-mail dle pravidla v bodě 3
3. Cron: `0 3 * * *`, `30 7 * * *`, `45 7 * * *`
4. Ruční test před nasazením
5. Nastavuje se jen na stroji, kde běží AI agent — ne na jiných serverech
