# Review: Spec „OAuth authorization server with per-session NetBox tokens“

- **Datum:** 2026-11-18
- **Scope:** `docs/superpowers/specs/2026-11-18-oauth-authorization-server-design.md` (Branch
  `oauth-plan-generic`, vor dem ersten Commit), abgeglichen mit `src/`, `tests/`, `fastmcp.json`, `.venv`
  (FastMCP 4.1.6, MCP SDK 2.3.0)
- **Teil 1 – Codex-Review:** `codex-reviewer`-Agent, Codex CLI 0.170.0, Modell `gpt-6.1-terra`, read-only;
  Einordnung und Zusatzbefunde (Z1–Z4) durch Claude
- **Teil 2 – Abgleich mit der Referenzimplementierung:** Claude-Agent, read-only, gegen
  `xwiki-mcp-server` `origin/hosted` @ 4a71e87 und den ungemergten Branch `fix/chatgpt-tools-protocol`
- **Gesamturteil:** Änderungen nötig, Architektur bestätigt. Nichts kritisch.
- **Status:** Alle Befunde am selben Tag in die Spec eingearbeitet, einschließlich der Maintainer-Entscheidung
  zur Häufigkeit der IdP-Prüfung (Spec §6.4).

## Teil 1: Codex-Review

| # | Schwere (eingeordnet) | Ort | Befund | Urteil | Maßnahme |
|---|---|---|---|---|---|
| 1 | hoch | §5.3, §6.4 | Userinfo-`sub` wird nicht gegen ID-Token-`sub` bzw. gespeicherte Verknüpfung geprüft | gültig (OIDC Core 5.3.2) | §5.3 Schritt 3, §6.4 |
| 2 | mittel | §6.1 | Eindeutiger Benutzername beweist keinen Besitz; lokales NetBox-Konto mit gleichem Namen würde verknüpft | wahrscheinlich gültig | §6.1: lokale Konten müssen auf die Sperrliste (Pflicht-Deployment-Schritt), Superuser abgelehnt |
| 3 | mittel | §5.4, §8 | (a) Replay-Fenster gibt Nachfolger an jeden Inhaber des alten Tokens; (b) nur ein alter Hash gespeichert → ältere Wiederverwendung beendet die Sitzung nicht | (b) gültig, (a) gültig, eng | §5.4: alle verbrauchten Hashes bis Sitzungsende; (a) als Restrisiko dokumentiert |
| 4 | mittel | §5.3, §6.4 | Fenster zwischen IdP-Antwort und Schreiben; Abgleich und Login können sich überholen | wahrscheinlich gültig | §6.4: IdP-Refresh je Sitzung serialisiert, unbekannter Ausgang schlägt geschlossen fehl |
| 5 | hoch | §6.2, §6.3 | Erneuerung ohne Marker, altes Token nicht atomar in die Aufräumliste; Erneuerung vs. Sitzungsende | gültig | §6.2: Marker auch bei Erneuerung, ein Schreibvorgang für Tausch + Aufräumeintrag, Sitzungs-Lock |
| 6 | hoch | §8 | „Fehlende Datei → leerer Zustand“ widerspricht dem Anti-Ziel „kein stiller Neuanfang“ | gültig | §8: fehlende Datei → Start verweigert, `netbox-mcp oauth init` |
| 7 | hoch | §8 | Restore bringt widerrufene Sitzungen zurück | gültig | §8: `oauth restore-reset` beendet alle wiederhergestellten Sitzungen |
| 8 | niedrig | §5.2, §5.3 | DCR-Client-Namen unverifiziert, gemerkte Zustimmung | überzogen (Redirect-Allowlist begrenzt Missbrauch) | §5.2/§5.3: Name als „unverifiziert“ angezeigt |
| 9 | mittel | §5.4, §5.5 | Refresh und Revoke prüfen `client_id` nicht | gültig | §5.4, §5.5 |
| 10 | mittel | §2, §6.3, §6.4 | „höchstens ein Tag“ vs. „nicht erreichbar → behalten“; Ergebnis des erkennenden Tool-Calls offen | gültig | §6.4: IdP-Prüfung bei jedem Refresh begrenzt den Zugriff auf ≈ 1 h; §6.3 Tool-Fehler, dann 401 |
| 11 | mittel | §5.1, §9 | `MCP_PUBLIC_URL` und IdP-URLs nicht validiert | gültig | §5.1 Startprüfung |
| 12 | niedrig | §7.2, §7.5 | „kein Schlüssel `content`“ mehrdeutig; „herunterverhandeln“ nur bei `initialize` | wahrscheinlich gültig | §7.2, §7.6 umformuliert |
| 13 | hoch | §4, `server.py`, `fastmcp.json` | Äußere App braucht `lifespan=mcp_app.lifespan`; Ablehnung von `fastmcp run` in `main()` greift nie | gültig (verifiziert, `fastmcp/server/http.py:104-106`) | §4: Lifespan-Komposition, Marker-Prüfung im FastMCP-Lifespan, Tests für beide Startwege |
| 14 | mittel | `auth.py:319-330` | Rate-Limit nach DCR-`client_id` statt nach Nutzer | gültig (verifiziert) | §4: Schlüssel `claims["sub"]` |
| 15 | niedrig | `tests/test_settings_documented.py:11-14` | Doku-Test scannt neue Module nicht | gültig (verifiziert) | §9 |
| Z1 | mittel | §3, §1 | Personenname und Ich-Form in einem öffentlichen Repo | gültig | neutral formuliert („maintainer decision“) |
| Z2 | niedrig | §3, §10 | Spec verweist auf nicht committete Spike-Dateien | gültig | Anhang A, Mock-IdP-Anforderungen in §10 |
| Z3 | Info | §4 | `JWTIssuer` deckt die Claims ab (`jwt_issuer.py:105-160`) | – | §4 festgelegt |
| Z4 | Info | §7.3 | FastMCP hat eigenen Host/Origin-Schutz (`mixins/transport.py:367-405`) | – | §4: abgestimmt konfigurieren, äußere Schicht maßgeblich |

## Teil 2: Abgleich mit der Referenzimplementierung

Klassen: (a) bewusst/begründet, (b) Lücke, (c) Widerspruch, der einen Client brechen kann.

| # | Bereich | Referenz | Klasse | Maßnahme in der Spec |
|---|---|---|---|---|
| 1 | Scopes | ein Ressourcen-Scope, kein `openid` | (c) | §5.1: Scope `netbox`; die frühere Angabe „wie in der Referenz“ beruhte auf einem veralteten lokalen Branch |
| 2 | `resource` | optional, ein abschließender `/` toleriert | (c) | §5.3, §5.4 |
| 3 | Root-Aliase `/register`, `/authorize`, `/token`, `/revoke` | echte Handler (Claude Code) | (b) | §5.1 |
| 4 | Erneuerung vs. laufender Tool-Call | `tokenVersion`, einmal mit aktuellem Token wiederholen | (b)/(c) | §6.2, §6.3 |
| 5 | Verwaiste Sitzungen (Code nie eingelöst) | Ende nach 10 min | (b) | §6.3 |
| 6 | Replay-Fenster | ein Slot, strikt < 30 s, Body nicht verglichen, Lock | (b) | §5.4 exakt beschrieben (strenger bei alten Hashes) |
| 7 | Transport | zustandslos, GET/DELETE 405, Notifications 202 | (b) | §4, §7.5 |
| 8 | `/mcp/` | wird bedient | (c) | §7.4 |
| 9 | DCR-Auth-Methode | nie ablehnen, immer `none` | (b) | §5.2 |
| 10 | Redirect-Validierung im Detail | Grenzen, Zeichen, Muster | (b) | §5.2 |
| 11 | Query-Strings im Log | nur Pfad | (b) | §4, §9: Access-Log aus |
| 12 | pending-create | atomares Entfernen, 10-min-Schutz, auch bei Erneuerung | (b) | §6.2 |
| 13 | IdP bei jedem Refresh | ja, Sperre ≈ 1 h | (a) | übernommen (Maintainer-Entscheidung), §5.4, §6.4 |
| 14 | Code-Wiederverwendung | `invalid_grant`, Sitzung bleibt; TTL 5 min | (a)/(c) | §5.4, §5.3: wie Referenz |
| 15 | Fehlerrouting | Validierungsfehler als HTML-Seite; IdP-`error` → `access_denied` | (a) | §5.3 |
| 16 | 401-Header | `realm`, `/mcp/.well-known/...`, `error` nur mit Token | (b) | §7.1 |
| 17 | Protokollversionen | echtes Datum, > neueste, ≤ 2 Jahre; `initialize` → neueste | (b) | §7.2 |
| 18 | Tool-Ergebnisse | `structuredContent` als Objekt, Listen gewrappt; nicht live verifiziert | (b) | §7.6 |
| 19 | Flow-Cookie und Header | Pfad, 10 min, Lax, no-store, no-referrer, Anti-Framing | (b) | §5.3 |
| 20 | Revoke-Details | 200 für unbekannte Tokens, abgelaufene widerrufbar | (b) | §5.5 |
| 21 | IdP-/NetBox-Klassifikation | Userinfo 401, fehlende Gruppen, kein Redirect-Folgen, HTML = nicht erreichbar | (b) | §6.4 |
| 22 | Access-Token-Prüfung | `client_id` = Sitzungs-Client | (b) | §5.4 |
| 23 | Root-`openid-configuration` | nicht ausgeliefert | (a) | §5.1 entfernt |
| 24 | Speicherformat | Feldweise versiegelt, leere Datei sofort geschrieben | (a) | §8 Abweichung markiert; Start ohne Datei verweigert |
| 25–28 | Aufräumtakt, Registrierungsablauf, CORS, PKCE zum IdP | – | (a)/(b) | §6.3, §5.2 (30 Tage), §2 (kein CORS), §5.3 |

Fixes der Referenz nach Client-Fehlern, die die erste Fassung nicht abdeckte und die jetzt drinstehen: Root-Aliase
(Claude Code), Notification 202 (Codex CLI), toleranter `resource` mit Slash, Objekt-Wrapping für
`structuredContent`, exakte Versionsregel.

## Entscheidung

Spec §6.4: IdP-Prüfung bei jedem Client-Refresh (wie Referenz, Sperre ≈ 1 h, IdP-Ausfall blockiert den
Refresh) statt täglich. Maintainer-Entscheidung 2026-11-18. Die 48-h-Veraltungsregel aus Codex-Befund 10
entfällt damit; der tägliche Lauf prüft nur noch die NetBox-Seite.
