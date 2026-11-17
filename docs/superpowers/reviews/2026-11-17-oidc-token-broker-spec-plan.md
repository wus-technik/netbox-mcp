# Review: OIDC-Token-Broker – Spec und Plan

- **Datum:** 2026-11-17
- **Scope:** `docs/superpowers/specs/2026-11-17-oidc-token-broker-design.md`,
  `docs/superpowers/plans/2026-11-17-oidc-token-broker.md` (Branch `oauth-plan-generic`),
  abgeglichen mit `src/`, `tests/`, `pyproject.toml`/`uv.lock`, Dockerfile, README
- **Modell/Befehl:** Codex CLI 0.169.0, `gpt-6.1-sol`,
  `codex exec --sandbox read-only --model gpt-6.1-sol -`; Einordnung und Zusatzbefunde durch Claude
- **Gesamturteil:** Umsetzbar nach Korrekturen. Die Architektur steht, es fehlen Garantien und Plan-Tasks.

Status: alle Befunde am selben Tag in Spec und Plan eingearbeitet (siehe „Maßnahmen“).

## Befunde

| # | Schwere | Ort | Befund | Fix | Urteil |
|---|---|---|---|---|---|
| 1 | hoch | Spec §3 (~Z. 114); Plan Task 8 | Beim ersten Login wird `preferred_username` auf einen NetBox-User abgebildet. Das beweist nur Eindeutigkeit, nicht Besitz. Der Claim ist nicht stabil, und es gibt keine Unique-Regel auf `netbox_user_id`, sodass zwei `(iss, sub)` auf denselben User zeigen können. | Admin-kontrollierter Username-Namensraum oder vorab provisioniertes Mapping. UNIQUE auf `netbox_user_id` unter aktiven Identitäten. Tests für Kollision und Rename. | gültig |
| 2 | hoch | Spec §3 Z. 93–99; Plan Tasks 1, 12 | Authentik setzt PKCE S256 per Konfiguration nicht durch: Es bietet `plain` und `S256` an und akzeptiert Requests ohne Challenge. Die Vorgabe `["S256"]` für die Discovery ist so nicht erfüllbar. | Expression Policy für eine S256-Pflicht-Challenge. Anforderung auf „enthält `S256`“ ändern und auf die Negativ-Probes stützen. | wahrscheinlich gültig (Quelle nicht selbst geprüft) |
| 3 | hoch | Plan Task 9; `src/netbox_mcp/server.py:105-110` | `FastMCP` und der Auth-Provider entstehen beim Import, und `fastmcp run` ruft `main()` nicht auf. Kein Task regelt, wo Store-Lock, Recovery, Hintergrund-Loops und Shutdown laufen. | Neuer Task mit `FastMCP(lifespan=...)`. Test, dass der Import keinen Lock nimmt, und Test für Shutdown bei gehaltenen Leases. | gültig (verifiziert) |
| 4 | mittel | Plan Task 8; `src/netbox_mcp/retry.py:94-96` | Die Retry-Transport-Schicht wiederholt nicht-idempotente POSTs bei 429. Das widerspricht „ein POST pro Journal-Eintrag“. Branching würde zudem einen Branch-Lookup und den Header mit dem Broker-Token senden. | Broker-Client mit `retry=False` und `use_branch=False`. Tests: genau ein POST bei 429, kein Branch-Header. | gültig (verifiziert) |
| 5 | mittel | Spec §4 (~Z. 212); Plan Task 6 | Die JWKS-Discovery über den Issuer hat keinen Task. Authentik nutzt einen Path-Issuer mit Slash und nur die angehängte Form `/.well-known/openid-configuration`. Die AS-Metadata-Discovery der Clients (Reihenfolge nach MCP 2025-11-25) wird nicht geprüft. | Discovery-Schritt mit exakter URL-Konstruktion und exaktem Issuer-Vergleich. AS-Discovery je Client in die Phase-A-Probes aufnehmen. | gültig |
| 6 | mittel | Plan Tasks 6, 9; `src/netbox_mcp/auth.py:51-69, 143-158` | Ein einziges `JwtRejected` erlaubt kein `403 insufficient_scope`. Der 503-Handler hängt an `NetBoxTokenVerifier.get_middleware()` und geht beim Wrapping in einen äußeren Provider verloren. | Getypte Fehler (Scope → 403, Broker-Ablehnung → 403, Ausfall → 503). `on_error` am äußersten Provider. Regressionstest für 503. | gültig (FastMCP-Interna nicht lokal geprüft) |
| 7 | mittel | Spec §4, §8; Plan Tasks 6, 9 | Der Aufbau von `AccessToken` ist unklar: Wo liegt `netbox_mcp_auth_mode` (vermutlich `claims`)? `Identity` verliert `exp`, sodass `expires_at` fehlt. Die Leeway-Politik zwischen SDK und Spec ist uneinheitlich. | Marker in `claims`, vom Server gesetzt. `exp` → `expires_at`. Eine Leeway-Regel, getestet mit injizierter Uhr. | wahrscheinlich gültig |
| 8 | mittel | Plan Task 5; `tests/test_settings_documented.py:11-14` | Der Doku-Test scannt nur `netbox_client.py` und `utils.py`. Neue Variablen in `oidc/config.py` würden nicht geprüft. | Bestehendes Muster nutzen oder `SOURCES` erweitern. `.env.example`, README und `server.json`/`REGISTRY_EXCLUDED` explizit regeln. | gültig (verifiziert) |
| 9 | mittel (Codex: hoch) | Spec §1 Z. ~27–29, §4 | NetBox-Token-Passthrough auf demselben Endpoint verletzt die MCP-Regel „no token passthrough“. Das Verhalten besteht schon und ist beabsichtigt, ist also kein neues Risiko. | Als Kompatibilitätsausnahme dokumentieren, optional abschaltbar machen, wenn OIDC aktiv ist. `AccessToken.resource` nicht als Resource Binding ausgeben. | gültig |
| 10 | mittel | Spec §4 | „ID-Token muss scheitern, auch bei passender Audience“ – ohne Unterscheidungskriterium. Bei Authentik sind sich die Claims sehr ähnlich. | Kriterium festlegen (z. B. `scope`-Claim Pflicht oder `typ=at+jwt`) und in Phase A mit echten Tokens bestätigen. | gültig (Claude) |
| 11 | niedrig | Plan Z. 173 | `AuthentikJwtVerifier` widerspricht Spec §9 (keine anbieterspezifischen Namen im Paketcode). | In `OidcJwtVerifier` umbenennen. | gültig (verifiziert) |
| 12 | niedrig | Spec §4, §9 | `NETBOX_TOKEN_PASSTHROUGH=true` fehlt in der Pflichtliste. SSE-Status unklar. `TOKEN_STORE_PATH` ist optional ohne Default, obwohl der Store Pflicht ist. Dockerfile ohne Volume, läuft als UID 10001. | Store-Pfad verpflichtend oder mit Default. Transportregel festlegen. Tests in Task 5. | gültig (Claude) |
| 13 | niedrig | Plan (Deps) | PyJWT kommt neben joserfc/authlib (FastMCP) hinzu – zwei JOSE-Bibliotheken. | Wahl begründen oder vereinheitlichen. | Ermessensfrage |
| 14 | niedrig | Spec §3 | `codex mcp add --oauth-client-secret` landet in der Shell-History. | Weg ohne Kommandozeile vorschreiben. | gültig (Claude) |
| 15 | niedrig | Plan (Tests) | `tests/oidc/test_config.py` kollidiert mit `tests/test_config.py`. | `tests/oidc/__init__.py` anlegen. | unsicher |
| 16 | Info | Plan Task 4 (Gate) | Authentik setzt `aud = client_id` und unterstützt RFC 8707 vermutlich nicht. Das Gate dürfte Phase A stoppen. | Fallback vorab benennen (anderer IdP, Token Exchange). | Hinweis |
| 17 | Info | Spec §6–§8 | Die Generation/Lease/Journal-Mechanik ist umfangreich. | Prüfen, ob ein einfacherer Lebenszyklus die Ziele erfüllt. | Hinweis |

## Kompatibilität (Bestätigtes)

- Vorregistrierte Credentials sind der erste Registrierungsweg nach MCP 2025-11-25. Der Verzicht auf DCR und CIMD ist damit legitim.
- PRM-Pfade, `resource`-Wert und Scope-Challenge sind konsistent mit RFC 9728.
- Codex CLI 0.169.0 kennt `--oauth-client-id`/`--oauth-client-secret`.
- Die Callback-URLs von claude.ai und ChatGPT wurden nicht erneut verifiziert.

## Maßnahmen

| # | Umsetzung |
|---|---|
| 1 | Spec §3: admin-kontrollierter Username-Namensraum als Deployment-Voraussetzung, eine aktive Identität pro NetBox-User, keine automatische Neuverknüpfung. Spec §6: partieller Unique-Index. Plan Tasks 1, 7, 8, 12: Prüfung und Regressionstests. |
| 2 | Spec §3: Discovery „enthält S256“. Authentik-Expression-Policy, deren Machbarkeit Phase A belegen muss. Plan Tasks 1, 12. |
| 3 | Spec §8: Abschnitt „Server lifecycle“. Plan: neuer Task 9a (Lifespan, Loops, Shutdown, Import ohne Seiteneffekte). |
| 4 | Spec §5: Broker-Client mit `retry=False`/`use_branch=False`. Plan Task 8: Tests für 429 und Branching. |
| 5 | Spec §3/§4: AS-Discovery-Formen und JWKS-Discovery mit exaktem Issuer-Vergleich. Plan Tasks 2, 6. |
| 6 | Spec §4: Tabelle der getypten Ablehnungen, Handler am äußersten Provider. Plan Tasks 6, 9. |
| 7 | Spec §4: `AccessToken` mit `expires_at` und `claims`-Marker, 60 s Leeway einheitlich. Plan Tasks 6, 9. |
| 8 | Spec §9 und Plan Task 5: Settings in `netbox_client.py`/`models.py`, `.env.example`, README, `REGISTRY_EXCLUDED`. |
| 9 | Spec §1: Compliance-Ausnahme dokumentiert, `OIDC_ACCEPT_NETBOX_TOKENS` (Default `true`). |
| 10 | Spec §4: Unterscheidungsregel (`typ`, `scope`, `nonce`/`at_hash`). Plan Task 2: mit echten Tokens bestätigen. |
| 11 | Plan Task 6: `OidcJwtVerifier`. |
| 12 | Spec §4/§9: `MCP_TRANSPORT=http` und `NETBOX_TOKEN_PASSTHROUGH=true` sind Pflicht, `TOKEN_STORE_PATH` ist Pflicht, Volume für UID 10001. |
| 13 | Spec §4: Begründung für die Wahl von PyJWT. |
| 14 | Spec §3 (Client-Tabelle), Plan Task 1: Secret nicht per Kommandozeile setzen. |
| 15 | Plan Task 5: `tests/oidc/__init__.py`, Testdatei umbenannt in `test_oidc_config.py`. |
| 16 | Spec §3: Fallbacks festgelegt, Upstream-Stand bei Authentik dokumentiert (RFC 8707 und PKCE-Pflicht erst für 2027.2.0 geplant, nicht gemergt). Token Exchange und `aud` per Scope-Mapping ausdrücklich ausgeschlossen. Plan Task 4. |
| 17 | Spec §6: einfacheren Lebenszyklus als Alternative beschrieben, Entscheidung am Gate in Task 4. |
