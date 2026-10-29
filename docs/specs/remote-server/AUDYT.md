# Audyt planu Lomi Remote

Data: 18.10.2026. Zakres: wszystkie dziewięć zastanych dokumentów `remote-server`, porównanie z istotnymi ścieżkami kodu pięciu aplikacji oraz oficjalnymi źródłami technicznymi. Rezultat: poprawiona dokumentacja, specyfikacja uzupełniająca i `prompt.md`. Nie wdrożono serwera ani zmian w aplikacjach/infrastrukturze.

## Ocena i ograniczenie wniosku

Zastany plan poprawnie wyznaczał kierunek: niezależny host Rust, wspólna domena desktop/CLI, terminal-only panele, Explorer/Git jako usługi workspace’u, E2EE i nowy model autoryzacji. Trafnie identyfikował ryzyko snapshotu Rust, Windows service i rozjazdu źródeł WWW. Nie wymagał odrzucenia architektury.

Wymagał doprecyzowania kontraktów i uzupełnienia rzeczywistych zależności migracji. Najistotniejsze luki dotyczyły blokad między procesami, wielu okien pod jedną sesją, powiązania enrollment z kluczem, global revoke po oddzieleniu host authorization oraz recovery aktualizacji. Zostały uwzględnione w planie. Ich opisanie **nie oznacza**, że zostały naprawione w kodzie.

To audyt dokumentacji i wybranych odpowiedzialnych ścieżek, nie pełny audyt bezpieczeństwa wszystkich aplikacji ani dowód działania przyszłej implementacji. Nie istnieje rzetelna gwarancja „idealności” systemu przed spikami i testami. Plan wskazuje wymagane dowody i blokuje deklarację kompletności przy brakujących wynikach.

## Rejestr ustaleń i poprawek

Waga określa skutek pozostawienia luki przy implementacji; wszystkie wpisy są zamknięte **w specyfikacji**, a implementacja/testy pozostają do wykonania.

| ID / waga | Problem i dowód | Poprawka / warunek sprawdzenia |
| --- | --- | --- |
| A-01 / wysoka | `project_write_guard.rs` używa process-local `OnceLock`; AI/MCP zostają w Tauri, files/Git przechodzą do hosta | 02/06/09: host-owned admission przez IPC, kwarantanna po utracie writera, test native task kontra remote write |
| A-02 / wysoka | Automatic pairing `live.ts` odwołuje inne deviceId tej samej sesji/host/workspace | 01/06/07/09: wiele limitowanych attachments; dwa okna i refresh jednego nie odłączają drugiego |
| A-03 / wysoka | Device plugin wydaje zwykłą sesję; hook klasyfikuje wszystkie `/device/token` jako desktop | 05/06: trwały immutable enrollment/key/bootstrap-session binding, proof-of-possession, jednokrotny exchange i recovery |
| A-04 / wysoka | Global revoke/maintenance polega na usuwaniu Session i `sourceSessionId` | 05/06/10: aktualizacja app/maintenance/account delete, niezależne authorizations/families/epoch; reactivation nie ożywia credential |
| A-05 / wysoka | „Revoke consumer” nie rozróżnia key/grant od nadal ważnej sesji owner-account | 05/09: osobne skutki obu operacji; refresh po grant revoke i po parent revoke ma różne wyniki |
| A-06 / wysoka | Desktopowy output backpressure i zapis CWD zależą od renderera | 01/06: host-owned shell integration/CWD i kolejki per attachment; test bez GUI i bez odbiorcy |
| A-07 / wysoka | Ogólne „FK/checks/triggers” nie określa migracji XOR web/mobile i legacy source session | 06/10: runbook expand→gate→re-enroll→contract, ograniczone DB roles i zachowanie push |
| A-08 / wysoka | Cofnięcie sekretów/epoch przy restore mogłoby użyć starego refresh tokena i grantów | 05/10: recovery domeny oddzielone od aktualnego credential/trust state; w razie niezgodności revoke/re-enrollment |
| A-09 / wysoka | Podniesienie limitów kanałów pomija globalny advisory lock authority | 01/06/07: obciążenie z admission/revoke churn, pomiar lock wait i freshness w całym budżecie |
| A-10 / średnia | Rozszerzenie Principal dotyka push (`!mobileId => native`, source FK), nie tylko Remote | 06/10: zachowanie dotychczasowej tożsamości push, test braku nowych praw i cascade regression |
| A-11 / średnia | Brak zależności capabilities per operacja; manage uruchamia shell; pull zapisuje worktree | 05/09: jawna macierz; manage jako wykonanie, pull wymaga git.write, walidacja closure grantu |
| A-12 / średnia | Katalog operacji nie określa zakresu create/delete/move ani timeout/cancel/subscribe | 00/04/09: puste create, remove pustego katalogu, move wewnątrz workspace; atomic snapshot, status i unknown |
| A-13 / średnia | Lokalny commit kreatora może sugerować transakcję z cloud i service managerem | 03: wznawialna sekwencja etapów z journalem; osobny prawidłowy wynik trybu ręcznego |
| A-14 / średnia | Unshare/logout offline i późniejszy outbox/restart nie miały jawnego trwałego zakazu publikacji | 00/05: trwały fence/tombstone; odróżnienie od przejściowego lost freshness |
| A-15 / średnia | DPAPI i mapped drives opisane zbyt ogólnie; TUF bez trwałego trust state/polityki pinowania | 03/05/08: user scope/no UI, UNC i profil konta, trwałe metadata i dozwolony recovery target |
| A-16 / średnia | Odbiór dopuszczał „brak capability” także dla funkcji obowiązkowej v1 | 00/07: brak obowiązkowego Explorer/Git/management blokuje pełne v1; macierz klient/OS/funkcja |
| A-17 / średnia | Brak promptu, mapy wymagań, artefaktów przekazania pracy i konkretnych procedur operacyjnych | 00/09/10/prompt: REQ IDs, macierze kontraktów, evidence/checkpoint, cutover/import/update/incident runbook |
| A-18 / wysoka, review | Fingerprint config/attributes nie obejmuje kodu wskazanego helpera; jego podmiana zachowuje starą konfigurację | 04/05/06/09: ograniczone granty odmawiają repo-controlled execution; osobne opcjonalne git.execute i lokalna zgoda oznaczają pełne wykonanie. Test podmiany helpera przy stałym config |

Dodatkowo uściślono repo/worktree guards, protected metadata i hardlink policy, ograniczony charakter CAS wobec zewnętrznych writerów, shell profiles/startup hooks/WSL, mobile `runtime.tsx` i znaczenie produktu v1 wobec wersji protokołu. Usunięto sugestię, że założenia planu są osobno zatwierdzone przez użytkownika.

## Podstawa porównania z kodem

Na początku audytu poniższe checkouty nie miały lokalnych zmian:

| Repo | HEAD |
| --- | --- |
| `lomi` | `2cef452c39eb8b455c8d2ae1251310dc870c50bb` |
| `auth-app` | `42520daa05127239608b818cc33354c18a135848` |
| `remote-web` | `65c580fa69275eaaa6678e3ebc103a1b616be4b6` |
| `mobile-app` | `1d7a9c668e20627629f658acddb87da94f71de94` |
| `auth-frontend` | `1551166ff60b183d6845e71d3cd513204c102f80` |

Dokładne punkty wejścia:

- [`project_write_guard.rs`](../lomi/src-tauri/src/project_write_guard.rs), [`agent_runtime/execution.rs`](../lomi/src-tauri/src/agent_runtime/execution.rs), [`git.rs`](../lomi/src-tauri/src/git.rs), [`agent_control.rs`](../lomi/src-tauri/src/agent_control.rs): process-local admission i lokalni writerzy.
- [`terminal.rs`](../lomi/src-tauri/src/terminal.rs), [`shell.rs`](../lomi/src-tauri/src/shell.rs), [`terminal-runtime.ts`](../lomi/src/terminal-runtime.ts), [`Workbench.tsx`](../lomi/src/Workbench.tsx): shell/CWD, renderer ACK i własność procesów.
- [`live.ts`](../auth-app/src/remote/api/live.ts), [`transactions.ts`](../auth-app/src/transactions.ts), [`relay/server.ts`](../auth-app/src/remote/relay/server.ts): pairing replacement, advisory lock, freshness i owner fencing.
- [`auth.ts`](../auth-app/src/auth.ts), [`app.ts`](../auth-app/src/app.ts), [`maintenance.ts`](../auth-app/src/maintenance.ts), [`mobile-auth.ts`](../auth-app/src/mobile-auth.ts): device session class, revoke i rotacja.
- [`schema.prisma`](../auth-app/prisma/schema.prisma), [`mobile consumers migration`](../auth-app/prisma/migrations/202610010001_mobile_consumers/migration.sql), [`DB permissions`](../auth-app/ops/remote-database-permissions.sql), [`push/api.ts`](../auth-app/src/push/api.ts): ownership/FK/role i sąsiednie prawa push.
- [`Dockerfile.remote-web`](../auth-app/Dockerfile.remote-web), [`crypto.worker.ts`](../remote-web/src/crypto.worker.ts), [`mobile runtime.tsx`](../mobile-app/src/runtime.tsx): źródło WWW, efemeryczne klucze i lifecycle.

Pozostałe źródła i świadomie zachowane ograniczenia są w [01](01-obecny-system.md) i [08](08-decyzje-i-zrodla.md). Oficjalny kod Better Auth 1.7.6 potwierdza zwracanie sesji, a dokumentacja TUF/OS potwierdza wymagania zaufania i usług. Upstream docs nie kwalifikują implementacji Lomi.

## Walidacja tego audytu

- Przeczytano wszystkie zastane dokumenty i porównano istotne twierdzenia z kodem oraz źródłami upstream; wyniki powyżej.
- Kontrola mechaniczna Python 3: **passed, exit code 0** — 14 dokumentów UTF-8, poprawne domknięcie bloków kodu i jeden nagłówek H1 na dokument, 117 istniejących lokalnych odnośników, 4 poprawne przykłady JSON, 17 unikalnych wymagań i 18 wpisów audytu; brak markerów konfliktu. Osobno sprawdzono końcowe nowe linie, zbędne spacje i odwołania wejściowe promptu.
- Niezależny reviewer przeczytał wszystkie 14 dokumentów, porównał istotne zmiany z oryginałem i wskazał A-18. Po poprawce ponownie sprawdził politykę wykonawców Git i potwierdził zamknięcie finding w specyfikacji; nie zgłosił innych materialnych sprzeczności. Nie zastępuje to przyszłego review kodu ani kwalifikacji platform.
- Nie uruchamiano aplikacji, migracji, buildów, VM, instalatorów, produkcyjnych API ani kwalifikacji snapshot/SCM/crypto. Przy zmianach wyłącznie dokumentacji nie byłby to dowód działania nowego systemu.
- Końcowe `git status --porcelain` pięciu wymienionych repozytoriów potwierdziło brak lokalnych zmian. Nie zmieniano kodu aplikacji, danych użytkownika, sekretów ani infrastruktury. Nie wykonywano commitów, push ani publikacji.

## Bramki, które pozostają przed implementacją i wydaniem

1. Pełny snapshot Rust↔xterm i dalszy strumień, także po eviction replay i bez duplikowania odpowiedzi terminala.
2. Usługi/PTY/storage bez interaktywnego loginu na każdym deklarowanym OS/trybie, szczególnie Windows SCM/ConPTY.
3. Kwalifikowany Git read isolation na Linux/Windows/macOS oraz spójne międzyprocesowe mutation admission.
4. Enrollment/key binding, crash-safe exchange/refresh recovery, SQL ownership i global revoke.
5. Finalne schemas/limits, pomiar authority/relay, platform matrix i podpisy/TUF z właściwymi operatorami kluczy.
6. Pełna integracja klientów, bezpieczna migracja i staging rehearsal z wymaganiami `REQ-*`.

Agent ma zamknąć te punkty dowodami etapów 0–7. Nie są brakującymi opisami do dowolnego dopowiedzenia ani testami już zaliczonymi w tym audycie.
