# 06 — Przebudowa i ujednolicenie aplikacji

Cel to jeden host, jeden kontrakt i te same reguły dostępu. Implementacje interfejsów pozostają właściwe dla swoich platform. Poniższe zmiany są backlogiem; żaden wymieniony plik nie został w tej fazie zmodyfikowany.

## Nowe repozytorium `lomi-remote`: wspólne źródło wykonania

1. Utworzyć odrębne repozytorium Git `lomi-remote` w `/Users/woro/Documents/Lomi/lomi-remote`, a w nim Rust workspace i entrypointy CLI/daemon/service/TUI. Specyfikacja pozostaje w `remote-server`; implementacja ma własne wersjonowanie i CI. Build hosta musi przechodzić na maszynie bez zależności desktopu.
2. Przenieść source crypto z `lomi/src-tauri/crates/lomi-remote-crypto` do jednego współdzielonego źródła, zachowując historię/test vectors i security patches. Odświeżyć automatyczny WASM/native pipeline i provenance.
3. Z prototypów session-core/host przenieść sprawdzone mechanizmy ownership, subscribe i IPC; zastąpić niezakwalifikowany model pełnym terminal state. Nie dystrybuować prototypu jako gotowego remote hosta.
4. Wydzielić z desktopowego `terminal.rs` zwykłe PTY/shell ownership, a z control-core native files/Git mechanizmy bez Tauri callbacków i ograniczeń `cfg` niepopartych testami.
5. Utworzyć autorytatywny workspace service, SQLite/outbox, command admission, leases, receipts i local API. Host nigdy nie czeka na gotowy renderer, żeby wykonać dozwoloną operację terminalową/file/Git.
6. Dodać network remote service z nową tożsamością hosta, kanałami i fail-closed freshness. `always-on` jest odrębną polityką, nie kopią desktopowego idle pause.

## `lomi`: desktop jako lokalny i zdalny klient

### Host i Share remotely

- `src-tauri/src/remote/{mod,workspace,channel,runtime,policy}.rs`: zastąpić orkiestrację Tauri adapterem do wspólnego hosta. UI/tray słucha statusu; nie jest źródłem prawdy.
- `src-tauri/src/terminal.rs` i `src/terminal-runtime.ts`: przenieść zwykłe terminale do host-owned PTY; renderer nadal zarządza xterm i parse ACK. Każdy terminal zdolny do Share jest od początku tworzony w host process.
- `src-tauri/src/shell.rs` i `src-tauri/shell/*`: przenieść zwykłe shell profiles/startup hooks i normalizację WSL do adaptera hosta. Kontrolowany env, wersjonowane hooki i ich pliki muszą być częścią wydania bez Tauri resources. Parser hosta przejmuje OSC 7/CWD i emituje metadane bez aktywnego renderera; klient nie ustawia autorytatywnego CWD przez zgłoszenie tekstu OSC. CWD nie zmienia root ani praw grantu. Nowy terminal domyślnie startuje w root; restart również, chyba że operator lokalnie wybierze `last-valid-under-root`, z walidacją istnienia i fallbackiem do root.
- Backpressure z `terminal.rs` zależny od Tauri Channel/renderer ACK zastąpić niezależnym czytaniem PTY i bounded kolejką per attachment. Zniknięcie okna nie kończy procesu; model terminala pracuje także bez odbiorców.
- `src/remote-workspace-domain.ts`, `src/remote-workspaces.ts`: usunąć model „React publikuje domenę i odpala shell, by dało się go udostępnić”. Komendy i eventy od hosta zastępują `WorkspacePublisher` jako autorytet.
- `src/model.ts`, `Workbench.tsx`, docking adaptery: mapować trwałe terminal references i private views, optimistic revision conflicts oraz events między oknami. Nie resetować PTY przy React unmount/dock.
- `RemoteSettingsPage.tsx`/status: pokazywać host installation, stan usługi, autostart, politykę sharing i account authorization. Taki sam revoke/sharing jak w TUI.
- Wspólny close/update flow: zamknięcie GUI zapisuje jego lokalne bufory i odłącza widoki. Nie wywołuje shutdown zewnętrznego hosta. Restart desktopowego updatera nie restartuje automatycznie daemonu.

Lokalne Android/browser/chat/plugin runtime pozostają w desktopie i mają swoje obecne lifecycle/close guards. Nie przechodzą do headless hosta tylko dlatego, że istnieją w mixed layout. Zwykłych terminali nie mieszać z terminalami wewnętrznymi/protected native AI tasks. Te ostatnie pozostają nieudostępniane do czasu osobnej integracji ich ownership/permissions.

`project_write_guard.rs`, `agent_runtime/execution.rs`, lokalny `git.rs` i `agent_control.rs` wymagają adaptera do host-owned admission z [02](02-architektura.md). Ochrona repo podczas aktywnego taska musi działać między procesami. Utrata IPC nie zwalnia w ciemno blokady działającego writera; test wymaga potwierdzonego zakończenia lub jawnego stanu blokady.

### Remote workspace na B

Wprowadzić `WorkspaceConnection = LocalHostRef | RemoteHostRef` oraz adaptery usług o wspólnej domenie. `RemoteHostRef` zawiera account/host/workspace IDs i pin/context, nie lokalny filesystem path. Shell, pliki i Git zdalnego projektu wykonują się na A.

Explorer, Source Control i terminal actions korzystają z `WorkspacePort`; UI nie rozgałęzia każdego polecenia na dowolny `invoke` vs `fetch`. Port obejmuje tylko zaakceptowane możliwości; brak capability daje jawny disabled state. Systemowy file picker B nie wybiera ścieżki workspace’u A.

Nowe okno na B otrzymuje remote reference i własny client view ID. Close view odłącza; close terminal mutuje hosta. Stan klienta/poświadczenia przechodzą przez kontrolowany native/session adapter, nie query string z tokenem. Wiele okien korzysta z jednego credential lifecycle, lecz niezależnych leases/attachments; aktywny właściciel input jest jednoznaczny.

Desktop B wymaga **nowego backend consumer principal**; dotychczasowy native host bearer nie wystarcza. Połączenie z A nie może automatycznie włączyć lokalnego host sharing na B.

## `auth-app`: jeden control plane

### Docelowe byty danych

Poniższe nazwy są logiczne; końcowy Prisma schema powstaje razem z migracją:

| Byt | Odpowiedzialność / relacje |
| --- | --- |
| `RemoteHostEnrollment` | Wygasający, jednokrotny binding client class, device approval, host key/ID, bootstrap session i exchange operation |
| `RemoteHostAuthorization` | Account, host installation, key fingerprint, scope, status, expiry i credential family; niezależny od browser source session |
| `RemoteHostCredential` | Hashe tokenów/rotacji, jednorazowe recovery, revoke; bez plaintext credential w normalnej tabeli |
| `RemoteConsumerAuthorization` | Jeden consumer owner z `kind=web|mobile|desktop`, FK do właściwej sesji, account, expiry i revoke |
| `RemoteHost` | Authorization FK, key bundle, access epoch, wyłączny runtime lease/generation, heartbeat i minimalny inventory |
| `RemotePairing` / `RemoteGrant` | Consumer authorization FK, host, workspace epoch, signed capabilities i deadline |
| `RemoteChannel` / `RemoteRelayTicket` | Purpose, grant revision, session context gdy terminal, krótkie tickets |
| `RemoteRelayOwner` | Zachowana lease/fencing; bez przypadkowego rolling overlap |

`RemoteConsumerAuthorization` ma w SQL dokładnie jeden prawidłowy FK zgodny z kind, np. `webSessionId`, `mobileSessionId` lub `desktopSessionId`, oraz niezmienne ownership. Jeżeli desktop używa wspólnej tabeli identity sessions, FK i class check muszą wskazywać sesję sklasyfikowaną przez serwer jako desktop. Nie wystarczy luźny `ownerType/ownerId` bez referential integrity.

Wygaśnięcie/revoke sesji konsumenta unieważnia jego authorization, pairing, grant, kanały i tickets. Host authorization ma niezależne świadomie nadane życie; global account revoke obejmuje obie gałęzie. Te relacje muszą istnieć także w uprawnieniach ról DB i testach SQL.

### Obszary zmian

- `src/auth.ts`, device flow i session metadata: oddzielić host enrollment od desktop client login. Nie uznawać wszystkich `/device/token` za zwykły desktop.
- `src/app.ts`, allowlist client IDs i walidatory `/device/code`/`device/token`: wpiąć rekord enrollment oraz atomowe proof-of-possession exchange/recovery. Publiczne client ID nie może samodzielnie ustawiać zaufanej klasy sesji.
- `src/remote/identity/`: wydać/odnawiać/revoke host authorization; istniejące exchange i standardowe login flows klientów pozostają.
- `src/remote/api/live.ts`, `workspaces.ts`, `crypto.ts`: nowe principals, capability grants, workspace/terminal purpose, membership rules, publication CAS/outbox acknowledgment i wersje.
- Git grants/admission: opcjonalne `git.execute` wymaga osobnej lokalnej zgody na pełne wykonanie kodu repo; ograniczony grant odmawia worktree-controlled executable helpers niezależnie od fingerprint config/attributes. Domyślna polityka nie dopisuje execute.
- `prisma/schema.prisma`, migracje SQL: FK, checks, ownership triggers, token hash uniqueness i indexes expiry/revocation. Aktualizować ról najmniejszych uprawnień z `ops`, nie dawać relay pełnej bazy kont.
- `src/app.ts` global revoke, `src/maintenance.ts` cleanup/status/block/delete oraz UI sesji: odpiąć cykl życia hosta od `sourceSessionId`, objąć osobne authorizations globalnym revoke i usunięciem/blokadą konta. Odwołanie credential families i access epoch odbywa się w jednej transakcji autoryzacji; ponowna aktywacja konta nie wskrzesza dawnych credentials.
- `live.ts` automatic pairing: zastąpić revoke innych `deviceId` limitowanym współistnieniem attachments jednego consumer authorization. Refresh jednego okna nie wycina drugiego; revoke nadrzędnej sesji wycina oba.
- `src/push/api.ts` i `PushSource`: sprawdzić wszystkie założenia typu `!mobileId => native`. Nowy host principal/desktop consumer nie dostaje automatycznie praw push. Push pozostaje przy obecnej tożsamości desktopowej do osobnej integracji; cutover Remote nie usuwa jego source przez nieprzeanalizowane FK cascade.
- `src/remote/relay/`: rozumieć nowy routing/context i wielkości ramek; nadal forwarduje ciphertext bez biznesowej interpretacji plików/Git. Zachować source admission, authority freshness i owner fencing.
- `ops/`: bootstrap, backup/restore, staging fixture i qualification obejmują nowe schema/principals. Prywatne identity/authority endpoints pozostają bez publicznego ingress.
- Endpoint katalogu wersji/features oraz release manifest określa, czy klient może otworzyć dany host. HTTP header nie jest zabezpieczeniem uwierzytelnienia.

Globalny authorization lock z `src/transactions.ts` wymaga testu obciążenia authority/admission/revoke przy docelowym budżecie kanałów i churnie kont. Mierzyć wait time blokady, odnawianie relay owner lease i rozłączenia freshness. Zmiana granularności locka lub batch validation wymaga ponownego dowodu niezmienników revocation, a nie samej poprawy benchmarku.

Nie dodawać do chmury treści plików, terminal output, Git diffs/messages ani rzeczywistych nazw katalogów jako danych potrzebnych do routingu. Serwer zna account/host/client IDs, zakresy i aktywność; E2EE nie ukrywa wszystkich metadanych.

### Jedno źródło Remote Web

`remote-web` staje się canonical repo/source. Pipeline tego projektu buduje immutable image/static artifact, a deployment wskazuje jego digest. `auth-app` wdraża API/identity/relay i może wskazywać gotowy artefakt WWW; przestaje budować ręczną kopię `apps/remote-web`.

Podczas przejścia dopuszczalny jest automatycznie importowany pinned artefakt/revision, ale CI musi sprawdzić exact source digest. Docelowo usunąć kopię aplikacji i stary Dockerfile path. Release dashboard pokazuje commit źródła WWW, schema/protocol/crypto/snapshot profile oraz image digest. Zmiana UI w sibling `remote-web` musi rzeczywiście trafić do środowiska.

## `remote-web`

- `protocol.ts`, `live-types.ts`, `workspace.ts`: zastąpić importem wygenerowanych kontraktów/runtime validators i wspólnych funkcji klienta.
- `crypto.worker.ts` / `live-client.ts`: zachować izolację kluczy w Worker/WASM; wyodrębnić wspólną maszynę stanów i dodać workspace RPC/events.
- `WorkspaceTerminals.tsx`, `TerminalView.tsx`, `App.tsx`: dodać Explorer/Source Control, create terminal/split/rename/close, local previews i akcję nowego okna. Nie dodawać nieudostępnionych typów do shared layout.
- `terminal-bridge.ts` i snapshot adapter: nowy Rust producer profile, zgodna wersja xterm i kontrola parse ACK. Blokować nieobsługiwany profil przed apply snapshot.
- Zachować same-origin HttpOnly cookie, CSRF/Origin, CSP, brak inline scripts i brak tokenów w URL. Wyjątek zatwierdzony przez użytkownika (ADR-18): chroniona lokalna identity konkretnego okna może być utrwalona w IndexedDB. Klucze kanału, granty, tickets i odszyfrowane pliki pozostają poza trwałym storage.
- Reconnect nie powtarza input ani mutacji; klient odczytuje operation status i bieżącą domenę. Revoke/Logout czyści worker, pending buffers oraz podglądy.

Nowe okno po kliknięciu tworzy odrębną identity pod tą samą sesją konta. Odświeżenie odzyskuje wyłącznie identity własnego okna zgodnie z ADR-18. Polityka owner-account obsłuży nową identity bez ręcznej akceptacji, ale podlega limitom i niezależnemu input lease. Nie zakładać automatycznie wspólnego Worker między różnymi oknami.

## `mobile-app`

- `src/remote/core.ts`, `protocol.ts`, `live-types.ts`, `workspace.ts`: konsumować wspólny kontrakt/maszynę stanów przez native adapters. Nie utrzymywać drugiego znaczenia tego samego error/lease/event.
- `modules/lomi-remote-crypto`: build z tego samego canonical source co WASM/native; provenance/hash i testy ABI dla iOS/Android, bez ręcznych patchy kopii.
- `TerminalRenderer` oraz bundled renderer: nowy profile adapter, uzgodniony xterm i CSP. Native bridge pozostaje; sekrety nie przechodzą do WebView renderer.
- Dodać Explorer i Source Control jako nawigację workspace’u, read-only file/diff preview, create terminal i menu kart/panes. Podgląd nie zapisuje dowolnej treści pliku; wymagane operacje Explorer na nazwach i pustych plikach/katalogach są dostępne z odpowiednią capability tak samo jak w pozostałych klientach (04/09, REQ-10). Widok jednej aktywnej sesji pozostaje poprawnym mobile UX.
- Suspend/background/lock: zatrzymać aktywne attachments i control intent, wyczyścić wrażliwe chwilowe bufory; foreground ponownie sprawdza auth i pobiera świeży stan. Brak automatycznego ponowienia input/commit/push.
- `src/runtime.tsx`: zachować powiązanie lifecycle aplikacji/Android blur/network z `core.setForeground`; objąć nim również nowe podglądy plików i diffów oraz ich czyszczenie.
- Stan `starting`, `auth required`, `credentials required`, `conflict`, `outcome unknown`, `host offline` musi być równie precyzyjny jak w desktop/WWW.

Zmiany Expo/native wykonuje się według wersji Expo z manifestu i właściwej dokumentacji. Ta faza nie zmienia konfiguracji Expo ani nie kwalifikuje iOS/physical devices; pełne sprawdzenie jest w kryteriach wydania.

## `auth-frontend`, strona instalacji i dokumentacja

Choć użytkownik wskazał cztery aplikacje, headless login wymaga pomocniczych zmian `auth-frontend` dla zgody host enrollment i zarządzania odwołaniem hosta. Istniejące allowlisty redirect/handoff pozostają. `lomi.dev/server/` dostarcza instalatory, instrukcje, wymagania OS, publiczne podpisy/root metadata i informacje o restartowaniu terminali.

Nie uruchamiać pełnej strony/hostingu w tej fazie planu. W implementacji podpiąć endpointy do istniejącego repo i procesu publikacji `lomi.dev`, zamiast tworzyć niezależną, nieutrzymywaną stronę pobierania.

## Przejście bez zgodności wstecznej

1. Zamrozić stary Remote i sporządzić manifest źródeł/artefaktów. Zabezpieczyć lokalne dane oraz wyłączyć jego feature gates przed cutover.
2. Wydać kompatybilny zestaw nowego API/klientów/hosta do staging. Starych i nowych grantów nie mieszamy; odrębne namespaces/wersje.
3. Przy zamkniętym GUI zapisać lokalną sesję i backup. Importować tylko projekt/workspace/terminal descriptors do nowego hosta z jednoznacznym ID mapping. Nowe shell sessions powstają bez replay komend. Niezapisane edytory są chronione dotychczasowym close flow.
4. Stare zgody terminal-only i keyring policy nie rozszerzają uprawnień. Użytkownik ponownie włącza sharing według nowego zakresu i dostaje nową rejestrację/epoki.
5. Backend unieważnia stare parowania, granty, kanały/tickets i stare host registrations. Konsumenci niezgodnej wersji otrzymują jasny komunikat aktualizacji; użytkownik może zalogować się ponownie.
6. Po akceptacji scenariuszy usunąć martwy Remote code, Node terminal helper i kopie protokołu z aktywnych buildów. Zachować historyczne fixture/security evidence potrzebne do audytu; testy nowego profilu stają się obowiązkowe.
7. Cutover relay respektuje jednego właściciela i lease. W razie rollback odtworzyć zgodny zestaw usług i danych; nie wskrzeszać starych uprawnień ani nie obiecywać ciągłości PTY przez restart.

Brak kompatybilności protokołu nie oznacza zgody na kasowanie plików użytkownika, Git repo, credentialów innych funkcji czy niezapisanych buforów. Te dane mają jawne zabezpieczenie przy przejściu.

Szczegółowa kolejność migracji DB, przełączenia relay, importu i odzyskania po awarii jest w [runbooku](10-operacje-i-weryfikacja.md). Nie usuwać legacy constraints/kolumn przed przełączeniem wszystkich zależnych usług i sprawdzeniem nowych ograniczonych ról.
