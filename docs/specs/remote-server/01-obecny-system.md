# 01 — Obecny system: analiza kodu

Poniższe informacje opisują lokalne źródła z 18.10.2026. Dokumentacja dawnych wdrożeń i feature flag nie jest dowodem aktualnego stanu produkcji. Nie odpytywano produkcyjnych kont ani nie wykonywano zmian w usługach.

## Desktop: działający Remote ma zależności od GUI

| Źródło | Obecna odpowiedzialność | Wniosek |
| --- | --- | --- |
| [`lomi/src/remote-workspace-domain.ts`](../lomi/src/remote-workspace-domain.ts) | `workspaceTerminals`, `terminalLayout`, `WorkspacePublisher`; projekcja kart i splitów terminalowych z domeny React | Zachować filtr terminal-only, przenieść autorytet domeny do hosta |
| [`lomi/src/remote-workspaces.ts`](../lomi/src/remote-workspaces.ts) | `useRemoteWorkspaces`; synchronizacja, start brakujących PTY, Share remotely | Zastąpić adapterem do wspólnej usługi |
| [`remote/mod.rs`](../lomi/src-tauri/src/remote/mod.rs) | `Remote`, `Core`, polling, parowanie, granty, kanały, komendy Tauri, tray, idle pause | Rozdzielić rdzeń hosta, UI i integrację konta |
| [`remote/workspace.rs`](../lomi/src-tauri/src/remote/workspace.rs) | `Domain`, `Consent`, `reconcile_workspaces`, metadane terminalowych workspace’ów | Podstawa semantyki udostępniania, nie gotowy katalog projektów/pliki |
| [`terminal.rs`](../lomi/src-tauri/src/terminal.rs) | `Terminals`, procesy `portable-pty`, output, input, zdalne lease i receipts | Procesy należą obecnie do procesu Tauri |
| [`remote/channel.rs`](../lomi/src-tauri/src/remote/channel.rs) | Noise, snapshot/delta, claim/renew/input/resync | Zachować niezmienniki, rozszerzyć kontrakt w nowej wersji |
| [`remote/policy.rs`](../lomi/src-tauri/src/remote/policy.rs) | Klucz hosta, zgody i granty w keyring; powiązanie z kontem i parent session | Potrzebny model niezależnego host authorization i headless storage |

Dzisiejszy przepływ: domena desktopowego frontendu → terminalowa projekcja → komendy Tauri → native Remote → backend → klient WWW/mobile. Zdalny klient może dołączyć do istniejącego terminala, zażądać kontroli i wysłać input. Ten kanał nie udostępnia obecnie poleceń tworzenia kart, Explorer ani Git.

`LIVE_QUALIFIED` oraz powiązane bramki ograniczają native Remote do macOS ARM64. Obecna polityka potrafi pauzować Remote po godzinie bezczynności. Host serwerowy musi mieć osobną jawną politykę pracy w tle; nie może przypadkiem odziedziczyć desktopowego pauzowania.

## Ważna zależność: model terminala uruchamia Node

[`remote/runtime.rs`](../lomi/src-tauri/src/remote/runtime.rs) uruchamia zweryfikowany, dołączany Node i helper z [`packages/remote-terminal-runtime`](../lomi/packages/remote-terminal-runtime/package.json). Model wykorzystuje `@xterm/headless` 6.0.0 i `@xterm/addon-serialize` 0.14.0. Snapshoty, checkpointy i journal pozwalają odbudować model po awarii helpera przy nadal działającym właścicielu PTY.

Nie jest to odtwarzanie procesu terminalowego po restarcie aplikacji. Kopia tekstu ekranu, stan emulatora i żywy shell to trzy różne rzeczy. Bez zmiany tego elementu nowy serwer nie spełni wymagania Rust-only.

## Prototypy i biblioteki do wykorzystania

| Element | Co realnie daje | Ograniczenia |
| --- | --- | --- |
| [`lomi-session-core`](../lomi/src-tauri/crates/lomi-session-core/src/lib.rs) | Własność PTY, input/resize, subskrypcje, epoki, bounded replay | `cfg(unix)`, osobny workspace Cargo, nie jest zależnością desktopu; profil `vt100-0.16-replay-v1-unqualified` |
| [`lomi-session-host`](../lomi/src-tauri/crates/lomi-session-host/src/main.rs) | Oddzielny proces, blokada właściciela, IPC same-UID, przetrwanie rozłączenia klienta | Unix-only, stan w RAM, `remote_control:false`, brak kont i relay |
| [`lomi-control-core`](../lomi/src-tauri/crates/lomi-control-core/src/lib.rs) | Broker, receipts, bezpieczne mechanizmy plików i Git | Część modułów Unix-only, Git zakwalifikowany tylko macOS ARM64; callbacki i UI epochs zależą od desktopu |
| [`lomi-control-protocol`](../lomi/src-tauri/crates/lomi-control-protocol/src/lib.rs) | Typowane operacje, revisions, błędy, idempotency, domena plików/Git/layout | Szerszy katalog MCP, nie gotowy publiczny kontrakt Remote |
| [`lomi-remote-crypto`](../lomi/src-tauri/crates/lomi-remote-crypto/README.md) | Tauri-free identity, podpisane bundle/granty, Noise i framing, WASM | Nowe capabilities/context potrzebują nowej wersji i testów; to nie gotowy daemon |

Prototyp session-core ogranicza replay do 256 KiB / 4096 rekordów. Po usunięciu początku historii odmawia snapshotu wymagającego pełnego replayu. Podniesienie limitu nie rozwiązuje problemu pełnej synchronizacji wielodniowego terminala.

MCP i Remote mają dziś osobne źródła autoryzacji. Można współdzielić wykonanie operacji, ale nie wolno przez to uznawać zdalnego klienta za zaufanego lokalnego agenta ani dziedziczyć jego grantów.

[`project_write_guard.rs`](../lomi/src-tauri/src/project_write_guard.rs) ma rejestr `OnceLock` działający **tylko w procesie desktopu**. Korzystają z niego m.in. [`agent_runtime/execution.rs`](../lomi/src-tauri/src/agent_runtime/execution.rs), [`git.rs`](../lomi/src-tauri/src/git.rs) i [`agent_control.rs`](../lomi/src-tauri/src/agent_control.rs). Wydzielenie biblioteki do daemonu nie tworzy wspólnej blokady z pozostawionym w Tauri AI/MCP; wymaga międzyprocesowego admission.

Shell integration to także [`shell.rs`](../lomi/src-tauri/src/shell.rs) i [`src-tauri/shell`](../lomi/src-tauri/shell). Obecnie OSC 7 / CWD przetwarza renderer w [`terminal-runtime.ts`](../lomi/src/terminal-runtime.ts), a Workbench zapisuje aktualizacje katalogów. Host działający bez GUI musi przejąć tę obserwację. Własność PTY to również zmiana backpressure: obecny `terminal.rs` zależy od ACK renderera i przy błędzie kanału potrafi zatrzymać sesję. Odłączenie odbiorcy nowego IPC nie może odziedziczyć tego zachowania.

## Backend: zachować fundamenty, zmienić model podmiotów

[`auth-app/src/remote/api/live.ts`](../auth-app/src/remote/api/live.ts) zawiera `createLiveController`, sprawdzanie hostów/grantów/kanałów i ticketów. [`workspaces.ts`](../auth-app/src/remote/api/workspaces.ts) waliduje heartbeat, zakresy i monotoniczność publikacji. [`schema.prisma`](../auth-app/prisma/schema.prisma) definiuje hosty, parowania, granty, kanały i relay tickets.

Istnieją już:

- rejestracja hosta i heartbeat;
- podpisane przez hosta granty v2 z workspace/session epochs;
- sanitizowany katalog HTTP: UUID, generic labels, status i część metadanych routingu;
- nazwy workspace’ów, tytuły i layout przesyłane przez szyfrowany kanał metadanych;
- oddzielne sesje przeglądarki i mobile;
- jednorazowe, krótkie relay tickets dla hosta i klienta;
- revocation, sprawdzanie parent session i transakcyjne blokady autoryzacji;
- prywatna usługa identity exchange i relay authority.

`Principal` ma właściciela web lub mobile. Native bearer służy hostowi. Pairing/grant nie ma obecnie właściciela „desktop jako klient”. Co więcej, [migracja mobile](../auth-app/prisma/migrations/202610010001_mobile_consumers/migration.sql) wymusza dokładnie jednego właściciela web/mobile w SQL, także przez triggery. Rozszerzenie wymaga migracji, FK/checków/triggerów i uprawnień ról, nie samego nowego pola TypeScript.

Host jest związany z `sourceSessionId`. [`auth.ts`](../auth-app/src/auth.ts) używa Better Auth 1.7.6 i ma już `deviceAuthorization`; hook klasyfikuje tokeny tego flow jako desktop. To dobry punkt wejścia dla CLI, ale nie gotowa długotrwała tożsamość usługi. Samodzielny plugin zwraca token sesji Better Auth, nie zapewnia automatycznie docelowej rotacji refresh tokenów hosta.

Globalne revoke w [`app.ts`](../auth-app/src/app.ts) i obsługa wygaśnięcia/blokady konta w [`maintenance.ts`](../auth-app/src/maintenance.ts) opierają się obecnie na sesjach Better Auth i `sourceSessionId`. Niezależne host authorization wymaga zmiany również tych ścieżek. Istniejące [`mobile-auth.ts`](../auth-app/src/mobile-auth.ts) jest przykładem wykrywania reuse refresh tokena; nie zawiera gotowego recovery utraconej odpowiedzi rotacji hosta.

## Relay i ograniczenia skali

[`relay/server.ts`](../auth-app/src/remote/relay/server.ts) przekazuje binarne, zaszyfrowane ramki i ponownie sprawdza autoryzację. [Opis admission](../auth-app/src/remote/relay/README.md) dokumentuje ograniczenia pending sockets, per-source rate limits, proxy trust i wygaszanie kanałów.

Obecnie walidacja authority odbywa się co około 2 sekundy, a brak świeżego potwierdzenia przez 5 sekund zamyka kanał. Kanały mają ograniczony czas życia. Zachować zasadę fail-closed i przełożyć ją również na lokalnego wykonawcę operacji.

Relay ma jednego aktywnego właściciela z lease/fencing. Nie wolno planować zwykłego rolling update dwóch aktywnych instancji bez zmiany tego modelu. Hosty klientów mogą być liczne; nie oznacza to automatycznie wieloinstancyjnego relay.

Aktualne limity m.in. 32 hosty/konto, 32 workspace’y/host i 64 kanały/host trzeba ponownie zbilansować dla Explorer/Git i wielu okien. Więcej paneli nie może niejawnie wyczerpywać wszystkich kanałów. Obecne zmiany revision/membership potrafią unieważniać kanały; nowy model rozdziela zmianę layoutu i autoryzacji.

Obecny helper ma także limit 32 aktywnych modeli terminali desktopu, w tym w nieudostępnionych workspace’ach. Nie jest to dowód docelowej pojemności hosta. [`transactions.ts`](../auth-app/src/transactions.ts) stosuje globalny advisory lock autoryzacji, również dla walidacji authority. Zwiększenie limitów kanałów wymaga pomiaru opóźnień tej blokady i freshness, nie tylko pamięci relay.

## Web i mobile: wspólny produkt, zdublowana implementacja

[`remote-web/src/crypto.worker.ts`](../remote-web/src/crypto.worker.ts) posiada secure core przeglądarki. [`mobile-app/src/remote/core.ts`](../mobile-app/src/remote/core.ts) implementuje podobną logikę przez adaptery native. Oba mają kopie protokołu, metadanych workspace’u i typów. Mobile ma vendored kopię Rust crypto z kontrolą pochodzenia oraz osobny bundled renderer xterm.

Web renderuje wiele splitów równolegle; mobile wybiera jeden pane naraz. To dobre różnice interfejsu, nie powód do różnej semantyki uprawnień, resync lub input. Obydwa klienty potrafią dziś obsługiwać istniejące terminale; obsługa plików/Git i tworzenia kart musi zostać dodana.

Przeglądarka używa efemerycznej tożsamości w Worker/WASM; po refreshu tworzy nową. Prosty dostęp własnego konta opiera się na polityce Share remotely i automatycznej akceptacji przez hosta. Nowy plan nie wymaga obowiązkowego ręcznego porównywania fingerprintu przy każdym otwarciu strony.

Istotne ograniczenie: automatyczny pairing w [`live.ts`](../auth-app/src/remote/api/live.ts) odwołuje dziś granty innych `deviceId` dla tego samego ownera sesji, hosta i workspace’u. Równoległe okna z osobnymi efemerycznymi kluczami wymagają usunięcia tej zasady zastępowania i limitowanego modelu wielu attachments. Samo otwarcie drugiego okna UI nie wystarczy. Mobile lifecycle obejmuje także [`runtime.tsx`](../mobile-app/src/runtime.tsx), nie tylko `remote/core.ts`.

### Istotny problem wydania WWW

[`auth-app/Dockerfile.remote-web`](../auth-app/Dockerfile.remote-web) buduje `auth-app/apps/remote-web`, a nie sąsiedni katalog `remote-web`. Te drzewa mają różnice także w secure core i UI. Plan wyznacza `remote-web` jako jedyne źródło aplikacji; wdrażanie nie może opierać się na ręcznie utrzymywanej kopii.

## Co zachować, a czego nie przenosić bezpośrednio

Zachować: istniejącą platformę kont, E2EE, host-signed grants, kontrolę epoch/revision, leases, input receipts, ochronę ścieżek, atomowe zapisy i sprawdzone testy.

Przeprojektować: własność procesów i domeny, host login/renewal, desktop consumer principal, możliwości plików/Git/layout, Rust snapshot engine, IPC Windows, instalatory i jednolity proces wydania.

Nie przenosić do serwera: Tauri, tray, WebView, Android SDK, browser runtime, AI runtime, bundlowanego Node, zależności od aktywnego renderera i callbacków GUI. Istniejących bramek platformowych nie usuwać, dopóki ich następcy nie przejdą kwalifikacji.
