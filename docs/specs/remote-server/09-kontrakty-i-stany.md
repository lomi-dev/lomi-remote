# 09 — Kontrakty, stany i artefakty dla implementacji

## Status i zakres

To uzupełnienie [architektury](02-architektura.md), [protokołu](04-protokol-workspace.md),
[bezpieczeństwa](05-logowanie-bezpieczenstwo.md) i [etapów](07-realizacja-i-odbior.md).
Opisuje **propozycję do zamrożenia w S0.5**, nie istniejące endpointy ani wykonane testy.
Agent implementujący najpierw generuje kontrakt i fixtures; nie zgaduje brakujących pól.
Zmiana poniższych reguł wymaga aktualizacji kontraktu, fixtures i testów konsumentów.

| Oś | Wartość docelowa | Znaczenie |
| --- | --- | --- |
| Produkt | v1 | Pierwsze kompletne wydanie funkcji opisanych w planie |
| HTTP Remote API | major 2, `/v2/remote` | Control plane kont, autoryzacji, routingu i admission |
| Application protocol | major 2 | E2EE workspace RPC i terminal channels |
| Grant/context | crypto v3 | Podpisane uprawnienia i kontekst Noise; nie algorytm kryptograficzny v3 |
| Terminal profile | osobny identyfikator | Dokładny format snapshot/delta wybrany przez S0.1 |
| Local IPC | osobny major/minor | Nie dziedziczy numeru HTTP ani wersji produktu |

Manifest zgodności zawiera każdą oś, capability registry i digest schematów/profili.
Niezgodny major, grant lub profil kończy negocjację `UPDATE_REQUIRED` przed danymi.
Nie ma fallbacku do starego terminal-only Remote ani automatycznego rozszerzenia grantu.

## Proponowany control plane `/v2/remote`

Poniższe ścieżki są **logicznymi propozycjami S0.5**; dopiero wtedy powstaje OpenAPI.
`H` = host authorization, `C` = consumer session, `E` = zatwierdzony enrollment bootstrap.
`C` obejmuje web/mobile/desktop; klasę i właściciela odczytuje serwer z sesji w DB.
Nagłówek, `clientId`, User-Agent ani pole body nie nadają klasy `H`, `C` lub `E`.

| Metoda i ścieżka po prefiksie | Klasa | Warunek / wynik |
| --- | --- | --- |
| `POST /enrollments` | publiczna inicjacja | Rate limit; host public key i challenge, bez dostępu do hosta |
| `POST /host-authorizations/exchange` | E | Jednorazowy bootstrap związany z enrollment i host key |
| `POST /host-authorizations/refresh` | H refresh | Rotation ID, family/reuse checks i ograniczone recovery |
| `POST /hosts/register` | H | Tylko własny host ID/key; idempotent registration |
| `POST /hosts/{hostId}/runtime/claim` | H | Wyłączny lease, nowa generation albo `HOST_BUSY` |
| `POST /hosts/{hostId}/heartbeat` | H | Runtime/generation CAS; lease i freshness deadline |
| `PUT /hosts/{hostId}/publication` | H | Publication seq CAS, epochs i opaque resource IDs; ACK |
| `GET /inventory` | C | Tylko udostępnione zasoby konta, opaque IDs i status |
| `POST /pairings` | C | Host/workspace ID, consumer public key, żądany capability set |
| `GET /pairings/{pairingId}` | C lub H | Tylko powiązany consumer albo host; pending/approved/denied/expired |
| `POST /pairings/{pairingId}/decision` | H | Zgoda lokalna/polityka; podpisany grant v3, bez poszerzenia żądania |
| `POST /channels` | C lub H | Osobna strona kanału; grant, purpose i aktualny membership |
| `POST /channels/{channelId}/tickets` | C lub H | Oddzielny jednorazowy ticket właściwego peer, krótki TTL |
| `POST /grants/{grantId}/revoke` | C lub H | Własny consumer albo właściwy host; fence i nowa revision |
| `POST /hosts/{hostId}/revoke` | H lub C właściciela | Jawne uprawnienie zarządzania kontem; odwołanie host authorization |

Sesja H nie zastępuje C dla inventory/pairing; C nie publikuje i nie odnawia runtime.
Zarządzanie hostem przez właściciela wymaga osobnego account-management check, nie samego grantu.
Backend sprawdza immutable ownership, FK i klasę także w transakcji mutującej DB.
Proof-of-possession, canonical bytes i podpisy pochodzą z istniejącego modułu crypto.
Backend przechowuje routing, IDs, epochs, capabilities i status, **bez plaintext nazw,
opisów, root, tytułów kart, ścieżek plików lub treści terminala**. Nie loguje tych danych.
Enrollment UI może wyświetlić niezaufany opis hosta bez trwałego zapisu/logowania backendu.
Metadane użytkowe host przesyła dopiero w E2EE; inventory działa także dla pustego workspace’u.
Tokeny, klucze, granty i tickets nie trafiają do URL/query/fragment, argv ani telemetry.
Transport ticketu WSS ustala S0.5: pierwsza ramka admission przed routingiem payloadu,
ze ścisłym timeoutem i limitem, bez umieszczania go w URL.

## Wiązanie tożsamości i lifecycle klienta

Grant wiąże: account ID, host ID/public key, host authorization/access epoch,
consumer authorization/session ID, consumer key fingerprint, grant ID/revision,
workspace ID/epoch, runtime ID/generation, capabilities, purpose, wersje, nonce i expiry.
Terminal context dodatkowo wiąże pane/session ID, session epoch i terminal profile.
Podpis i Noise prologue muszą zgadzać się co do całego kontekstu; mismatch = odmowa.
Nowa karta jest dynamicznym membership workspace’u, lecz nowy kanał wymaga aktualnego admission.

Consumer session konta i crypto identity okna to różne obiekty: dwa okna mogą należeć
do tej samej autoryzacji konta, ale mają oddzielne klucze efemeryczne, granty, kanały,
request IDs i leases. Nie współdzielą noise state/counter ani przechwyconych tickets.
Refresh przeglądarki odzyskuje chronioną identity wyłącznie tego okna w tej samej sesji/autoryzacji (zatwierdzone ADR-18). Nadal tworzy świeży handshake i kanał; nie importuje sekretów innego okna ani wcześniejszych liczników Noise, tickets lub lease.
Revoke consumer session odcina wszystkie związane okna; revoke grantu może odciąć jedno.
Reconnect transportu wymaga świeżego handshake i aktualnego admission, nie odzyskuje lease.

Jeżeli zatwierdzona lokalnie mutacja wymaga publikacji, a Cloud nie potwierdził
bieżącego stanu, host zamyka pozostałe połączenia. Sam brak cache eligibility
nie dowodzi takiej mutacji i może jedynie wstrzymać I/O w ramach dotychczasowego
deadline. Wąski wyjątek pozwala raz dostarczyć własny trwały receipt do dokładnie
tego połączenia i requestu, który wykonał operację; nie pozwala wznowić inputu,
odczytów ani kolejnych mutacji. Zmiana na zachowanie połączeń i ponowienie po
ACK wymaga odrębnej decyzji bezpieczeństwa.

Stan klienta: `signed_out → authenticating → authorized → pairing → connecting → syncing → ready`.
Z `ready` utrata transportu daje `disconnected`; ponowne admission prowadzi przez `syncing`.
`AUTH_REQUIRED`, revoke, wygaśnięcie grantu lub brak potwierdzenia authority daje `locked`:
stop input/mutacji, zamknięcie kanałów, dispose kluczy, wyczyszczenie plaintext snapshotów,
scrollback, podglądów plików/diff, kolejki input i cache pamięci/workerów.
Plaintext Remote nie trafia do localStorage, IndexedDB, service worker cache ani logów.
Timeout pojedynczego odczytu nie oznacza logout; utrata ważności auth zawsze blokuje dane.
Po ponownym loginie stan pobieramy od początku; stare requesty nie wracają do kolejki.

## Capability closure i macierz RPC

Każdy wiersz wymaga aktualnego grantu, zgodnych epochs, membership i freshness.
Definicje skrótów (koniunkcja, nigdy alternatywa):

- `W` = `workspace.read`.
- `O` = `W + terminal.observe`.
- `C` = `O + terminal.control`.
- `M` = `O + terminal.manage`.
- `FR` = `W + files.read`; `FW` = `FR + files.write`.
- `GR` = `W + git.read`; `GW` = `GR + git.write`; `GN` = `GR + git.network`.

`git.execute` jest opcjonalnym dodatkowym prawem pełnego wykonania kodu repo w mutacji,
z osobną lokalną zgodą. Nie wchodzi domyślnie do GW/GN ani do żadnego read-only grantu.
Wiersze mutacji Git wymagają go dodatkowo, jeśli używają repo-controlled execution.
Bez niego wykonawca odmawia filters/hooks/helperów zależnych od zmiennego worktree;
nie pomija filtra i nie udaje poprawnego wyniku. Wymaganie dotyczy też zależności
pośrednich/aliasów, nie tylko lokalizacji executable. Kwalifikowane host-managed
credential/transport helpers mają odrębny binding kodu/argv/env poza File/Git writes.

Niepełne zależności grantu są odrzucane; serwer nie dopisuje uprawnień bez zgody.
**`terminal.manage` daje pełną możliwość shell execution tak jak `terminal.control`**:
create/restart/split uruchamia profile, startup scripts i środowisko konta OS.
Nie wolno prezentować `M` jako bezpiecznej zmiany layoutu ani ograniczenia do root.
`M` nie nadaje input lease; `C` nie nadaje prawa tworzenia nowych procesów przez RPC.

| Metoda logiczna | Wymaga | CAS / revision / preconditions | Wynik i event |
| --- | --- | --- | --- |
| `workspace.get/capabilities` | W | workspace epoch | Snapshot/revisions i faktycznie dostępne capabilities |
| `workspace.subscribe` | W | epoch + opcjonalny cursor | Atomic snapshot/catch-up, potem ordered events |
| `operation.status/cancel` | W + prawa operacji | Actor/operation binding; bez domain CAS | Stan / prośba cancel; `operation.changed` |
| `terminal.create/split` | M | expected domain revision, profile ID z hosta | Receipt IDs; `workspace.changed`, publication pending |
| `terminal.rename/move` | M | expected domain revision, istniejące tab/pane IDs | Receipt; `workspace.changed` |
| `terminal.close/restart` | M | expected domain revision + session epoch, gdy istnieje | Receipt; `workspace.changed`, terminal exit/new epoch |
| `terminal.attach/snapshot` | O | session epoch, profile | Atomic terminal snapshot/delta; bez uruchamiania shella |
| `terminal.ack` | O | subscription ID, monotonic throughSeq | Watermark renderera; nie zmienia domeny |
| `terminal.claim/renew/release` | C | session epoch + lease token/version | Lease; `terminal.controlChanged` |
| `terminal.input/resize` | C | session epoch, lease, input seq/ID lub resize seq | Bytes receipt / rozmiar; ordered terminal delta |
| `files.list/stat/read/searchNames` | FR | entry identity; cursor i opcjonalna file revision | Ograniczony odczyt; `FILE_CHANGED` dla nieaktualnego tokena |
| `files.watch` | FR | workspace epoch, watch cursor | Invalidation; `files.invalidated`, overflow → resync |
| `files.create/mkdir` | FW | parent identity/revision + destination absent | Receipt, file revision; `files.invalidated` |
| `files.rename` | FW | source identity/revision, parent identities/revisions, target absent | Receipt; `files.invalidated` |
| `files.remove` | FW | entry identity/revision, parent revision, confirmation | Receipt; `files.invalidated` |
| `git.repositories/status/diff/log/show` | GR | repo binding, paginacja; HEAD/index token dla spójnego widoku | Ograniczony wynik; `git.invalidated` po zmianie |
| `git.stage/unstage/commit` | GW | repo binding, expected HEAD/index; file revisions dla stage | Receipt; `git.invalidated` |
| `git.fetch/push` | GN | repo binding, remote/ref z hosta, expected refs | Operation; `git.invalidated`, `operation.changed` |
| `git.pull` | GN + git.write | repo binding, expected HEAD/index/worktree i refs; ff-only | Operation; `git.invalidated`, `operation.changed` |

`terminal.move` w produkcie v1 działa **wyłącznie wewnątrz jednego workspace’u**.
Transfer między workspace’ami jest poza v1, także gdy root/project jest wspólny.
`files.create` tworzy wyłącznie pusty regularny plik; params nie ma `content` ani uploadu.
Brak file editor/write-content API i arbitralnych patchy w v1; rename nie nadpisuje celu.
`files.remove` usuwa tylko plik, link lub pusty katalog; nie ma recursive delete.
Precondition katalogu nie gwarantuje atomowości rekurencyjnego usuwania zmiennego drzewa.
Nonempty directory daje `DIRECTORY_NOT_EMPTY`; link usuwamy bez podążania do celu.
Mutacje File API odrzucają repo metadata (`.git`, zatwierdzone gitdir/commondir),
chronione konfiguracje hosta i ich aliasy; walidacja identity działa po rozwiązaniu ścieżki.
Nie pozwalają podmienić workspace root ani configu wykonywalnych profili. Shell ma prawa OS.
Git read zawsze wymaga izolowanego wykonawcy. Zmiana config/attributes unieważnia
lokalną zgodę wykonawczą, ale niezmieniony fingerprint nie dowodzi niezmienności helpera.
`git.execute` z tą zgodą świadomie dopuszcza pełne wykonanie zmiennego kodu repo;
bez tej capability podmiana helpera przy stałym config nie może prowadzić do wykonania.
Odmowa daje `REPOSITORY_EXECUTION_REQUIRED`, nie ciche rozszerzenie grantu.

## Revisions, przyjęcie i trwały wynik

Revisions/sequences/offsets to dziesiętne stringi u64; UUID pozostają stringami UUID.
`domainRevision` dotyczy struktury/nazw, nie każdego bajtu PTY lub pliku.
`fileRevision`, `repoStateToken` i event cursor są osobnymi opaque tokenami, nie timestampami.
Mutacje lokalne TUI/IPC przechodzą przez ten sam coordinator i podnoszą te same revisions.
Jeden host-owned project/repo mutation admission obejmuje także lokalnych agentów/MCP:
agent runtime pozostający w Tauri zgłasza przez IPC intent i pobiera ograniczony lease
coordinatora; to wewnętrzny kontrakt, nie nowy publiczny endpoint Remote.
Process-local guard w osobnym procesie nie spełnia tej gwarancji. Lease ma ownership,
expiry i fence; nie trzymamy transakcji SQLite przez wykonywanie zewnętrznego narzędzia.
Utrata IPC/expiry nie potwierdza końca działającego writera: kolidujące zapisy pozostają
zablokowane do potwierdzonego końca/terminate albo lokalnego rozstrzygnięcia kwarantanny,
zgodnie z 02. Nie uznajemy samego wygaśnięcia lease za bezpieczne zwolnienie blokady.
Shell i niezależny Git nadal mogą zmieniać dysk poza admission. Nie obiecujemy globalnej
blokady procesów ani atomowego CAS wobec dowolnego external write; host ponownie sprawdza
identity/preconditions przy efekcie i sygnalizuje wykryty konflikt lub niepewny wynik.

`requestId` jest lokalny dla połączenia; `operationId` jest UUID mutacji, zachowany po disconnect.
Klucz deduplikacji: `(principal authorization, workspaceId, operationId)`; hash obejmuje
metodę, target, params i preconditions, ale nie nowy requestId/transport timeout.
Zmiana payloadu dla istniejącego ID daje `IDEMPOTENCY_CONFLICT`, nigdy nową operację.
Sprawdzenie praw poprzedza ujawnienie receipt, także przy powtórzonym operation ID.

Dla mutacji SQLite: domain CAS, zmiana stanu, nowa revision, receipt, event/outbox
są jedną transakcją. Sukces nie może opublikować revision bez trwałego receipt i odwrotnie.
Dla efektów FS, tworzenia/kończenia PTY i Git: najpierw trwałe admission/intent, potem ponowny fence i efekt;
po nim transakcja finalizuje receipt, revisions i event/outbox. SQLite nie obejmuje OS/Git.
Crash pomiędzy efektem a finalizacją daje `outcome_unknown`; reconcile nie wymusza sukcesu.
Receipt zawiera hash, IDs, stan i minimalny wynik, bez trwałego cache plaintext payloadu.
Zwykły input/resize ma osobne, ograniczone receipts w RAM konkretnej epoki sesji;
nie zapisujemy każdego klawisza ani jego łatwego do odgadnięcia hasha w SQLite.
Receipt input oznacza liczbę bajtów przyjętych przez PTY, nie wykonanie polecenia przez shell.
Po utracie kanału/epoki nie replayujemy input niezależnie od dostępności receipt.
Retencja receipt: proponowane 24 h od finalizacji; limit budżetu zgłaszany przed admission.
Niezakończonych intents nie usuwamy jako zwykłego cache; restart wymaga recovery/reconcile.
Po retencji `OPERATION_EXPIRED` nie oznacza „nie wykonano”. UI odczytuje stan zasobu.
Reconnect, timeout i restart klienta **nigdy automatycznie nie replayują mutacji ani input**.
Odczyt/status można ponowić; świadome nowe działanie użytkownika otrzymuje nowe operation ID.

## Status, cancel i timeout

Maszyna operacji: `accepted → running → succeeded | failed | cancelled | outcome_unknown`.
`accepted → cancelled/failed` jest dozwolone przed pierwszym efektem.
`cancelRequested` jest flagą, nie obietnicą zakończenia ani osobnym wynikiem.
`operation.status` jest odczytem autorytatywnego receipt/stanu wykonawcy hosta, bez skutków.
Wymaga tego samego principal binding i aktualnych capabilities operacji; inni nie enumerują IDs.
Nieznany ID daje `OPERATION_NOT_FOUND`; znany wygasły tombstone daje `OPERATION_EXPIRED`.
Po usunięciu tombstone brak rekordu także nie dowodzi braku historycznego efektu.

`cancel` jest idempotentną prośbą wobec tego samego operation ID; finalny stan zwraca bez zmian.
Przed efektem usuwa z kolejki i kończy `cancelled`. Podczas wykonania zatrzymuje bezpieczne
etapy/subprocess, lecz nie cofa wysłanego input, commit, delete ani zdalnego push.
`cancelled` oznacza potwierdzone zatrzymanie przed skutkiem; możliwe częściowe/nieznane
skutki dają `failed` z jawnym partial result albo `outcome_unknown`, nie fałszywy brak efektu.
Stan finalny jest niezmienny; późniejszy odczyt/reconcile może dopisać dowody do unknown,
ale nie uruchamia ponownie operacji. Revocation nie czeka na zakończenie cancel.

`timeoutMs` jest ograniczonym budżetem obsługi od odbioru przez host, liczonym monotonicznie.
Deadline przed admission/efektem daje `DEADLINE_EXCEEDED` z `effect: none`.
Długa operacja zwraca operation handle przed deadline odpowiedzi; wykonanie ma osobny limit.
Timeout czekania/utrata odpowiedzi nie dowodzi anulowania; klient pyta o operation ID.
Po przekroczeniu limitu wykonawcy host żąda cancel; nierozstrzygnięty efekt to unknown.
Nie ma retry-on-timeout mutacji, a `retryable` błędu nie jest pozwoleniem na replay.

## Atomic workspace subscribe i resync

Host w jednej sekcji serializacji rejestruje subskrypcję i pobiera snapshot przez `throughSeq=N`.
Snapshot zawiera workspace epoch, domain revision, subscription ID i opaque cursor N.
Kolejka dostarcza wyłącznie eventy od N+1; żadna zmiana nie wpada w szczelinę snapshot/live.
`eventSeq` porządkuje workspace stream; terminal output i watches mają własne sekwencje.
Nie wolno utożsamiać eventSeq z domain revision: event operacji może nie zmieniać domeny.
Filtrowanie per capability zachowuje ciągłość przez `cursor.advance`, bez ujawnienia payloadu.

Propozycja S0.5: journal workspace 10 min i 4096 eventów; wcześniej osiągnięty limit wygrywa.
Kolejka subskrybenta: 1 MiB; admission snapshotu i reassembly dziedziczy limity dokumentu 04.
Resume przy zgodnych epoch/runtime i retained cursor odtwarza eventy po cursor w kolejności.
Duplikat z tym samym seq można odrzucić; luka, inny epoch/runtime, overflow lub stary cursor
zwraca `RESYNC_REQUIRED`, zamyka starą subskrypcję i wymaga nowego atomic snapshotu.
ACK cursor oznacza zastosowanie stanu przez klienta; nie zatrzymuje eviction journalu.
Snapshot może przyjść w chunks; eventy czekają do jego kompletnej walidacji i zastosowania.
Disconnect nie usuwa operation receipts; resync nie jest replayem mutacji.
File/Git events są invalidation, nie obietnicą kompletnej historii zewnętrznych zapisów.
Overflow watch wymusza ponowne list/status; nie maskujemy go udanym pustym wynikiem.

## Przykładowe DTO i błędy

Nazwy pól poniżej są propozycją canonical camelCase do wygenerowania z Rust/Serde.

```json
{"v":2,"type":"state","workspaceId":"7debf0e1-51d0-4241-b063-28dcf80a0061","workspaceEpoch":"dfe4f478-598a-408c-8bc8-2a56e44317cc","runtimeGeneration":"9","domainRevision":"42","subscriptionId":"sub-1","throughSeq":"108","cursor":"opaque-cursor-108","name":"Build","tabs":[]}
```

```json
{"v":2,"type":"error","requestId":"req-2","operationId":"c01b33aa-7995-40e9-a131-12223825bb47","error":{"code":"REVISION_CONFLICT","message":"Stan workspace’u uległ zmianie.","retryable":false,"effect":"none","details":{"expectedRevision":"41","actualRevision":"42"}}}
```

```json
{"v":2,"type":"event","subscriptionId":"sub-1","workspaceId":"7debf0e1-51d0-4241-b063-28dcf80a0061","workspaceEpoch":"dfe4f478-598a-408c-8bc8-2a56e44317cc","eventSeq":"109","cursor":"opaque-cursor-109","kind":"workspace.changed","domainRevision":"43","operationId":"c01b33aa-7995-40e9-a131-12223825bb47","data":{"change":"terminal.renamed","tabId":"a22502f2-d7c3-4728-8214-6407177d1abe","name":"Tests"}}
```

Wspólny error envelope HTTP/RPC ma `code`, bezpieczny `message`, `retryable`, `effect`
(`none | committed | partial | unknown`) i walidowane per-code `details`; nigdy stack/token/root.
`effect: committed/partial/unknown` dla mutacji wymaga operation ID i ścieżki odczytu statusu.
HTTP mapuje: 400 validation; 401 `AUTH_REQUIRED`; 403 scope/unshared; 404 niedostępny zasób;
409 CAS/epoch/idempotency/host busy; 410 operation expired; 426 update; 429 resource limit;
503 freshness/service unavailable; 504 deadline. RPC używa tych samych kodów bez HTTP status.
`retryable=true` dopuszcza retry bezpiecznego odczytu/admission po usunięciu przyczyny;
status mutacji rozstrzyga się osobno. Brak praw nie ujawnia istnienia obcego zasobu.
Registry zawiera również `FILE_CHANGED`, `CONTROL_REQUIRED/REVOKED`, `SESSION_EXITED`,
`CREDENTIALS_REQUIRED`, `UNSUPPORTED_CAPABILITY`, `RESYNC_REQUIRED`, `OUTCOME_UNKNOWN`,
`DIRECTORY_NOT_EMPTY`, `PROTECTED_PATH`, `INVALID_ARGUMENT`, `SERVICE_UNAVAILABLE`,
`REPOSITORY_EXECUTION_REQUIRED` (403; bez wskazywania treści chronionej konfiguracji).

## Mapa wdrożenia kontraktu i odbioru

Ścieżki artefaktów to propozycje w nowym canonical repozytorium `lomi-remote`, nie obecne pliki. Katalog `remote-server` zawiera specyfikację.
Źródłem DTO jest `crates/lomi-remote-protocol`; JSON Schema/TS/OpenAPI to generowane wydania.
CI odrzuca ręczny drift, nieznane pola, nieprawidłowe enumy i liczby u64 zamiast stringów.

| Etap | Generowany kontrakt / fixtures | Obowiązkowe negatywne testy |
| --- | --- | --- |
| S0.5 | Manifest osi wersji, HTTP/OpenAPI, RPC/error/grant schemas; golden JSON i canonical signature bytes | Downgrade, extra fields, overflow, unknown capability, podmieniony purpose/key/epoch |
| 1 | State/command/receipt/event/terminal profile fixtures; crash-recovery cases | CAS race, receipt bez revision, snapshot/live gap, restart unknown, manage uruchamia shell tylko po zgodzie |
| 2 | Enrollment/session-class/grant/ticket fixtures, DB constraints | H jako C i odwrotnie, forged class, obce FK, refresh reuse, key w URL, plaintext publication |
| 3 | Rust/WASM/mobile crypto vectors i handshake/admission transcripts | Ticket replay, consumer key mismatch, stale generation, revoke podczas queued input |
| 4 | Projekcja mixed layout i shared revisions, move/close fixtures | Cross-workspace move, dirty private editor, nowe okno tworzące shell, brak manage |
| 5 | Files/Git params, preconditions, stream/cancel/status fixtures | Content w create, recursive remove, protected metadata/alias, pull bez write, external effect crash |
| 6 | Wspólne TS runtime validators i lifecycle recordings wszystkich klientów | Replay po reconnect, luka cursor, overflow, cache plaintext po lost auth, współdzielenie kluczy okien |
| 7 | Release manifest/digests i contract compatibility report | Niezgodny artefakt/profil, rollback przy złym schema, niekwalifikowany adapter Git read |

S0.5 zatwierdza dokładne TTL/limity, transport admission i profile na podstawie prób;
nie pozwala usunąć wymaganych gwarancji przez samą zmianę wartości budżetu.
Odbiór wymaga generowania artefaktów oraz testów native↔WASM↔mobile i rzeczywistych
SQLite/PostgreSQL/procesów dla transakcji i awarii, zgodnie z dokumentem 07.
