# 04 — Protokół, terminale i operacje workspace’u

## Wersjonowanie i kanały

Projektujemy nowy **Remote API major 2** (`/v2/remote`), application protocol major 2, **podpisany grant/context crypto v3** i osobny identyfikator profilu terminala. Numery mają różne odpowiedzialności. Stary terminal-only protokół nie jest negocjowany wstecz. Niezgodność daje `UPDATE_REQUIRED` przed połączeniem z danymi.

Produkt v1 używa tych nowych wersji. Macierz operacji, dokładne warunki admission, stany i logiczne endpointy są w [09](09-kontrakty-i-stany.md). Nazwy metod poniżej są skrótem katalogu; nie zastępują schematów, które trzeba wygenerować i zamrozić w S0.5.

Nowe `ChannelPurpose`:

- `workspace`: metadane, komendy/odpowiedzi, events i ograniczone strumienie plików/Git;
- `terminal`: stan i ordered I/O jednej sesji PTY z jej epoką.

Cel kanału, workspace epoch, capability set, grant ID/revision, peer identity i profile/version są związane podpisem i Noise prologue. Kanał workspace nie staje się nieograniczonym kanałem do PTY. Endpoint dispatch waliduje każdą operację i target, także po otwarciu kanału.

W v1 zostawiamy prosty model: jeden workspace channel na aktywny klient-workspace, terminal channel na dołączony pane. W ramach workspace channel są stream IDs dla plików/Git, oddzielne limity i priorytety. Jeśli transfer blokuje control, ograniczamy go i odrzucamy, zamiast rozbudowywać transport do ogólnego tunelu TCP. Wszystkie payloady tych kanałów są E2EE.

## Wspólny kontrakt i model komend

Kontrolne komunikaty: rygorystyczny JSON/UTF-8 z wygenerowanym schematem. Duże dane i terminal output: binarne ramki, bez base64 w strumieniu. Canonical encoding podpisów pozostaje w Rust crypto; JSON klienta nie jest podstawą do samodzielnego składania podpisu w kilku językach.

Przykład logicznej komendy, po odszyfrowaniu:

```json
{
  "v": 2,
  "type": "request",
  "requestId": "rpc-connection-local-id",
  "operationId": "c01b33aa-7995-40e9-a131-12223825bb47",
  "workspaceId": "7debf0e1-51d0-4241-b063-28dcf80a0061",
  "workspaceEpoch": "dfe4f478-598a-408c-8bc8-2a56e44317cc",
  "expectedRevision": "42",
  "timeoutMs": 10000,
  "method": "terminal.create",
  "params": { "tabName": "Build", "profileId": "default" }
}
```

`requestId` koreluje żądanie w połączeniu. `operationId` identyfikuje mutację podczas retry. 64-bitowe revisions/sequences/offsets w JSON kodujemy jako dziesiętne stringi; klient JS nie obcina ich przez `Number`. Binary framing ma ustalone endian/length, hard limits i test vectors.

Odpowiedź to `result`, `error` lub identyfikator `operation` ze stanem `accepted/running/succeeded/failed/cancelled/outcome_unknown`. Błąd ma stabilny kod, flagę retryable i bezpieczny komunikat; surowy stderr może być osobnym ograniczonym wynikiem dla uprawnionego klienta.

Istotne kody: `AUTH_REQUIRED`, `SCOPE_DENIED`, `WORKSPACE_UNSHARED`, `STALE_EPOCH`, `REVISION_CONFLICT`, `FILE_CHANGED`, `CONTROL_REQUIRED`, `CONTROL_REVOKED`, `SESSION_EXITED`, `RESYNC_REQUIRED`, `RESOURCE_EXHAUSTED`, `CREDENTIALS_REQUIRED`, `UNSUPPORTED_CAPABILITY`, `DEADLINE_EXCEEDED`, `OUTCOME_UNKNOWN` i `UPDATE_REQUIRED`.

### Idempotency i równoczesne operacje

Host zapisuje przyjęcie mutacji i hash parametrów przed wykonaniem. Ten sam `(principal, workspace, operationId)` z innymi parametrami daje konflikt. Wynik/receipt przechowujemy domyślnie 24 h, z limitem liczby i rozmiaru. Po upływie retry window klient musi odczytać stan, nie ponawiać niepewną mutację jako nową.

Nie obiecujemy exactly-once dla efektów zewnętrznych, input terminala ani Git push. Awaria między wykonaniem a zapisaniem receipt daje `outcome_unknown`; odczyt/reconcile lub świadoma decyzja użytkownika rozstrzyga wynik. Retry po reconnect nie wykonuje automatycznie commit/push/delete/input. Nową kartę można rozpoznać po utworzonym UUID i operation ID.

Mutacje układu są szeregowane per workspace, mutacje repozytorium uwzględniają fizyczny Git common directory i worktree, operacje plikowe używają wspólnego admission/revision. Dwa workspace’y tego samego projektu i linked worktrees nie omijają kolidujących blokad przez różne workspace ID. Lokalni writerzy Tauri/MCP uczestniczą przez IPC opisane w [02](02-architektura.md). Nie trzymamy blokady bazy podczas sieciowego Git. Zewnętrzne procesy nieuczestniczące w admission nadal wymagają rewalidacji stanu; revision aplikacji nie jest blokadą całego dysku.

## Ścieżka otwarcia workspace’u

1. Klient loguje się własną metodą konta i pobiera katalog hostów/workspace’ów.
2. Inventory ujawnia wyłącznie minimalne dane routingu i status; prawdziwe nazwy/root/titles nie trafiają do nieszyfrowanego katalogu.
3. Klient tworzy identity i pairing. Host sprawdza konto, sharing consent, aktualną politykę i proponowany capability set.
4. Host automatycznie zatwierdza własne konto według polityki lub czeka na ręczną decyzję. Podpisuje grant v3. Klient sprawdza podpis, pin, epochs, capabilities, expiry i kontekst.
5. Obie strony pobierają oddzielne jednorazowe relay tickets i nawiązują świeży Noise handshake.
6. Workspace channel zwraca snapshot metadanych i `domain_revision`; następnie ordered events. Katalog może zawierać także pusty workspace, który da się otworzyć i utworzyć w nim pierwszy terminal.
7. Wybrane terminale otrzymują własny snapshot i delta. Input jest dostępny po render ACK i otrzymaniu lease; Explorer/Git działa na osobnych jawnych uprawnieniach.
8. Utrata uprawnień zamyka kanały i czyści stan wrażliwy, a nie tylko ukrywa przyciski.

## Revisions i zmiana membership

Rozdzielamy:

- `host_access_epoch`: revoke wszystkich dostępów hosta;
- `runtime_generation`: aktualny proces hosta dopuszczony przez wyłączny backend lease;
- `workspace_epoch`: unshare/re-share, zmiana root lub reset bezpieczeństwa;
- `grant_revision`: zmiana capabilities konkretnego klienta;
- `domain_revision`: nazwy, karty, splity i membership terminali;
- `session_epoch`: konkretny proces PTY, zmienia się przy restarcie;
- `event_seq/output_offset`: kolejność danych wewnątrz danej sesji/kanału.

Grant workspace z `terminal.observe/control/manage` dotyczy bieżących **terminalowych** zasobów tego workspace’u, także utworzonych później; użytkownik wyraża tę zgodę przy sharing. Nie podpisujemy pełnej listy wszystkich session ID przy każdej zmianie layoutu. Przy tworzeniu terminal channel host i authority sprawdzają aktualną przynależność `(workspace, session, session_epoch)` i wiążą ją w context. W usuniętym zasobie od razu blokujemy nowe operacje i stare kanały tej sesji.

`domain_revision` nie jest automatycznie revision grantu. Utworzenie karty nie odcina zdrowych kanałów innych terminali. Zmiany autoryzacji i epochs nadal odcinają dostęp. `terminal.move` w v1 zmienia układ wyłącznie wewnątrz workspace’u. Przenoszenie żywego terminala między workspace’ami pozostaje poza v1; przyszłe rozszerzenie wymaga nowego kontekstu/grantu docelowego i unieważnienia kanału źródłowego.

Lokalna domena i cloud inventory nie mają wspólnej transakcji. Host zapisuje domenę oraz publication outbox w jednej transakcji. Zmianę wysyła z monotonicznym numerem i CAS; dopiero potwierdzona publikacja pozwala otworzyć zdalny kanał nowego terminala. UI może wcześniej pokazać `starting/publishing`. Unshare/delete blokuje lokalne wykonanie **przed** oczekiwaniem na cloud; opóźniona publikacja nie wznawia dostępu. Startup po niepewnym zamknięciu zaczyna się od fence i uzgodnienia epochs.

Publication, approval i channel admission niosą także `runtime_id/generation`; stare requesty poprzedniego procesu są odrzucane. Generation jest związane z podpisanym kontekstem i sprawdzane przez authority. Runtime lease odnawiamy w heartbeat; lokalny termin przydatności liczymy od początku żądania, aby późna odpowiedź nie przedłużała zaufania o czas timeout. Utrata lease natychmiast po upływie lokalnego deadline blokuje zdalne wykonanie. Automatyczny restart czeka na wygaśnięcie starego lease; administracyjny takeover odwołuje poprzednią generację i jej kanały.

## Terminal: własność, snapshot i sterowanie

### Stan terminala Rust

Wczesny spike wybiera silnik pod `TerminalState` i potwierdza wykonalność eksportu do klientów xterm. Kandydat `alacritty_terminal` ma model grid/terminala; sam `vte` jest parserem, nie kompletnym emulatorem. `vt100` jest kandydatem porównawczym, nie zakwalifikowaną automatyczną zamianą.

Preferowany profil v1: host utrzymuje pełny bieżący stan i bounded scrollback; eksportuje checkpoint w uzgodnionym formacie oraz bezpieczny prefiks ANSI/restore adapter dla xterm. Kolejność: reset odbiorcy → odtworzenie checkpointu, wymiarów, trybów i obu ekranów → zastosowanie suffix/pending parser state → live bytes. Serializer jest częścią projektu do zbudowania, nie funkcją, którą zakładamy w Alacritty. Jeśli poprawnej kontynuacji nie da się dowieść, etap 0 kończy się zmianą projektu profilu/adaptera, nie ukrytą zależnością Node lub wydaniem niepełnego replayu.

Sprawdzamy screen/alternate screen, cursor/modes, resize/reflow, scrollback, UTF-8 przerwany między chunkami, szerokie znaki/emoji/combining, kolory, bracketed paste, mouse modes, OSC, hiperlinki i niedokończone escape sequences. Testy obejmują `vim`, `less`, `top/htop`, `tmux` jeśli zainstalowany, shell i rzeczywiste CLI używane w Lomi. V1 nie obiecuje protokołów graficznych/sixel/kitty ani pełnej zgodności każdego emulatora terminala.

Odpowiedzi terminala na DSR/DA i podobne zapytania generuje **jeden hostowy model**, a klienci nie duplikują ich do PTY. Zdarzenia `onData` pochodzące z odpowiedzi parsera klienta muszą być odróżnione od intencjonalnego input użytkownika albo filtrowane przez ustalony adapter. Nie kwalifikować wielu obserwatorów bez testu braku podwójnych odpowiedzi. OSC 52 i inne efekty lokalne nie mogą automatycznie zmieniać schowka klienta.

### Atomic subscribe i flow control

Każde zdarzenie output/resize/exit ma seq. Snapshot ma `throughSeq`, `outputOffset`, dimensions, profile i `sessionEpoch`. W jednej operacji host pobiera checkpoint i rejestruje subskrypcję delta od kolejnego seq. Zapis do PTY i model są uporządkowane; brakujących bajtów nie maskujemy samym tekstem ekranu.

Klient ACKuje output po przetworzeniu przez renderer, nie po odebraniu pakietu. Bounded per-client queue nie blokuje innych klientów ani odczytu PTY. Wolny klient dostaje `RESYNC_REQUIRED` i świeży snapshot; stale przeciążony zostaje odłączony. Historia jest ograniczona, ale utrata starego replayu nie uniemożliwia nowego snapshotu. Ordered exit jest przekazywany po ostatnim output.

Reconnect zawsze tworzy nowy kanał i handshake. Jeśli epoka/profil nie pasuje, porzucamy lokalny stan. Sam widok odzyskuje output, ale odzyskanie kontroli zależy od aktualnego focus, uprawnień i nowego lease. Nie replayujemy niewysłanych klawiszy po utracie połączenia.

### Wiele klientów i rozmiar terminala

Wiele klientów może obserwować ten sam PTY. Jeden aktywny lease obejmuje **pisanie i resize**. Startowo lease 5 s, odnowienie co około 2 s; terminy sprawdza monotoniczny zegar hosta. Local desktop input może odebrać lease zdalnemu klientowi, generując event. Odłączenie/focus loss zwalnia lokalny zamiar sterowania. Pasywny focus okna nie kradnie kontroli.

Rozmiar PTY pochodzi od właściciela lease, po debounce i walidacji. Obserwator dostosowuje viewport bez zmieniania globalnej geometrii. Bez lease host zachowuje ostatni poprawny rozmiar. Dwa okna o różnych rozmiarach nie mogą co klatkę wzajemnie resize’ować shella. Układ kart/splitów jest wspólny; przewijanie i wybór aktywnej karty są lokalne.

Input ma własny input ID/seq i receipt liczby zapisanych bajtów. Częściowy zapis nie oznacza możliwości bezpiecznego wysłania całości ponownie. Po revoke/lost auth sprawdzamy fence tuż przed syscall zapisu. Wklejanie dużych fragmentów jest ograniczone i potwierdzane przez klienta.

## Katalog metod v1

| Grupa | Metody logiczne | Uwagi |
| --- | --- | --- |
| Workspace | `get`, `subscribe`, `capabilities`, `operation.status/cancel` | Bez zdalnego zmieniania root, host secrets lub autostartu |
| Terminal tabs | `terminal.create`, `rename`, `split`, `move`, `close`, `restart` | Wersjonowana domena, profile tylko z hosta; close/restart może kończyć proces |
| Terminal I/O | `attach`, `snapshot`, `ack`, `claim`, `renew`, `release`, `input`, `resize` | Odrębny terminal channel i session epoch |
| Explorer | `files.list/stat/read/searchNames/watch/create/mkdir/rename/remove` | Root-relative, paginacja, revision i ograniczenia |
| Source Control | `git.repositories/status/diff/log/show/stage/unstage/commit/fetch/pull/push` | Fizyczny repo/worktree guard, Git credentials na hoście |

V1 nie zawiera ogólnego `exec arbitrary command` w RPC, port-forwardingu, browser.open, android.start, plugin.invoke, system.settings ani zdalnego instalowania narzędzi. Pełny shell jest osobnym świadomie udostępnionym terminalem.

### Explorer

Root jest rozwiązywany na hoście przez `workspaceId`, a nie nadsyłany przez klienta jako ścieżka absolutna. API operuje względnymi ścieżkami/opaque entry IDs. Trzeba obsłużyć nazwy niebędące UTF-8 na Unix bez strat: opaque ID + display name, z odpowiednio zakodowanym identyfikatorem ścieżki w kontrakcie. Windows ma osobną walidację case, junction/reparse points, device names i alternatywnych strumieni.

`list` ma cursor i limit; `watch` emituje invalidation z revision, nie nieograniczony stream całego dysku. `read` jest ograniczonym podglądem, zachowuje encoding/line endings i nie odczytuje devices/FIFO. Pliki binarne/duże zwracają metadane i informację o limicie. W v1 nie ma arbitralnego uploadu/downloadu całych repozytoriów ani edytora współdzielonych buforów.

Mutacje wymagają expected file identity/revision i root-relative otwierania chronionego przed wyjściem przez symlink/TOCTOU. Podgląd nie podąża poza root; zewnętrzny symlink pokazujemy jako link. Rename w v1 nie nadpisuje istniejącego celu. `files.create` tworzy pusty plik z warunkiem nieistnienia; nie przenosi treści ani executable mode klienta. Remove obejmuje plik/link lub pusty katalog, bez rekursywnego usuwania; ma potwierdzenie i oczekiwaną revision. Zmiana zawartości katalogu przez zewnętrzny proces kończy usunięcie katalogu błędem, nie szerszym delete. Kosz tylko jeśli platforma zapewnia go w danym kontekście, inaczej jawne trwałe usunięcie. Serwer bez GUI nie może obiecywać systemowego kosza użytkownika.

Sekrety/data directory hosta nie mogą leżeć w udostępnianym root ani root obejmować ich przez katalog nadrzędny. File API blokuje mutacje `.git` i zatwierdzonych katalogów gitdir/commondir oraz własnego root; operacje index/ref należą do GitService. Sprawdzenie dotyczy tożsamości pliku/katalogu, nie tylko tekstu ścieżki. Hardlink może udostępniać zawartość spoza drzewa: v1 pokazuje jego metadane, ale odmawia odczytu treści i mutacji regularnych plików z wieloma dowiązaniami, z jawnym błędem `PROTECTED_PATH`. Sprawdzenie link count dotyczy otwartego handle; adapter bez kwalifikowanego sprawdzenia odmawia tej operacji. Testy obejmują podmianę i utworzenie dowiązania podczas operacji. Root nie jest izolacją shella ani ochroną przed lokalnym właścicielem danych; brak dodatkowego dowiązania nie dowodzi pochodzenia treści i nie zabezpiecza przed dowolnym zewnętrznym zapisem.

### Git / Source Control

Git musi być zainstalowany na hoście; jego brak wyłącza capability Git, a terminal/Explorer nadal działa. Wywołania używają argv i kontrolowanego env, bez składania poleceń przez shell. `status --porcelain=v2 -z` oraz pozostałe parsowalne formaty służą do poprawnej obsługi nazw. Zewnętrzne diff/textconv, automatyczne fetch i dowolne executable paths z klienta są niedozwolone.

**Samo argv i wyłączenie hooks nie zabezpiecza Git read.** Atrybuty/config mogą uruchamiać clean/process filters także przy status/diff; stage/pull mogą uruchamiać clean/smudge. `git.read` wymaga osobnego wykonawcy read-only: bez procesów potomnych/wykonania skonfigurowanego kodu, bez sieci i bez odczytu danych spoza zatwierdzonego repo/root oraz minimalnego runtime Git. Ograniczamy env/config, wyłączamy optional writes i używamy platformowego mechanizmu izolacji procesu. Niewspierana konfiguracja lub brak zakwalifikowanego adaptera daje jawny błąd capability, nie niezabezpieczony fallback. Filtry wymagające wykonania nie są automatycznie uruchamiane dla obserwatora.

Istniejący `lomi-control-core/src/git_read.rs` stosuje macOS sandbox i ma test odmawiający wykonania filtra przy diff. Port takiej gwarancji na Linux/Windows jest osobną bramką bezpieczeństwa w etapie 0/5. Nie chodzi o sandbox całego shella — terminal.control zachowuje jawnie pełne prawa konta. Wszystkie platformy reklamowane jako kompletne v1 muszą przejść tę bramkę dla Source Control.

Zewnętrzne gitdir/commondir powiązanego worktree nie są automatycznie uznawane za dowolną dozwoloną ścieżkę. Host rejestruje i sprawdza identity właściwego repo oraz minimalne zatwierdzone katalogi metadanych; podmiana pliku `.git`, symlinku lub `commondir` unieważnia binding. Repo nadrzędne poza root wymaga jawnej lokalnej zgody na jego zakres. Klient nie wybiera własnego gitdir ani nie rozszerza dostępu przez przesłanie ścieżki. Testy obejmują także config includes i podmianę zewnętrznych gitdirs podczas operacji.

V1 obejmuje stage/unstage całych plików, nie dowolne patche klienta ani interactive rebase. Commit zawiera jawny message, expected HEAD/index state i ustawioną na hoście tożsamość Git. Diff/history są paginowane, a duże/binarne pliki mają limit. Conflict po zmianie HEAD/index nie może zostać zamieniony w force.

Fetch/pull/push używają istniejących poświadczeń konta OS na hoście: SSH key/agent lub credential helper. UI nie odbiera prywatnych kluczy. Domyślnie `GIT_TERMINAL_PROMPT=0`; brak możliwości uwierzytelnienia daje `CREDENTIALS_REQUIRED` i instrukcję konfiguracji na hoście/terminalu. Pull w v1 jest `--ff-only`; konflikt/rebase rozwiązuje się w terminalu. Push bez force, bez ustawiania nowego remote URL przez RPC. Signed commit lub helper wymagający GUI może być niedostępny w usłudze i kończy się zrozumiałym błędem.

Repo hooks, filters i credential helpers mogą wykonywać kod hosta. **Fingerprint config/attributes nie pinuje kodu helpera**: `filter.clean = sh ./tools/filter.sh` nadal wskazuje tę samą komendę po podmianie skryptu. Samo hashowanie konfiguracji nie może więc podnieść `git.write` do uprawnienia wykonawczego.

Domyślny ograniczony wykonawca `git.write/network` wyłącza hooks i odmawia konfiguracji wymagającej repo-controlled executable filters/helpers. Nie pomija wymaganego filtra i nie stage’uje przez to niepoprawnych danych; zwraca `REPOSITORY_EXECUTION_REQUIRED`. Dozwolone są kwalifikowane, host-managed credential/transport helpers poza obszarem modyfikowalnym przez File/Git API, z ustalonymi executable identity, argv, env i zależnościami. Sama ścieżka poza root nie dowodzi bezpieczeństwa: skrypt wywołujący kod worktree, alias/hardlink lub niezweryfikowany shell fragment nie przechodzi tej kwalifikacji. Nie da się dowieść ograniczenia — operacja jest odrzucona.

Opcjonalne `trusted-repository-execution` wymaga **osobnej lokalnej zgody i podpisanej capability `git.execute`**, oprócz write/network właściwego dla operacji. To pełne wykonanie kodu repo z prawami konta OS, także kodu zmienionego później przez pull/file mutation; nie jest trybem obserwatora ani obietnicą stałego, niezmiennego kodu. Nie dopisujemy go do grantów domyślnie. Fingerprint zatwierdzonej konfiguracji nadal wykrywa zmianę sposobu wykonywania; jego zmiana unieważnia zgodę. Status/diff zawsze korzysta z izolowanego read-only wykonawcy również przy `git.execute`. Nie zmieniamy globalnej konfiguracji użytkownika.

Obowiązkowy test: podmiana skryptu helpera przez rename lub ff-only pull bez zmiany config/attributes nie może doprowadzić do wykonania go przez grant bez `git.execute`. Sprawdzić też transitive helper, include files i alias poza root. Terminal.control/manage pozostają niezależnymi jawnymi możliwościami wykonania shella; ich obecność nie zastępuje wymaganego uprawnienia konkretnego RPC Git.

## Karty i okna

Nowa karta terminalowa jest wspólnym zasobem workspace’u na A, B, WWW i mobile. Nowe okno jest **lokalnym kontenerem widoku** klienta, bez utworzenia nowego shella. Desktop B otwiera nowe okno Tauri z tym samym remote workspace reference. Web udostępnia link/akcję otwieraną po kliknięciu i działa z ograniczeniami popup blocker. Mobile oferuje kolejną trasę/widok i nie obiecuje wielu natywnych okien na każdym telefonie.

„Zamknij widok” odłącza klienta. „Zamknij terminal” jest mutacją hosta z ostrzeżeniem o działającym procesie i eventem do pozostałych klientów. Domyślny nowy terminal startuje w root z zatwierdzonym shell profile; dowolnego polecenia startowego klienta nie przemycamy jako nazwy karty.

## Budżety początkowe

To proponowane ustawienia do pomiaru w etapie 0, nie zmierzone możliwości produktu:

| Zasób | Punkt startowy |
| --- | --- |
| Workspace’y / aktywne terminale | 32 / 32 na host; osobne limity |
| Połączenia klientów / obserwatorzy terminala | 8 klientów na host / do 8 obserwatorów jednej sesji, z globalnym budżetem |
| Kanały | 256 na host; admission odmawia nadmiaru, nie gwarantuje iloczynu wszystkich limitów |
| Ramka zaszyfrowana / input | Około 16 KiB ramki zgodnie z crypto; input do 16 KiB |
| Złożony komunikat kontrolny / snapshot | 1 MiB / do 8 MiB, chunkowane, z łącznym limitem reassembly |
| Kolejka output obserwatora / replay | 1 MiB / 2 MiB na sesję przed resync |
| Podgląd pliku / strona listy | 1 MiB tekstu / 200 wpisów, paginacja |
| Scrollback | Do 10 000 linii i limit pamięci na sesję; globalny budżet modelu weryfikowany pomiarem |
| Równoległe operacje | 4 file reads i 1 mutacja repozytorium; limity per host/principal |

Snapshot nie blokuje input control bez ograniczenia czasu. Chunk assembly ma timeout, limit równoczesnych strumieni i limit RAM niezależny od deklarowanego rozmiaru. WSS compression wyłączona na zaszyfrowanych danych; kompresja application payload nie jest potrzebna w pierwszym wydaniu. Rekey/nowy handshake następuje przed limitami liczby ramek istniejącej implementacji crypto.
