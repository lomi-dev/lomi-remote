# Stan wdrożenia Lomi Remote

Stan roboczy z 23 października 2026 według czasu Europe/Warsaw. Starsze wyniki produktu odnoszą się do checkpointu źródeł z 20 października UTC; nowe dowody E1/E2 i hosta opisano niżej. Szczegółowy zapis implementacji, wyników, otwartych problemów i następnych prac. Aktualizowany podczas realizacji zadania.

### 23 października — Ubuntu product service po zimnym starcie VM

Runner produktu zakończył się powodzeniem na tymczasowej maszynie Ubuntu
24.04 aarch64. Zbudował bieżące źródła i uruchomił testy produktu; zestaw
`lomi-host` przeszedł 545 testów. Tymczasowa usługa `systemd --user` z linger
była aktywna po zimnym zatrzymaniu i starcie VM, przed pierwszym zaobserwowanym
logowaniem SSH. Sprzątanie usunęło jednostkę i fixture, przywróciło pierwotny
stan linger i nie pozostawiło procesów fixture.

Raport: `../lomi-remote/artifacts/product-linux/7e165239-ab9c-4e13-846c-93f0d8929f94/report.json`.
Ma `complete=true`, `passed=true`, ale `qualified=false`: to ograniczony
odbiór usługi produktu na jednej maszynie Linux, nie instalator, pełny VPS,
Cloud/relay ani kwalifikacja wydania. Pełna lista otwartych bramek pozostaje
w `../lomi-remote/docs/implementation/progress.md`.

### 23 października — Remote Web v2 blokuje stary input po przejściu karty w tło

Zmiana widoczności strony i `pagehide` natychmiast wyłączają sterowanie
terminalem, przerywają otwieranie kanału i zamykają stary kanał. Powrót otwiera
wyłącznie istniejącą sesję, wymaga świeżego snapshotu i claimu z bieżącego
kanału; nie tworzy shella ani nie odtwarza wpisanego inputu. Odpowiedź claimu
ze starego kanału nie może zmienić stanu nowego. Przejście w tło sprząta również
kanał po zakończonym terminalu.

Walidacja: 144 testy Remote Web, 711 asercji; `pnpm build` zakończył się
powodzeniem (0 błędów i ostrzeżeń diagnostycznych, 4 istniejące wskazówki;
Vite nadal ostrzega o dużym chunku); Chromium, Firefox i WebKit przeszły testy
odtworzenia IndexedDB oraz blokady inputu w lifecycle. Przeglądarkowy harness
protokołu przeszedł aktualne testy na mockowanym hoście. To nie jest odbiór
żywego relay, fizycznego urządzenia ani pełnego shella E3.

Równoległy odbiór native transport zatrzymał się przed testem: brakowało
przypiętego binarium `transport_authority`. Zbudowanie przykładu z bieżącego
źródła dało inny SHA-256 niż pin, a porównanie wykazało też dziesięć zmienionych
hashy wejściowych. Nie poluzowałem pinów; native E6 nadal wymaga świadomego
odświeżenia manifestu i ponownego uruchomienia zestawu.

Przegląd mobilnego E5 wykazał, że aplikacja ma wyłącznie kanał terminala v1 i
nie ma klienta RPC v2, `files.watch` ani Explorera. Sam ekran plików nie może
bezpiecznie użyć hostowych metod v2 bez kanału z kontekstem zatwierdzonego
workspace'u i authority. Następny bezpieczny fragment to wspólny dla mobile
klient v2, a potem tylko odczyt Explorera. Nie zmieniono aplikacji mobilnej.

Sprawdzony został również model poświadczeń API. Mobile używa klucza urządzenia
i grantu z `/v1/remote/mobile/channels`. `/v2/remote/channels` przyjmuje
przeglądarkowe cookie powiązane z zarejestrowanym oknem albo bearer klienta
klasy `desktop`. Grant mobilny nie jest żadnym z tych poświadczeń. Klucz
urządzenia uwierzytelnia peer Noise, ale nie autoryzuje utworzenia kanału v2.
Telefon wymaga jawnego mostu autoryzacji po stronie API i bazy, admission hosta
i istniejących kontroli workspace. Nie użyto przeglądarkowej tożsamości ani
ominięcia kontroli grantów.

Diagnostyka SSH do Windows 10 wykryła przypięty klucz hosta, ale żadna lokalna
tożsamość nie uwierzytelniła konta `woro-server`. Test zatrzymał się przed
wykonaniem zdalnego polecenia i instalacją fixture. Ten host nie kwalifikuje
Windows 11 ani Windows Server.

### 23 października — mapa bezpiecznego GitService

Host nadal odrzuca wszystkie zdalne metody Git jako unsupported. Audyt ścieżki
potwierdził, że protokół ma kontrakty i scope `GitRead`, ale ingress nie ma
autoryzacji/dispatchu ani usługi Git. Istniejące `FileRoot` celowo ukrywa
metadane `.git` oraz chroni gitdir/commondir, więc nie można go użyć do
bezpiecznego odkrywania repozytoriów. Spike'i macOS/Linux nie są usługą
produkcyjną. Bezpieczny pierwszy krok to przypięty hostowy model repozytorium,
stabilne ID i snapshot brokera; nie podłączono RPC i nie dodano natywnego
fallbacku Git.

### 23 października — host produktu i usługa użytkownika na VPS Ubuntu x86_64

Zamrożone archiwum 1 344 plików zbudowało się na autoryzowanym VPS Ubuntu
24.04.5 x86_64 (Rust/Cargo 1.98.1). Wybrany zestaw produktu przeszedł 819
testów w 32 zestawach; 2 istniejące testy były ignorowane. Testy obejmują
rzeczywisty TLS/Noise z dwoma klientami i jednym PTY, unshare przed inputem i
w trakcie snapshotu/watch, `files.watch` z ACK/resume oraz inotify wykrywające
zmiany przy tym samym mtime i rozmiarze. Dwa odrębne połączenia SSH potwierdziły,
że runtime i sesja terminala przetrwały
rozłączenie, a ponowne otwarcie widoku nie tworzy drugiego shella. Tymczasowa,
nieuprzywilejowana usługa `systemd --user` przeszła 9 kontroli przygotowania
i 23 kontrole weryfikacji obejmujące właściciela, rozłączenie SSH, restart i
awarię procesu, PTY, przerwane odinstalowanie oraz zachowanie profilu. Po
zebraniu dowodów usunięto dokładnie oznaczony fixture, katalog tymczasowy i
tymczasową jednostkę.

Raport: `../lomi-remote/artifacts/product-linux-vps/cc81ca51-b68a-44b0-b399-404cf40e0980/report.json`.
Logi, manifest i archiwum źródeł są w tym samym katalogu. Wynik nie obejmuje
rebootu ani startu bez zalogowanego użytkownika, instalatora E3, kodu urządzenia,
wdrożonego Cloud/relay z fan-outem, browser/mobile shell ani długiego soak wielu
hostów. Nie zamyka E1/E2 ani E3.

### 23 października — Consumer S5–S7 i odzyskanie Cloud po TCP drop

Prywatny odbiór Consumer na PostgreSQL 18.6 przeszedł 962 testy bez błędów,
w tym authority, revoke, inspekcję readiness prunera, Prisma i TypeScript.
Zamknął wykryty mismatch metadanych UUID; raport nie wskazuje kolejnej luki w
zestawie Consumer.

Następny przebieg CloudWorker zakończył się kodem 0 na lokalnym PostgreSQL 18.6.
Rzeczywisty loopback TLS handler zatwierdził publikację, po czym zerwał TCP
przed ACK. Worker zachował zamiar, uzgodnił kursor odczytem i nie powtórzył
PUT; restart zachował stan i również nie opublikował ponownie. Test centralnego
revoke zamknął obu aktywnych klientów, odciął wspólnego ownera, zwrócił 401 przy
odczycie runtime i nie zmienił zapisanego runtime. Testy i cleanup przeszły.

Raport Cloud: `../auth-app/artifacts/cloud-worker-restart-pg18-tcp-drop-clt-20261023/e82ef717-6afa-4550-b3f6-9875d2910405/runtime-proof.json`.
Raport Consumer: `../auth-app/artifacts/consumer-s5-s7-acceptance-20261023/e986852b-584b-478b-9ae3-fe79bc230320/runtime-proof.json`.
Są to prywatne fixture'y handlera i TLS, nie odbiór wdrożonego relay ani
pełnego fan-outu Cloud. E1/E2 nadal nie są zamknięte.

### 23 października — Remote Web wybiera aktywny data plane v2

Gdy konto otrzymuje z API URL aktywnego relay v2, Remote Web nie uruchamia już
równolegle starego workera live v1. Ekran parowania v2 nadal wymaga jawnej
zgody, a samo otwarcie widoku nie tworzy terminala. Bootstrap sesji i wylogowanie
pozostają na HTTP control plane v1, więc to migracja data plane, nie pełne
przełączenie protokołu.

Walidacja na Node 22.23.3: test bootstrapu przeglądarki przeszedł, w tym kontrolę
braku workera v1 dla kont v2; `bun test tests` przeszedł 140/140 testów
(697 asercji); `pnpm check` zakończył się 0 błędów i 0 ostrzeżeń; build
statyczny przeszedł kontrolę outputu. Vite nadal zgłasza istniejący chunk ponad
500 kB. Testy używają mocków HTTP i nie sprawdzają aktywnego relay, logowania
kodem, shella w przeglądarce ani reconnectu bez replayu. E3 i E6 pozostają
otwarte.

Szczegóły: `../lomi-remote/docs/implementation/progress.md`, sekcja z
23 października.

### 22 października — Cloud TCP drop na PostgreSQL 18.6 zablokowany przez środowisko

Próba rozszerzenia odbioru o rzeczywiste zerwanie TCP, restart CloudWorkera,
uzgodnienie kursora oraz revoke wielu klientów zatrzymała się podczas linkowania
sterownika Rust. Apple `cc` odmówił pracy, ponieważ lokalna licencja Xcode nie
została zaakceptowana. Baza testowa nie została uruchomiona; raport potwierdza
cleanup. To brak nowego wyniku testu, nie awaria produktu. Wcześniejszy
ograniczony dowód Cloud z PostgreSQL 16.15 pozostaje jedynym zaliczonym fixture'em.

Raport: `../auth-app/artifacts/cloud-worker-restart-pg18-tcp-drop-20261022/a1f316d0-cb4d-4351-adab-794a7d6f7f99/runtime-proof.json`.

### 22 października — odbiór mobilny zablokowany przez licencję Xcode

Xcode 27.1 jest zainstalowany i wybrany. `xcodebuild` oraz `xcrun devicectl`
odmawiają działania, dopóki administrator Maca nie przejrzy i nie zaakceptuje
licencji Apple. Nie uruchomiono builda ani testu iPhone'a. Android nie jest
wykrywany przez `adb`. Właściciel stanowiska musi zaakceptować licencję lokalnie;
nie można jej zaakceptować z sesji bez hasła administratora.

### 22 października — przegląd containmentu PTY na macOS

Domyślny host uruchamia worker w zwykłej grupie procesów. Daje to cleanup
lidera, PTY i pierwotnej grupy, ale test potwierdza, że naturalnie kończący się
shell może pozostawić potomka działającego w tle. Opcjonalny backend coalition
pozostaje wyłączony: skanowanie członków nie dowodzi atomowego zatrzymania
forkowania ani pełnej śmierci potomków. Bezpiecznego domyślnego containmentu
macOS nadal nie ma; nie zmieniono zachowania produkcyjnego.

### 22 października — kontrola parsera dowodów Consumer S5

Dozwolony test źródłowego recordera przeszedł 7/7: sprawdza zamknięty format
markerów i błędów bez uruchamiania procesu ani PostgreSQL. Nie uruchomiono
przygotowanego `positive-auth.sql`; integracja recordera, dokładne porównanie
katalogu, admission oraz odbiór S5–S7 pozostają otwarte.

### 22 października — przegląd ścieżki Git w hoście

Protokół deklaruje wszystkie metody Git, ale zdalny ingress nadal odrzuca je
kanonicznym `unsupported`; host nie ma GitService ani bezpiecznego adaptera.
Najmniejszy sensowny następny fragment to wyłącznie odczyt `git.repositories`
i `git.status`, po zaprojektowaniu izolacji, przypięcia repozytorium i mapowania
stabilnych identyfikatorów plików. Nie zmieniono ścieżki wykonania Git.

### 22 października — kontrole Remote Web i mobile

Na Node 22.23.3 Remote Web przeszedł `pnpm check` (0 błędów, 4 wskazówki),
`pnpm test` (140/140), statyczny build z kontrolą outputu, auth bootstrap
(24 sprawdzenia) oraz odzyskiwanie tożsamości IndexedDB w Chromium, Firefox i
WebKit. To testy kontraktów/klienta; nie jest to E3 relay/shell ani odbiór
wszystkich metod E6.

Mobile na Node 22.23.3 przeszedł typecheck, 289/289 testów, renderer, crypto
provenance i config checks. `release:check` zatrzymał się na `xcodebuild` exit
69 z powodu niezaakceptowanej licencji Apple; build iPhone'a oraz E6 z
urządzenia nie zostały wykonane.

Pełny browser crypto fixture próbował zbudować natywny Rust peer dla
Chromium/Firefox/WebKit, ale linkowanie `ring` zatrzymało się na tej samej
licencji Xcode (exit 69), zanim uruchomił przeglądarki. Trójsilnikowy test
IndexedDB powyżej nie pokrywa kontraktu ani metod z E6.

Desktop przeszedł `pnpm check`, `pnpm test` (306/306 oraz AI runtime 45/45) i
frontend `pnpm build`. Bundle zbudował się, lecz `Workbench` ma 1,089 kB po
minifikacji i Vite zgłasza chunk ponad 500 kB. To nie test natywnego Rust hosta,
pełnego instalatora ani wydajności wymaganej w E7.

### 22 października — limit okien Consumer i odpowiedź HTTP 429

Test runtime przechodzi przez publiczne endpointy: po 63 oknach wysyła
równolegle dwa poprawne żądania. Dokładnie jedno zostaje przyjęte, drugie
otrzymuje kanoniczne `RESOURCE_EXHAUSTED` (`retryable=true`, `effect=none`),
a liczba rekordów pozostaje równa 64. Prywatny przebieg Consumer na PostgreSQL 18.6
zakończył się kodem 0: 7 testów runtime/schema, 961 zaliczonych testów w 16
plikach, 1 pominięty test, Prisma i TypeScript; baza została zatrzymana.
Receipt ma `productionQualified=false` i nie zamyka S5/S6/S7.

Raport: `../auth-app/artifacts/consumer-window-cap-race-429-20261022/cacd6b45-8216-40f6-8579-7fc7271cdc70/runtime-proof.json`
(SHA-256 `8d256b0d15fb96058ae9305fc4b0f81ddf528dbd91219f2c9395d067d0ac73b5`).

### 22 października — korekta odbioru restartu Cloud po utracie ACK

Wcześniejszy wynik `89bde8eb-...` pozostaje historycznym niezaliczonym
przebiegiem fixture'u. Późniejszy poprawiony fixture przeszedł: po utracie
ACK dla publikacji seq 8 nowy proces przejął wygasłą dzierżawę, uzgodnił
końcowy kursor lokalny i Cloud, opublikował tylko seq 1 nowej generacji i nie
powtórzył starego PUT. Sprawdził dokładnie dziewięć tras; centralny revoke
zamknął oba klienty. Testy użyły rzeczywistego handlera Remote, CloudWorkera i
prywatnego PostgreSQL 16.15 przez loopback TLS.

Raport:
`../auth-app/artifacts/cloud-worker-restart-cursor-acceptance-20261022/6ba2870c-d049-4a2d-834e-8acc5b2bbc9f/runtime-proof.json`.
To ograniczony fixture, `productionQualified=false`; wdrożony Cloud/relay,
fanout między hostami oraz pełne E1/E2 pozostają otwarte.

### 22 października — retencja tożsamości okna po revoke

Test runtime sprawdza, że sfinalizowana tożsamość okna pozostaje niezmieniona
po revoke nadrzędnej autoryzacji, a dalsze użycie jest odrzucane. Prywatny
zestaw Consumer na PostgreSQL 18.6 przeszedł: 7 testów runtime/schema, 962
testy łącznie w 16 plikach, walidację Prisma i TypeScript; baza została
zatrzymana i posprzątana. To ograniczony dowód Consumer, nie odbiór S5/S6/S7;
receipt ma `productionQualified=false`.

Raport: `../auth-app/artifacts/consumer-window-revoke-retention-rerun-20261022/5326616f-dea4-4ed4-9530-4829fc798a6f/runtime-proof.json`
(SHA-256 `8c4cb574edca300788e4d355e384dbcf46e7efd77d6b865b04774dd35b5a637f`).

### 22 października — kontrola kodu host `files.watch`

Na zadeklarowanych targetach host używa inotify (Linux), kqueue (macOS) i
`ReadDirectoryChangesW` (Windows), z okresową pięciosekundową rekonsyliacją
zmian przodka i ograniczeń backendu. Przegląd kodu nie jest testem integracji
Explorera ani odbiorem E5/E6; podpięcie klientów i pełne testy hosta pozostają
otwarte.

### 22 października — odłączenie SSH i reboot fixture usługi Linux

Na Ubuntu 24.04 ARM64 w VM `lomi-e0` świeży, prywatny snapshot źródeł
zbudował i przetestował `lomi-service-fixture`. Wszystkie cztery fazy
systemd-user fixture przeszły: przygotowanie 26/26, odłączenie SSH 2/2,
rzeczywisty stop/start VM i ponowny boot 8/8 oraz cleanup 4/4. Raport
potwierdza, że PTY przeżył zakończoną sesję SSH, jednostka wróciła po boot bez
logowania konta usługi, stara epoka nie została adoptowana, a fixture został
posprzątany. Build i natywne testy fixture zakończyły się kodem 0.

Raport: `../lomi-remote/artifacts/services-linux/evidence.json` (SHA-256
`afe2cffce88f3a57f178781c190c857c3d854b6aad88c7d1ff60186074e6c593`).
To dowód testowego runnera i usługi systemd-user na jednej VM, nie instalatora
ani produkcyjnej usługi systemowej; receipt jawnie ma
`qualifiedProductHost=false`. Nie obejmuje czystej instalacji E3, rzeczywistego
Cloud/relay, innych dystrybucji/architektur, revoke/watch/Git w produkcyjnym
przepływie ani pełnego E1/E2.

### 22 października — dostępność urządzeń do E6

Xcode 27.1 jest zainstalowany i wybrany jako aktywny Developer Directory.
`xcodebuild -checkFirstLaunchStatus` i `xcrun devicectl list devices` kończą
się jednak odmową z powodu niezaakceptowanej licencji Apple, więc build iOS
oraz inwentaryzacja iPhone'a pozostają zablokowane do lokalnej akceptacji.
`adb devices -l` nadal nie wykrywa Androida ani AVD. Fizyczne scenariusze
Android/iOS wymagane przez E6 nie zostały wykonane.

### 22 października — sprawdzenie lokalnych podpisów E7

Keychain ma jedną ważną tożsamość Developer ID Application, ale żadnej
Developer ID Installer. Windows 10 host laboratoryjny nie ma certyfikatu
Code Signing z kluczem prywatnym w CurrentUser/LocalMachine. Dostępność
notarization credential i podpisanych metadanych nie została potwierdzona.
Nie wykonano podpisywania ani publikacji.

### 22 października — ograniczenie TOCTOU w prototypie S5 na macOS

SDK tego hosta nie udostępnia `fexecve` ani `execveat`; test
`execve("/dev/fd/N", ...)` kończy się `EACCES`. Prototyp uruchamia więc
przypięty interpreter przez `posix_spawn(POSIX_SPAWN_START_SUSPENDED)`, czeka
na potwierdzenie stanu stopped, sprawdza kod procesu przez
`SecCodeCopyGuestWithAttributes`/`SecCodeCheckValidity`, a dopiero potem wysyła
`SIGCONT`. Wynik `waitpid` ma rozróżnione stany stopped-unreaped,
terminal-reaped i unknown; sygnał sprzątający jest dopuszczony tylko dla
potwierdzonego, wciąż nieodebranego dziecka. Odziedziczone `SIGCHLD=SIG_IGN`,
`SA_NOCLDWAIT` i niestandardowy handler są odrzucane przed spawnem. Sprzątanie
ponawia `SIGKILL` po `EINTR` i nie blokuje na reap po nieudanym sygnale.

Focused test przechodzi 17/17, również po niezależnym uruchomieniu; obejmuje
odrzucenie walidacji bez efektu dziecka, brak auto-reap oraz retry `EINTR`.
`clang -Wall -Wextra -Werror -fsyntax-only` przechodzi, a niezależny security
review nie znalazł już ścieżki do zabicia obcego PID. Pozostaje warunkowe
ograniczenie: gdy system odmówi `SIGKILL` z przyczyny innej niż `EINTR`, dziecko
może pozostać zatrzymane; proces odrzuca admission bez blokującego oczekiwania.
To nadal prototyp źródłowy: nie ma instalacji, admission roota, operator pin,
testu podpisanego artefaktu produkcyjnego ani pełnego S5.

### 22 października — regresja fail-closed dla metod Git

Bieżący `lomi-host` przeszedł natywny test TLS/Noise
`real_tls_noise_git_methods_are_refused_without_any_result_until_a_git_service_exists`
(1/1). Potwierdza on, że `git.repositories` nie zwraca sfabrykowanego wyniku
przed wdrożeniem GitService. To weryfikacja bezpiecznej odmowy; usługi Git
ani żadnej z metod E5 nadal nie ma.

### 22 października — Remote Web v2: reconnect ponownie sprawdza zgodę

Niezależny review wykrył, że ręczne połączenie i reconnect ufały lokalnie
zapisanej zgodzie. Przed otwarciem kanału klient teraz pobiera aktualny pairing,
wymaga aktywnego `approved`, sprawdza tuple konta/sesji/autoryzacji i fingerprint
tożsamości okna, a potem odświeża inventory i porównuje workspace, epoch, runtime
i podpis hosta. Zmiana sesji, klucza albo revoke zatrzymuje connect; unmount
anuluje oczekujące żądania. Nieznany wynik mutacji terminala nie jest ponawiany.

Walidacja bieżącego checkoutu Remote Web: `bun test` 137/137
(685 asercji), `astro check`
(45 plików, 0 błędów/ostrzeżeń, 4 hints), statyczny build i integralność
outputu przeszły. `astro check` oraz build zostały ponownie uruchomione po
poprawce; Vite nadal zgłasza istniejący duży chunk. Poprawka zamyka trzy
wyścigi: reuse rejestracji po zmianie tuple sesji, zapis odpowiedzi pollingu po
anulowaniu oraz commit inwentarza starego konta po zmianie konta. Worker
przekazuje tuple zweryfikowaną podczas rejestracji i UI porównuje ją z
inwentarzem przed utworzeniem requestu. Testy sprawdzają bramkę pollingu i
normalizację ID konta. Fixture przeglądarkowy v1 i test trwałej tożsamości
IndexedDB w Chromium, Firefox i WebKit nie są testem komponentu v2.

Ścieżka v2 pobiera snapshot workspace, otwiera istniejący terminal, tworzy nowy
wyłącznie po osobnej akcji użytkownika i może uruchomić Explorer. Utworzenie
shella zapisuje operation ID przed wysłaniem; po utracie odpowiedzi klient
sprawdza status bez powtarzania mutacji. Odzyskanie po refresh korzysta z
tab-local tuple sesji, identyfikatora okna i pairing ID oraz ponownie sprawdza
pairing, inventory i authority. Nie zapisuje ani nie odtwarza inputu.

To podłączona ścieżka opt-in, nie pełny odbiór E3: bootstrap konta i główna
ścieżka nadal zawierają v1. Nie przeszła instalacja na czystym Ubuntu/Debian
VPS, logowanie kodem na telefonie ani shell/Explorer przez wdrożony relay,
utraty sieci i unshare na prawdziwym hoście. E6 na desktopie i fizycznym
Androidzie/iOS pozostaje otwarte.

### 22 października — natywny product-host proof na Windows 10 LTSC

Na labowym Windows 10 Enterprise LTSC 19044 (x64, Rust 1.98.1) bieżący,
zamrożony build `lomiremote` przeszedł natywny proof CLI/host/SQLite/IPC/ConPTY
na syntetycznym prywatnym workspace. SSH-continuity start/stop, MSVC Clippy i
rustfmt również przeszły; fixture usunięto, bez pozostałych jego procesów.
Raport:
`../lomi-remote/artifacts/product-host-windows/b3e3aeab-75dc-4d58-b4ea-555f45122722.json`
(SHA-256 `dd512f4895eef778413d49754902b17eb6bd144cd42c554157301b20e380a396`).

To nie obejmuje SCM, poświadczeń ani prawdziwego workspace i nie kwalifikuje
Windows 11/Server ani macierzy wydania. Pełny boot/logon/logoff, systemowe
sekrety oraz odbiór E1/E2 pozostają otwarte.

### 22 października — ponowny Cloud heartbeat i revoke dwóch klientów

Fixture testowy nie odnawiał rzeczywistego heartbeat podczas attachu i
oczekiwania na oba terminale; wcześniejsza próba gubiła 5-sekundowe freshness
przed `Parked`. Teraz ten sam CloudWorker przechodzi przez rzeczywisty lokalny
handler HTTPS i aktualizuje `PeerEligibility`. Po zaparkowaniu nie odpytuje już
Cloud, więc nie konkuruje z centralnym revoke. Produkcyjny limit i fail-closed
pozostały bez zmian.

Pełny lokalny `runtime` przebieg zakończył się kodem 0: 961 testów handlera
przeszło, 1 pominięto, 0 nie przeszło; 7808 asercji. Prisma, TypeScript,
Rust build i cleanup także przeszły. Przy centralnym revoke epoch hosta wzrósł,
cofnięto wszystkie rodziny autoryzacji, supervisor dostał rzeczywiste HTTP 401,
wspólny owner został zablokowany, oba kanały TLS/Noise zamknięte, a rekord
runtime pozostał niezmieniony. Siedem tras Cloud pasowało do kontraktu. Prywatny
PostgreSQL 18.6 i listener TLS zostały zatrzymane.

Receipt:
`../lomi-remote/artifacts/cloud-actual-handler-refresh/b2a37672-001c-4e71-a994-bcb535ac7647/runtime-proof.json`
(SHA-256 `c6a503d53dfcbc9d38e24d67b8f70a7dd7110aa2daa7e0c2868718a70322bf87`),
log SHA-256 `0746ef84a2092df30878088f27b63ecfa54b891f5d84dc12efaf7e35afa34ade`.
`productionQualified=false`: to dowód lokalnego fixture, bez wdrożonego relay,
cross-host fanout ani pełnej macierzy wydania.

### 22 października — przygotowanie statycznej bramki consumer S5–S7

Naprawiono preparer, aby brał kandydackie pliki z katalogu przypiętego
manifestu zamiast ze starszej gałęzi staging; validator przypina aktualny
digest manifestu. Przeszło 53 kontrole statyczne i sprawdzenie zamrożonych
wejść. Utworzony plan ma status `PREPARED_NOT_EXECUTED`, zero wywołań
PostgreSQL i nie zawiera wyników SQL. S5/S6/S7 pozostają otwarte.

Receipt:
`../lomi-remote/artifacts/consumer-derivatives-plan/e1d69230-d471-40d1-aaa2-3a16b5bd673f`
(plan SHA-256 `3a4f37707311645612ebcc11dd417a9aeb614dd6950f030efa86a6f3a72184c0`).

### 22 października — Cloud lost-ACK na rzeczywistym handlerze: dowód częściowy

Prywatny fixture PostgreSQL 18.6 / Bun 1.4.2 zbudował Rust transport driver i
binarium testowe, zastosował migracje i ograniczone granty oraz uruchomił
rzeczywisty handler aplikacji i Rust CloudWorker przez lokalny TLS. Markery
potwierdzają publikację i refresh uprawnień, lost ACK po rzeczywistym TCP drop,
zachowany intent, brak advance sekwencji, reconcile przez GET bez ponownego
PUT oraz recovery po restarcie. Przeszedł też marker ACK po zamknięciu drugiego
klienta.

Agregat **nie przeszedł**: Bun 6/7; test centralnego revoke z dwoma klientami
nie doczekał parkowania obu terminali (`UnexpectedEof` w TLS/Noise fixture).
`shutdownAndCleanupCompleted=true`, klaster zatrzymany, źródła stabilne podczas
przebiegu, `productionQualified=false`. Nie zaliczam centralnego revoke ani
pełnego E2 na podstawie pozytywnych podmarkerów.

Receipt:
`../lomi-remote/artifacts/cloud-actual-handler/586ae1ec-f051-4d4b-9b07-f954c25b866d/runtime-proof.json`
(SHA-256 `46a281c013c27549f2eb47ed1bcd38c0f4794b00e92be115b47df6be99a7ba91`),
log SHA-256 `00c71d8859c7848007422e2c956eb145b528afe33cf084db51e18b66b8f8e6a9`.

### 22 października — restart po rzeczywistym utraconym ACK: odbiór niezaliczony

Nowszy fixture zapisał publication sequence 8 przez rzeczywisty handler,
zerwał gniazdo TLS przed odpowiedzią dla workera i otworzył ten sam HostStore
w drugim procesie. Faza przed restartem zachowała niepewny intent. Po restarcie
wygasła dzierżawa, więc worker wszedł w prawidłową ścieżkę ponownego claimu;
fixture błędnie wymagał natychmiastowego stanu `online`. Wynik to 6/7 testów,
786 asercji. Nie potwierdzono końcowego uzgodnienia kursora ani braku
powtórnego PUT. Przegląd nie ustalił błędu produktu; test odbiorowy pozostaje
niezaliczony i wymaga asercji całej ścieżki claim oraz końcowego stanu.

Receipt:
`../auth-app/artifacts/cloud-worker-restart-cursor-acceptance-20261022/89bde8eb-fdd9-4779-91b5-8ae756c87d1b/runtime-proof.json`.
Polityka fail-closed i produkcyjny kod Cloud nie zostały zmienione.

### 22 października — preflight VPS-a E3

Po potwierdzeniu klucza hosta w konsoli dostawcy wykonano wyłącznie odczyt
stanu VPS-a użytkownika: Ubuntu 24.04.5 x86_64, 27 GiB wolnego miejsca, sudo
bez hasła i brak jednostek systemd Lomi. Nie kopiowano ani nie instalowano
produktowych plików. Dokument instalacji oznacza przykładowe URL-e `lomi.dev`
jako projekt interfejsu, a repozytorium nie zawiera produkcyjnego instalatora
ani paczki wydania. Maszyna nadaje się na target E3, ale instalacja i pozostały
odbiór E3 nie zostały wykonane.

### 22 października — lokalny instalator testowy Linux

Dodano `../lomi-remote/tools/install_linux_local.py` do instalowania jawnie
wskazanego lokalnego binarium, bez pobierania i bez konfiguracji loginu,
sharingu, usługi lub autostartu. Instalator wymaga SHA-256, hashuje również
staging i przechowuje binaria w obiektach adresowanych hashem. Aktywny command
zmienia się jednym atomowym przełączeniem symlinka. Odrzucane są obce pliki i
symlinki oraz katalogi zapisywalne przez inne konta.

Focused unit tests: 10/10 lokalnie i 10/10 na Ubuntu 24.04 ARM64 VM; skan
białych znaków czysty. VM miała `umask 002`, więc nowo tworzone katalogi
ograniczono do trybu 0700; pliki testowe usunięto, a VM zatrzymano. To
unsigned/unreleased narzędzie deweloperskie; nie weryfikuje podpisu, nie
zastępuje TUF ani nie kwalifikuje czystej instalacji E3. VPS nie został
zmieniony.

### 22 października — pełny Host na Ubuntu 24.04 ARM64

Na świeżej kopii zamrożonych źródeł przeszedł natywny build `lomiremote` i
`tools/test-host.sh -p lomi-platform -p lomi-host-store -p lomi-terminal
-p lomi-host -p lomiremote` na Ubuntu 24.04 ARM64, kernel 6.8.0-147-generic,
glibc 2.39. Główna biblioteka Host: 541/541; wszystkie uruchomione zestawy
zakończyły się kodem 0. Przeszedł również test działania po zamknięciu
niezależnego SSH oraz tymczasowy cykl systemd-user: rozłączenie, restart,
crash, stop, trwałość tożsamości, brak automatycznego shella oraz sprzątanie
fixture'a. Raport końcowy potwierdza brak pozostałych procesów.

Raport: `../lomi-remote/artifacts/product-linux/3e4c5788-ed33-4ad5-b4bb-2291b9799da6/report.json`
(SHA-256 `cd94090428b613f331ad61d2e5aa326e05fd6bc5df5ebc2c2b6e9262baf4e92a`).
Raport jawnie oznacza `qualified=false`, a test usługi `bootQualified=false` i
`rebootTested=false`: nie kwalifikuje instalatora, systemd system service,
czystego bootu, Cloud/relay ani pozostałych targetów E1/E2/E7.

Pierwsza próba macOS `experimental-macos-session-cleanup` na macOS 27 zakończyła
supervision 5/13. Przyczyną było sprawdzanie SID procesów już kończących się
oraz uzależnienie zbieżności od całej listy procesów systemowych. Po poprawce
supervision przechodzi 13/13, testy biblioteki 26/26, formatowanie przechodzi,
a niezależny review nie znalazł materialnego problemu. Funkcja pozostaje
eksperymentalna i domyślnie wyłączona: nie daje gwarancji dla fork churn ani
potomków odłączonych przez `setsid`, więc wymóg containmentu nadal jest otwarty.

### 22 października — natywne watchery `files.watch` na trzech hostach

`FileRoot` rejestruje natywne watchery na zweryfikowanych, przypiętych
uchwytach katalogów: Linux używa inotify przez `/proc/self/fd`, macOS używa
kqueue vnode dla katalogu i do 64 plików bezpośrednich, ograniczonych
dostępnym budżetem deskryptorów, a Windows używa overlapped
`ReadDirectoryChangesW` na zweryfikowanym uchwycie asynchronicznym. Host nie
udostępnia klientowi ścieżek zdarzeń ani treści. Zdarzenie wyłącznie wyzwala
ponowną weryfikację fingerprintu i uzbrojenie watchera dla nowych lub
podmienionych plików. Przepełnienie, błędny rekord i błędy odczytu kończą
subskrypcję przez `ResyncRequired`. Wszystkie te platformy zachowują
pięciosekundową kontrolę tożsamości dla zmian rodziców oraz ograniczeń backendu.
Testy macOS wykrywają edycję pliku o tym samym rozmiarze po przywróceniu mtime
oraz ponowne uzbrojenie po utworzeniu pliku.

Na Macu natywnie przeszły testy `remote_files_watch` (11/11) oraz `lomi-files`
(20/20, w tym watcher przy niskim `RLIMIT_NOFILE`). `lomi-files` przeszło
również natywne testy na Windows 10 (29/29), w tym watcher katalogu głównego i
potomnego po bezczynnych odczytach, dwa kolejne cykle zdarzeń i osiem anulowań
bezczynnych watcherów oraz edycję pliku z przywróconym mtime.
Pierwszy test runtime ujawnił odmowę dostępu z `ReOpenFile`; adapter korzysta
teraz z overlapped `CreateFileW` dla katalogu głównego i asynchronicznych,
względnych otwarć potomków przez `NtCreateFile`. Niezależny review nie wykazał
pozostałego problemu bezpieczeństwa; zasugerował testy rearm/cancel, które
teraz przechodzą. Cross-check testów Windows
`cargo check -p lomi-files --tests --target x86_64-pc-windows-msvc` również
przechodzi. Pełny cross-check `lomi-host` z testami nie doszedł do kompilacji,
ponieważ brakowało toolchaina C dla zależności `ring`.
Transkrypt i sumy źródeł: `../lomi-remote/artifacts/windows-files-watch/2026-10-22/`.

Na Arch Linux x86_64 z Rust 1.98.1 przeszły natywnie: 21 testów `lomi-files`,
10 testów `remote_files_watch` i `cargo clippy --all-targets -D warnings`.
Źródło zostało zamrożone i sprawdzone SHA-256 przed rozpakowaniem; testowy
katalog i archiwum usunięto po potwierdzeniu braku procesów. Raport:
`../lomi-remote/artifacts/linux-host-current-source/2026-10-22-inotify-8d295873-5606-4bbb-a73a-0592d80ba1dd/runtime-proof.json`
(SHA-256 `94bdb676af6b153c347940d48768c9b0289c9c19995650af0e7dac21fcc1a40f`),
archiwum wejściowe SHA-256
`6b158e2cfb15847efc8f2e98e63e0fbc27e1f2beec3a4e002a828ecf58d9b8e6`.

Windows 10 jest tylko hostem laboratoryjnym, a Arch nie kwalifikuje Ubuntu
22.04+/Debian 12+. Watch nadal obejmuje jeden wybrany katalog. Linux przypina
do 256 plików bezpośrednich; macOS do 64, z dalszym ograniczeniem na podstawie
wolnych deskryptorów. Zakres rekursywny pozostaje otwarty. Cały E5 i gotowość
produkcyjna pozostają otwarte.

### 22 października — natywny test usługi SCM na Windows 10

Nowy przebieg `product-scm-windows` zbudował rzeczywisty `lomiremote.exe` i
przykład obserwatora na Windows, wykonał natywny test timeoutu oraz oba Clippy.
Test SCM uruchomił ręczną usługę jako LocalService w Session 0. Sprawdził
kontrolowany stop, awaryjny stop z kodem 1, restart bez automatycznego shella i
bez replay wpisanego tekstu, rzeczywisty wpis `--internal-scm` domyślnego CLI,
odmowę IPC obcemu kontu, przeżycie niezależnego sentinela i usunięcie dokładnej
usługi oraz profili fixture. Końcowy raport potwierdza zero pozostawionych
procesów.

Przebieg przeszedł: 7 lokalnych testów harnessu, build CLI, build przykładu,
test timeoutu, Clippy CLI, Clippy przykładu, dowód SCM i cleanup. Raport:
`../lomi-remote/artifacts/product-scm-windows/3e6cff18-7aa1-49e9-b538-46d3818be0a3.json`;
zamrożone wejście SHA-256
`c2dd73989e2d06ffaca43eb6c9f18a0ab7db2aa94a599a41b4f0d77614f675b2`.

Maszyna ma Windows 10 Enterprise LTSC 19044. Raport celowo oznacza
`qualified=false`: ten wynik nie kwalifikuje Windows 11 x64/ARM64, Windows
Server 2022+/Server Core, bootu, logon/logoff ani podpisanego wydania. Pełna
macierz E1/E7 pozostaje otwarta.

### 22 października — retencja wyzwań rejestracji okna konsumenta

Dodano migrację `202610220013_consumer_challenge_pruning`. Ograniczona
funkcja `lomi_prune_expired_consumer_window_challenges` usuwa wyłącznie
wygasłe, niezużyte wyzwania bez sfinalizowanej tożsamości potomnej; blokuje
wiersz autoryzacji rodzica. Funkcja ma osobną rolę właściciela bez logowania,
minimalne granty kolumnowe, przypięty `search_path` oraz kontrolę właściciela i
konfiguracji w inspektorze schematu. Gotowość aplikacji sprawdza obecność
funkcji i prawo wykonania bez wywoływania mutacji.

Prywatny fixture PostgreSQL 18.6 / Bun 1.4.2 przeszedł: sześć testów bazowych
i 1 179 asercji; ponowne zastosowanie rzeczywistych skryptów uprawnień
przeszło dwukrotnie. Dodatkowo przeszło 957 testów bez bazy / 7 729 asercji z
jednym wcześniejszym pominięciem, walidacja Prisma i TypeScript. Prywatny
klaster zatrzymano i posprzątano; wejścia źródłowe pozostały niezmienione.
Receipt:
`../auth-app/artifacts/consumer-challenge-pruning-20261022/1e7f1289-d88f-4ceb-ac73-14e06eb7134e/runtime-proof.json`
(SHA-256 `17af7106c7b07e0190f981ac04795ec5fd7383ed4947a5503f094d91d4580547`;
log SHA-256 `a5301e19230b6b34f15c3b1ccc57d3ec770ac843b93a6b049fe34a1dd6bc1762`).

Powtórzenie na bieżących źródłach dopisało do odbioru SQL jawne odmowy
`EXECUTE` dla `lomi_remote_api` i `lomi_remote_exchange`, przy zachowaniu
wykonania przez `lomi_runtime`. Prywatny PostgreSQL 18.6 / Bun 1.4.2 przeszedł
7 testów bazowych i 1 182 asercje; regresje bez bazy: 961 passed, 1
wcześniejszy skip / 7 808 asercji. Prisma, TypeScript i cleanup przeszły, a
hash wejściowego testu był identyczny przed i po fixture. Receipt:
`../auth-app/artifacts/consumer-challenge-pruning-verified-rerun/d15837c0-b437-4ade-b602-fdb014da8c07/runtime-proof.json`
(SHA-256 `8079f70a6059244a718c569b2506297e46661a2fc78c52d12bbb4b51ff799d4b`;
log SHA-256 `bf0a5543e107b2a424df9b8b19f9d431d2828dadf6688d5711c90aad87385ddd`).
To ograniczony lokalny fixture (`productionQualified=false`); nie kwalifikuje
pełnego S5 ani środowiska produkcyjnego.

To domyka retencję wyzwań w ramach ograniczonej ścieżki rejestracji; nie
rozwiązuje retencji sfinalizowanych tożsamości okien ani ich limitu 64. Pełny
cykl S5/S6/S7, E2 i gotowość produkcyjna pozostają otwarte.

Świeże powtórzenie 22 października na bieżących źródłach użyło lokalnego,
przypiętego Bun 1.4.2 i ponownie przeszło 7/7 testów bazowych z 1 182
asercjami oraz 961 testów regresji, jednym wcześniejszym skipem i 7 808
asercjami. Prisma, TypeScript i cleanup przeszły; wejścia nie zmieniły się,
PostgreSQL 18.6 nie otworzył listenera TCP, a prywatny klaster został
zatrzymany. Receipt:
`../auth-app/artifacts/consumer-authority-refresh/eb893538-eb8c-4acc-bac5-990f2ee0e5f6/runtime-proof.json`
(SHA-256 `fed286721deb79a40823a1069ea4bb54666deb30b333b8a22d26aab0472f9e15`;
log SHA-256 `f8b2246aef199487769b8f9ad48b96750126b1a57df42c74267a562c26fc5dbf`).
Receipt nadal ustawia `productionQualified=false`; to potwierdza ten ograniczony
lokalny zakres, nie pełne S5/S6/S7 ani E2.

### E3 — fundament trwałej tożsamości przeglądarki

Użytkownik wybrał trwały klucz per okno przeglądarki. `remote-web` zapisuje
zaszyfrowany seed w IndexedDB i wiąże go z autorytatywnym tuplem konta,
autoryzacji konsumenta oraz sesji źródłowej. Odświeżenie odtwarza lokalną
tożsamość bez ponownej rejestracji. Zmiana tuple, wygaśnięcie i udane
wylogowanie czyszczą lokalne rekordy i sesje workera. Czyszczenie anuluje
oczekujące pobranie WASM; pobranie ma też limit 10 sekund.

Walidacja po poprawce: pełne testy Remote Web 76/76 (485 asercji), TypeScript,
kontrola snapshotów pakietów oraz `bun run build` ze sprawdzeniem integralności
wyjścia statycznego przechodzą. Niezależny przegląd nie znalazł dalszego
konkretnego problemu w ścieżce czyszczenia. `astro check` zgłasza 0 błędów,
0 ostrzeżeń i jeden istniejący hint; Vite zgłasza chunk powyżej 500 kB.

Remote Web ma teraz jawnie włączaną ścieżkę v2 dla parowania, ticketu, relay,
Noise, grantu, terminala i Explorera. Osobny `REMOTE_RELAY_V2_URL` trafia do
uwierzytelnionego klienta wyłącznie przy aktywnej bramce v2; adres jest
walidowany niezależnie od endpointu v1. Domyślna ścieżka nadal używa v1.
Testy konfiguracji, pełny zestaw 137 testów Remote Web, build statyczny i test
trwałej tożsamości w Chromium/Firefox/WebKit przeszły. Nie wykonano czystego
odbioru VPS, logowania z telefonu ani rundy przez wdrożony relay i prawdziwy
host. Nie ma serwerowego endpointu statusu/cofania tożsamości okna, lokalne
czyszczenie nie usuwa wierszy serwera, a limit 64 okien na autoryzację nadal
obowiązuje. E3 i gotowość produkcyjna pozostają otwarte.

Host v2 obsługuje przychodzące pairing przez produkcyjny worker i przypięty
DataTransport. Worker automatycznie podpisuje kwalifikujące się granty zgodnie
z lokalną polityką udostępnionego workspace; jawne `share` w TUI jest zgodą
hosta. Nie ma osobnego ekranu zatwierdzenia każdego klienta. To nie podłącza
jeszcze klienta przeglądarki do utworzenia kanału.

### Najnowszy dowód E2: centralny revoke zamyka dwóch aktywnych klientów

Bieżący test `runtime` na macOS przeszedł z dwoma przyłączonymi klientami
TLS/Noise na tym samym ownerze. Rzeczywisty endpoint managera cofnął host:
epoch wzrósł, a wszystkie rodziny autoryzacji zostały unieważnione. Rzeczywisty
CloudWorker użył produkcyjnego supervisora autoryzacji i przypiętego TLS
DataTransport; GET runtime otrzymał 401 z handlera Remote. Supervisor zapisał
blokadę w tym samym `SharedOwner`. Obaj klienci dostali `Delivery::Closed`, oba
ich drivery rozłączyły się, a wiersz `host_runtime` nie uległ zmianie. Nie było
oczekującej publikacji i nie zmieniono reguły fail-closed.

Fixture wykonał się na macOS, Bun 1.4.2, PostgreSQL 18.6 (prywatny socket) i
Rust 1.98.1. Przeszły 7 testów DB, 913 regresji, Prisma, TypeScript, build Rust
i cleanup. TLS listener i prywatna baza zostały zatrzymane. Receipt:
`../auth-app/artifacts/host-credentials-runtime-central-revoke-multiclient-rerun3-20261022/589b8d69-b4ff-44b5-8a2d-da453f1fbbb3/runtime-proof.json`
(SHA-256 `97ba916956c057abfe5f4c58b92c93023d819dcb6627e1195df3d6ebc03e5d8d`),
log SHA-256 `ae1291be6a6386669b0427a95cb55a61d895ae2403b94696531fafbe37d2e03d`,
archiwum wejść SHA-256
`b942da37813ead630f9edaee04bd65c862a534578e0622aa0e9b9adf03ab06e1`.

To zamyka ograniczony test dwóch klientów i rzeczywistych lokalnych handlerów.
Nie obejmuje wdrożonego relay, cross-host fanout, reconnect ani pełnego E2.
S5/S6/S7, E2 i gotowość produkcyjna pozostają otwarte.

### Najnowszy dowód E2: rzeczywisty Cloud ACK po zamknięciu drugiego klienta

Test dwóch kanałów TLS/Noise dostał opt-in wariant fixture, w którym obaj
klienci i CloudWorker współdzielą `HostStore`, `SharedOwner` i `HostAuth`.
Klient B dostaje `Delivery::Closed` dla odczytu workspace, zanim Cloud
potwierdzi oczekującą publikację mutacji A. Potem prawdziwy CloudWorker
publikuje ją przez DataTransport i loopback TLS do rzeczywistego handlera
Remote oraz prywatnego PostgreSQL. Handler potwierdza zmianę publikacji po
zamknięciu klienta B. Nie zmieniono polityki fail-closed.

Receipt:
`../lomi-remote/artifacts/host-credentials-runtime-local/f35c6b32-2b60-4964-bf4a-cd195da9c57a/runtime-proof.json`
(SHA-256 `8a8bb86a689c32cf05c2729aa3c9e3698265410bf35e38b04769cca767a181a`),
log SHA-256 `ce949c83032f5af34bea94891fb6a87ed169e1cf93257c55f87a1c619da0ab2a`,
archiwum wejść SHA-256
`3db3876841eff2acd53ddd6b38b337b12ab30e2944598a798bbef41fb2f005b1`.
Run zakończył się kodem 0: test Bun, regresje, Prisma, TypeScript, offline
build i cleanup przeszły. Całość obejmuje 34 żądania Rust TLS, z czego 8 w
połączonym scenariuszu. PostgreSQL był socket-only i został zatrzymany.

To domyka wyłącznie ograniczony test multi-client + Cloud ACK. Reconnect po
zamknięciu, propagacja centralnego revoke, produkcyjny relay i pełne E2/S5/S6/S7
pozostają otwarte. `productionQualified`, `e2Qualified` oraz pełny odbiór
systemu pozostają false.

### Dowód CloudWorker: pierwszy claim bez runtime row

Najnowszy ograniczony przebieg `3967c452-82de-40d4-8dda-3805430e4a8d`
sprawdza pierwsze przejęcie hosta przy braku wiersza `host_runtime` w
prywatnym PostgreSQL. Rzeczywisty CloudWorker wysyła przez DataTransport i
fixture TLS: GET runtime → claim POST → GET runtime → heartbeat POST →
publication PUT. Handler tworzy generation 1 / epoch 5 / publication sequence
1. Lokalny binding i HostAuth uzgadniają epoch 5, workspace dostaje ACK, a
pending intent, outbox i retained operation zostają wyczyszczone. Fixture
zaczyna od istniejącej tożsamości hosta z epoch 4; nie dowodzi czystego
enrollment konta.

Receipt:
`../lomi-remote/artifacts/host-credentials-runtime-local/3967c452-82de-40d4-8dda-3805430e4a8d/runtime-proof.json`
(SHA-256 `04812532fa89883ac5100d713b54ed89735b4b96f833f0ab2683d47aa32c18b6`),
log SHA-256 `7ff8ad2868fbf68c1a0bb43e5f366827a3cc201d71a49b1473aaec4e2e73b3d4` i archiwum wejść SHA-256
`9b7fbbb4b4650a1008120b43beb0dd2a32d276e39c4829fb281912fe6402db46`.
Łączny przebieg obejmuje 26 żądań Rust TLS, 7 testów DB / 1 338 asercji,
regresje, Prisma, TypeScript, offline build Rust oraz sprzątanie. Niezależny
przegląd źródeł i konfiguracji nie znalazł istotnych problemów.

To dowód ograniczonego fixture lokalnego. Nie kwalifikuje produkcyjnego Cloud,
pristine-account enrollment, relay, koordynacji wielu klientów, consumer S5/S6/S7
ani E1–E7. Fail-closed pozostaje bez zmian.

### Bieżący host na maszynie Linux (22 października)

Po wznowieniu autoryzowanego SSH bieżące źródła skopiowano do osobnego katalogu
testowego; SHA-256 archiwum zgadzał się przed i po transferze
(`3d508fd35b320d9a174680d4d1e96c531a2202aaf32257267a862d96258cd299`). Na Arch
Linux x86_64, kernel 7.2.11 i Rust 1.98.1 `cargo clippy --offline -p lomi-host
--all-targets -- -D warnings` przeszedł, a pełne `cargo test --offline -p
lomi-host` zaliczyło 535/535. Użyto wcześniejszego cache `target`, poza kopią
źródeł. `cargo fmt -p lomi-host -- --check` przeszło lokalnie.

To aktualna runda na kodzie bieżącym, ale Arch nie jest kwalifikowanym Ubuntu
22.04+/Debian 12+. Opcjonalny `cloud-fixture`/PostgreSQL nie był uruchamiany.
Usługa na czystej maszynie, boot/restart, pełna macierz i produkcyjne E1/E2
pozostają otwarte.

### Poprzedni dowód CloudWorker z rzeczywistym handlerem

Najnowszy przebieg runtime `a1a04f67-6031-456d-aa2f-eda0ac1097e4` łączy
publikację i odświeżenie uprawnień, przejęcie wygasłej dzierżawy oraz odzyskanie
zatwierdzonej publikacji z nieznanym ACK. Claim wykonuje GET → claim POST → GET
→ heartbeat POST → publication PUT; wygasłe generation 2 / epoch 3 przechodzi
na generation 3 / epoch 4, a kursor zaczyna się od sekwencji 1.

Osobny scenariusz centralnego revoke przechodzi przez rzeczywisty handler
managera kont i Rust CloudWorkera. Manager przesuwa epoch i unieważnia wszystkie
rodziny autoryzacji hosta. Następny GET workera otrzymuje 401, lokalny owner
zamyka authority, a `host_runtime` nie zostaje zmieniony. Fixture sprawdza
pojedynczego workera; nie dowodzi propagacji do wielu klientów.

Nowy scenariusz lost-ACK wykonuje GET → heartbeat → pojedynczy publication
PUT → GET. Rzeczywisty handler zapisuje sekwencję 7 w prywatnym PostgreSQL;
fixture zastępuje odpowiedź powodzenia kanonicznym 409 `OUTCOME_UNKNOWN` z
`Cache-Control: no-store`. Przed GET lokalny kursor zostaje na sekwencji 6, a
intencja i outbox pozostają zachowane. GET uzgadnia dokładny workspace, bez
drugiego PUT. To model nieznanego wyniku po commicie, nie dosłowne zerwanie
gniazda TCP/TLS. Reguła fail-closed dla pozostałych przypadków nie została
zmieniona.

Receipt:
`../lomi-remote/artifacts/host-credentials-runtime-local/a1a04f67-6031-456d-aa2f-eda0ac1097e4/runtime-proof.json`
(SHA-256 `d7218cc86c7b63905ed068247a2877e5c9e35e453692e7d640175d3fddbfc7f6`).
Exit code 0; 21 żądań Rust TLS obejmuje transport race, publikację, claim,
lost-ACK i jeden GET centralnego revoke. 7 testów DB / 1 329 asercji, 912
regresji z jednym istniejącym pominięciem, Prisma, TypeScript, offline build
Rust i sprzątanie przeszły. Log SHA-256
`b351d89683a545bb212f1f5c802936123be8abf3628f58fc1b5220946607d715`;
archiwum zamrożonych wejść SHA-256
`bdbbc010344e113cce37ad0d7ee8d73d0400a8f0301cdc22d614414e086c6159`.
Claim, lost-ACK i central revoke mają pozytywne znaczniki w receipcie.

To nadal ograniczony test lokalny: `productionQualified`,
`productionPostgres186Qualified` i `boundedPostgres186FixturePassed` pozostają
false. Nie obejmuje relay, wielu klientów ani ich koordynacji fail-closed,
restartu hosta ani pełnego E2/S5/S6/S7. Dowód centralnego revoke obejmuje
pojedynczego workera. Dowód lost-ACK używa odpowiedzi kanonicznej zamiast
rzeczywistego zerwania połączenia.

### Ograniczony dowód E2 z 22 października

Test handlera z prawdziwym PostgreSQL sprawdza, że aktywny runtime hosta i
opublikowany stan workspace przeżywają rotację poświadczeń. Stary bearer
przestaje działać; nowy kontynuuje ten sam binding. Proces Rust
`DataTransport` wykonał siedem żądań HTTPS przez loopback do rzeczywistego
handlera Remote: runtime GET, heartbeat i publikację przed rotacją, odmowę
starego bearer oraz te same trzy operacje nowym bearerem. Nowy bearer
opublikował sekwencję 4 przez CAS. Następnie rzeczywisty `CloudWorker`
wykonał GET, heartbeat i publication PUT. Po ACK test cofnął lokalne
udostępnienie workspace; ten sam Worker wykonał heartbeat i kolejną publikację.
Prywatna baza przesunęła sekwencję 4→5→6, z pustą listą workspace’ów; lokalny
ACK wskazuje sekwencję 6 bez oczekującej operacji i outboxu. Końcowy znacznik
workera to `complete`. Binding runtime był wcześniej utworzony przez fixture,
więc przebieg nie obejmuje gałęzi `claim`.

Fixture Bun 1.4.2 / PostgreSQL 18.6 przeszedł: 7 testów DB / 1 329 asercji,
912 regresji / 7 255 asercji z jednym istniejącym pominięciem, Prisma,
TypeScript, budowę Cargo/Rust i sprzątanie. Raport:
`../lomi-remote/artifacts/host-credentials-runtime-local/86f79b72-576c-4db4-9c72-1a176735f42d/runtime-proof.json`
(SHA-256 `a061c304661444ee4a45675ce25a2d415ddc30d9921ec0ed80ca00cecc85bbd8`).
Test użył przypiętych binariów Bun i PostgreSQL z `lomi-remote/artifacts`, nie
systemowego Bun 1.3.14.

To dowód ograniczonego transportu Rust TLS i odświeżenia publikowanych
uprawnień przez pojedynczego CloudWorkera. Nie dowodzi produkcyjnego zaufania
TLS, relay, globalnego revoke ani reguły fail-closed dla wielu klientów, gdy
Cloud nie potwierdzi publikacji. Raport zachowuje `productionQualified: false`;
cały E2 i pełny odbiór systemu pozostają otwarte.

### Korekta S5 i fixture Cloud z 22 października

Niezależny przegląd harnessu jedenastu zapytań znalazł sprzeczne dowody:
`root-audit.json` pozostawia niezależny przegląd otwarty, a
`root-check.json` ma `PASS_PENDING_INDEPENDENT_ROOT_RESULT_REVIEW` oraz
`rootOuterPrivateAbsent=false`. Zbiorczy receipt twierdzi wynik przeciwny, choć
wiąże hashe tych samych plików. Nie znaleziono późniejszego zamknięcia wyniku.
Run zewnętrzny ma zapisane exit 0 i pozostaje dowodem kandydującym, bez
akceptacji. Historyczne kopie źródeł i testu przywrócono do przypiętych bajtów;
88 z 88 hashy archiwum freeze przechodzi. Aktywny kandydat wymaga receiptu
admission z drzewa `/private/var/db/lomi/consumer-private-eleven-root-admission`
oraz plików należących do OS UID 0; sprawdza też hashe dwóch dowodów
wejściowych. Przechodzi 15 czystych testów, w tym odrzucenie plików sfałszowanych
przez zwykłego użytkownika. Niezależny ograniczony review zamyka się dla hashy
aktywnego kontrolera i testu zapisanych w verification.json. Historyczny receipt
ma UID 501, więc nie spełnia nowej bramki. Nie ma nowego freeze ani nowego
admission wystawionego przez OS UID 0. Native admission i pełne kwalifikacje
S5 nie były uruchamiane. Osobny fixture Cloud z PostgreSQL przeszedł, ale nie
zamyka S5. S6/S7 oraz pełne S5 pozostają otwarte.

Test z PostgreSQL/TLS przeszedł w ograniczonym harnessie. To dowodzi tylko
publikacji i odświeżenia membership jednego hosta. Bariera ACK pozostaje po
walidacji odpowiedzi i rechecku ownera. Reguła fail-closed dla niepotwierdzonej
publikacji pozostaje bez zmian; full Cloud/E2 i pełne S5 nadal są otwarte,
S6/S7 nie uruchomiono.

**Cały system nie jest jeszcze ukończony.** Istnieje rozbudowany host Rust, lokalne IPC, trwała domena terminali, mechanizmy uprawnień, komponenty API i relay oraz działające części zdalnego transportu. Trwa domykanie E1 i E2. Pełny produkt z desktopem A/B, WWW, mobile, Explorerem, Git oraz podpisaną instalacją i aktualizacją pozostaje do wykonania i odbioru.

Żadne pełne wymaganie `REQ-01`–`REQ-17` nie ma jeszcze końcowego odbioru. Liczba plików i zdanych testów nie stanowi procentu ukończenia całego produktu. Wyniki komponentów opisane poniżej mają własny zakres i konkretną wersję kodu.

## Nowszy kod po zapisaniu checkpointu

Po utworzeniu kopii checkpointu 708 zintegrowano fundament przenoszenia terminali: wspólny, typowany planer układu oraz atomową operację Store z revision, receipt, zdarzeniem i outbox. Lokalna ścieżka korzysta już ze wspólnego planera. Zdalna metoda `terminal.move` nadal nie jest aktywna. Osobno dodano diagnostykę testową miejsc odmowy w TLS; nie jest to jeszcze poprawka przyczyny błędu.

Bieżący manifest obejmuje **709 plików** i ma SHA256 `c831720920b0c71db34cddf85ee448e8c0d6dfe8b4448c02de8683bd3bd97901`. Kompilacja wszystkich targetów wybranych komponentów oraz Clippy z `-D warnings` przeszły w sesji 10765. Pierwszą nieudaną kompilację 42737 zachowano: rozszerzona krotka diagnostyczna miała pominięte dwa pola w gałęzi błędu połączenia; dopisano dwa `false`, ponieważ połączenie i jego oczekujące odpowiedzi/strumienie jeszcze tam nie istnieją.

Na tych samych źródłach producer 40615 zachował 24 pliki wykonywalne i wybrał dziewięć do weryfikacji. Native38 w sesji 69624 zaliczył 38 przypadków i zachował 114 kopii dowodów. Listing 72849 odczytał 675 nazw: Host 476, Store 30, Auth 4, HTTP 58, TerminalLib 28, PTY 19, AuthLifecycle 45, PeerPolicy 15. Po pięciu historycznych wyłączeniach pełny zestaw wynosi 670 testów; **pełnego zestawu 670 jeszcze nie uruchomiono**. Niezależny zbiorczy przegląd wyników tych zakresów jest zamknięty bez usterek integralności, z zachowaniem nieudanego wyniku pakietu celowanego.

Wspólny, celowany pakiet w sesji 9233 wykonał **39 testów: 38 zaliczonych i jeden niezaliczony**. Przeszło osiem nowych testów Store, dwa nowe lokalne testy move oraz wszystkie 28 regresji rename. Ponownie nie przeszedł wcześniejszy test rzeczywistego TLS/Noise. Store uruchomiono przed Host, więc jego osiem wyników jest zachowanych także w nieudanym przebiegu zbiorczym. Dwa uruchomienia mają sześć zweryfikowanych kopii dowodów, zebranego jednego pracownika PTY i pozytywne zamknięcie/usunięcie własnych zasobów. Pierwotny zegar Root zachowano: górna granica obserwacji 17,631871 s.

Nowa diagnostyka wskazuje odmowę `stream.current-proof / Invalid` przy oczekującym strumieniu, bez oczekującej odpowiedzi, w turze 141. Ostatnie odnotowane żądanie to pierwszy `terminal.attach`; ten licznik sam w sobie nie oznacza błędu wykonania attach. Szczegółowa przyczyna odmowy nie jest jeszcze udowodniona. Audit wszystkich 39 indywidualnych wyników oraz tożsamości 709 plików i pięciu narzędzi zapisano w `production-ownergraph-eight-class-results/fdc48f8388d84867919630969711fcea/root-focused39-outcomes-audit.json`, SHA256 `ded74f8ddfd2b28cb4ee2dd3a045b9a0ed067d0e601a0bd2e7129c365b4abde6`.

W raporcie z sesji 9233 wskazano problem fixture: kolejka 64 syntetycznych odpowiedzi pairing nie wystarczała na snapshot obu buforów terminala 80×24. Pusta kolejka fixture zwracała `Invalid`; była to diagnoza testu, nie potwierdzenie błędu produkcyjnego. Późniejszy, celowany przebieg rozstrzygnął ten przypadek: `cargo test -p lomi-host --lib real_tls_noise_terminal_lifecycle_streams_and_reconnect_keep_one_pty_without_input_replay -- --nocapture` zaliczył 1 test (3,17 s). Bieżąca fixture używa PTY 12×40 i kolejki 8192 odpowiedzi. Nie zmienia to świeżości, uprawnień ani limitów produkcyjnych. Pełnego zestawu Host i rundy Linux nie powtórzono.

Formalny odbiór bieżących zaliczonych zakresów jest w `production-ownergraph-move-foundation-result-review/e3d50c72-c5f8-4ee6-8325-72909745f676/`. Przegląd ma SHA256 `07129effdd0428ed0a9fa2cd86c3708964bbb1599d08cde5ae8a5197085b7f3c`, a osobny odbiór Root `9a9619e0aada40f7c3ecf65df98dff9ebea2b496a934d276a74361ccc072a4ec`. Zweryfikowano 144 publiczne kopie dowodów: Native38, listingi i pakiet celowany. Odbiór obejmuje konkretne zaliczone zakresy, a nie pełny sukces 39 testów, całego Host, 670 testów, etapów produktu lub REQ.

Osobny kandydat uprawnień i receipt dla zdalnego move przeszedł niezależny przegląd źródeł bez istotnych usterek: `terminal-move-owner-kernel/12588f5c-9040-4415-bb92-6b561c7bc3e1/`, manifest `febe7e133fec4514ff8214ea088d03b0afb56551b67304c3a7a693720713bc56`. Zmienia siedem istniejących ścieżek i zawiera 13 nowych, jeszcze nieuruchomionych testów. Pozostaje poza kodem produktu; nie jest skompilowany ani aktywny zdalnie. Integracja wejścia sieciowego i testy rzeczywistego socketu dla move są przygotowywane osobno. Wyników checkpointu 708 poniżej nie przypisuje się automatycznie nowszym źródłom.

Nowe dowody znajdują się w `../lomi-remote/artifacts/terminal-ingress-diagnostic-compiler-correction/761d71cb-9b02-42c3-af0b-ba896adff8d6/`, `production-ownergraph-regression-producer-results/1c4cd7edb9304e51b73891aa3787c31e/`, `production-ownergraph-native38-results/dc9fa1e6392e4182bfd8184e2a0a83fe/` oraz `production-ownergraph-eight-class-results/fe1314d8de9644fabeefcae9e471f0bc/` pod tym samym katalogiem artefaktów.

## Zamrożony checkpoint 708

| Obszar | Stan obecnego kodu |
| --- | --- |
| Główna implementacja | Osobne repozytorium `../lomi-remote` |
| Zamrożony zestaw źródeł | 708 plików produktu i pięć przypiętych narzędzi Rust |
| Identyfikator źródeł | `246f4624d08aff63a468349892e3f62dda440fa5bb7d15659513320a7aec9794` |
| Kompilacja wszystkich targetów wybranych komponentów | Zaliczone |
| Clippy z traktowaniem ostrzeżeń jako błędów | Zaliczone |
| Przygotowanie binariów testowych | 24 zachowane pliki wykonywalne, dziewięć wybranych do weryfikacji |
| Testy własności procesów Native38 | 38 zaliczonych przypadków; ograniczony odbiór wyniku aktualnej wersji zamknięty |
| Odkryte testy komponentów | 665 nazw; pięć jawnych wyłączeń historycznych; 660 zaplanowanych testów |
| Wykonane testy Host | **474 wykonane: 473 zaliczone, jeden niezaliczony** |
| Nowe testy zmiany nazwy terminala | **28 zaliczonych**, w tym rzeczywisty transport TLS/WebSocket/Noise |
| Wcześniejsze siedem problematycznych testów | Wszystkie siedem zaliczone w bieżącym pełnym przebiegu Host |
| Pozostałe siedem klas | **186 zaliczonych testów**, w tym nowy test zegara; ograniczony odbiór zamknięty |
| Cała bieżąca macierz komponentów | **660 wykonanych: 659 zaliczonych i jeden niezaliczony**; pięć historycznych wyłączeń poza tą liczbą |
| Kolejna funkcja | Fundament `terminal.move` przygotowany jako osobny kandydat źródłowy; nie jest aktywny zdalnie |
| Publikacja | Nie wykonano wdrożenia produkcyjnego, push ani publikacji wydania |

Najnowszy pełny przebieg zatrzymał dalsze klasy po niepowodzeniu jednego testu Host. Pozostałe 186 testów wykonał następnie osobny, sprawdzony runner na tych samych źródłach i binariach. Wszystkie przeszły. Nie zmienia to niezaliczonego wyniku Host.

Pełny wykaz bieżących testów i ich indywidualnych wyników znajduje się w zachowanym `root-host-failure-audit.json`, wskazanym w części o dowodach. Kolejne aktualizacje są dopisywane do sekcji aktualizacji na końcu tego pliku.

## Gdzie znajdują się kod i dokumentacja

| Lokalizacja | Zawartość |
| --- | --- |
| [Plan w tym katalogu](README.md) | Specyfikacja produktu i pierwotny plan po audycie |
| [Prompt wykonawczy](prompt.md) | Zadanie obejmujące cały system, etapy i wymagania dowodowe |
| [Repozytorium implementacji](../lomi-remote/README.md) | Host, CLI/TUI, protokół, biblioteki, testy, narzędzia i dokumentacja implementacji |
| [Postęp implementacji](../lomi-remote/docs/implementation/progress.md) | Bieżące kamienie milowe i stan wymagań |
| [Rejestr maszynowy](../lomi-remote/docs/implementation/verification.json) | Szczegółowe wyniki, ścieżki, hashe, historyczne próby i granice kwalifikacji |
| [E1](../lomi-remote/docs/implementation/e1.md) | Lokalny host, terminal, usługi i platformy |
| [E2](../lomi-remote/docs/implementation/e2.md) | Identity, credentials, PostgreSQL, API, pairing, kanały i relay |
| [Przeglądy](../lomi-remote/docs/implementation/review.md) | Niezależne przeglądy, wykryte problemy i zamknięcia zakresów |
| [Decyzje](../lomi-remote/docs/implementation/decisions.md) | Decyzje implementacyjne i ich uzasadnienia |
| [Dowody E0](../lomi-remote/docs/implementation/evidence.md) | Próby wykonalności i historyczne polecenia odtwarzania |
| [Kopia checkpointu](stan-wdrozenia/2026-10-21/README.md) | Zapis dokumentacji, bieżących wyników i indeksu plików w katalogu wskazanym przez użytkownika |

W `lomi-remote` jest nowa gałąź `main` bez commitów; pliki produktu są obecnie nieśledzone przez Git. Nie należy utożsamiać braku commitów z brakiem implementacji. Kod istnieje na dysku i ma przypięte manifesty źródeł oraz wyniki testów.

W `auth-app` istnieją lokalne zmiany backendu, migracje i testy nowego Remote. W `auth-frontend` są lokalne zmiany logowania/zgody urządzenia i integracji przeglądarkowej. `remote-web` i `mobile-app` były czyste przy odczycie stanu Git dla tego checkpointu. W `lomi` widoczne są także liczne zmiany UI, motywów i MCP; sam `git status` nie przypisuje ich temu zadaniu i nie dowodzi migracji desktopu na nowego hosta. Te zmiany są zachowywane. Dokładny stan checkoutów zapisano osobno w kopii checkpointu.

## Zaimplementowany host i lokalne terminale

Powstał host Rust niezależny od Node, Tauri, WebView i renderera GUI. Najważniejsze komponenty obejmują `lomi-host`, `lomi-host-store`, `lomi-platform`, `lomi-terminal`, `lomi-terminal-state`, `lomi-host-auth`, `lomi-host-http`, `lomi-remote-protocol`, `lomi-remote-crypto` oraz narzędzie `lomiremote`.

Zaimplementowano i sprawdzano w odpowiednich komponentach:

- Prywatny profil instalacji, blokadę jednego właściciela i lokalne IPC z weryfikacją uprawnień.
- SQLite z trwałymi projektami, workspace’ami, identyfikatorami, epokami, revision, zgodą udostępnienia i blokadami po cofnięciu zgody.
- Trwały dziennik operacji, receipts, odtwarzanie znanego wyniku i rozróżnianie efektu niepewnego od braku efektu.
- Outbox publikacji, przygotowanie i potwierdzanie dokładnie właściwej wersji publikowanego stanu.
- Lokalne create, split, rename, move, close i restart terminali.
- Shell hosta, PTY, input, resize, Ctrl-C, naturalne zakończenie i zachowane ekrany po zakończeniu procesu.
- Kontrolę wejścia przez lease oraz potwierdzenia częściowego zapisu bez ponownego wysyłania już przyjętych bajtów.
- CLI oraz TUI Ratatui pracujące na strukturze stanu terminala.
- Dwa klienty IPC korzystające z jednego shella; zamknięcie widoku lub TUI nie jest poleceniem zakończenia hosta.
- Jawne stany stopped/lost po utracie właściciela; restart tworzy nową sesję i epokę.
- Obsługę przerwanych migracji SQLite, bezpieczne ponowne użycie zgodnego backupu i utrwalony wybór shella.

Nie oznacza to jeszcze, że istniejący desktop Lomi używa nowego hosta dla wszystkich swoich terminali. Migracja rzeczywistego desktopu jest nadal osobnym etapem E4.

### Model terminala Rust

Odrzucono pierwotny wariant oparty na stockowym `vt100`, ponieważ nie zachowywał wymaganej zgodności snapshotu. Przyjęty eksperymentalny profil Rust i strukturalny adapter xterm mają dowody dla 26 grup, 246 projekcji i 82 granic attach. Rzeczywisty Chromium sprawdzał renderowanie i input.

Natywny Vim na macOS oraz Linuxie osobno przeszedł siedem kamieni milowych, 39 projekcji i 13 granic attach. Późniejszy kompaktowy model historii/projekcji ma osobny dowód 28 grup i 160 zastosowań patchy. Te liczby opisują różne checkpointy i nie są sumą testów obecnego kodu.

Rust interpretuje wyjście PTY i odpowiada na zapytania terminala; klient konsumuje strukturę stanu. Pozostaje szersza kwalifikacja profilu, programów CLI, ograniczeń zasobów, opóźnień i długiego działania.

## Własność domeny i bezpieczeństwo operacji

Duża część dotychczasowej pracy dotyczy jednego wspólnego właściciela stanu oraz poprawnego zatrzymywania operacji przy utracie uprawnień. Są to fundamenty późniejszego podłączenia desktopu, WWW, plików i Git.

Zaimplementowane granice obejmują:

- Rzeczywisty `SharedOwner` obejmujący domenę i Store, z rozróżnieniem writerów lokalnych, współdzielonych i zdalnych.
- Ogłoszenie writera przed próbą uzyskania blokady oraz unieważnianie starszej autoryzacji po konkurencyjnej zmianie.
- Zachowanie oryginalnej tożsamości operacji, deadline i sygnałów anulowania podczas oczekiwania, HTTP, publikacji i wysyłania odpowiedzi.
- Kontrole bieżącej generacji, konfiguracji, ownera, providerów sekretów, runtime, grantu, workspace’u i źródła uprawnień.
- Zwolnienie blokad domeny/Store przed fizycznym IO i sprawdzanie uprawnień również przy granicy wykonania lub zapisu do socketu.
- Brak automatycznego ponowienia efektu, jeżeli jego wynik jest niepewny.
- Zachowanie trwałego receipt mimo późniejszej utraty prawa do ujawnienia odpowiedzi.
- Rozdzielenie niepowodzenia konkretnego peer/channel od cofnięcia całego upoważnienia hosta.

W bieżącej wersji 38 przypadków Native38 sprawdza własność, utratę kontrolera, procesy potomne, awarie i sprzątanie. Samo poprawne zakończenie procesu testowego nie wystarcza: wyniki zawierają również potwierdzenia przejęcia, zachowania uchwytu do dziecka, reap, opróżnienia grupy i usunięcia własnego katalogu roboczego.

## Bieżący transport zdalny i zmiana nazwy terminala

W kodzie produkcyjnym hosta połączono WSS, natywny Noise, aktualne uprawnienia peera, dekodowanie RPC i współdzieloną domenę. Obecna ścieżka obejmuje:

```text
workspace.get
terminal.attach
terminal.snapshot
terminal.ack
terminal.claim
terminal.renew
terminal.release
terminal.input
terminal.resize
terminal.rename
```

Istnieją bounded streams terminala, snapshoty, ACK, wyłączna kontrola oraz ochrona przed powtórnym wykonaniem input. Zdalne create, split, move, close i restart nie są jeszcze ukończoną ścieżką produktu.

### Co sprawdza nowy rename

Zdalny rename korzysta z rzeczywistego Shared writera, aktora konsumenta, oryginalnego operation ID, hasha oryginalnych parametrów i CAS revision. Store zapisuje zmianę nazwy, nową revision, receipt, event oraz outbox w jednej transakcji.

Dokładne ponowienie żądania odczytuje istniejący wynik przed oceną starego CAS i nie zmienia nazwy ani revision drugi raz. Zmiana parametrów przy tym samym operation ID jest konfliktem. Trwały receipt nie staje się nową autoryzacją zdalnego użytkownika.

Nowa odpowiedź po własnym commicie ma wąską, zapieczętowaną ścieżkę przejścia przez własną zmianę publikacji. Używa tego samego enkodera wiadomości i rzeczywistego socketu. Obiekt odpowiedzi jest konsumowany przy szyfrowaniu i wysyłce. Nie ma publicznej funkcji wielokrotnego szyfrowania pożyczonego receipt ani dowolnego obejścia bramki publikacji.

Każde późniejsze ogłoszenie writera, cofnięcie zgody, utrata aktualności, anulowanie lub przekroczenie oryginalnego czasu blokuje wysłanie. Przy znanym commicie i późniejszej utracie możliwości odpowiedzi zachowany jest wynik trwały, a ścieżka zdalna zachowawczo się zamyka.

W bieżącym przebiegu **28 nowych testów rename przeszło**, w tym przypadki ownera/domeny, CAS, konfliktów parametrów, trwałych receipts, publikacji, późniejszego writera, anulowania, deadline, pojedynczego fragmentu odpowiedzi i rzeczywistego TLS/Noise z reconnect/duplicate. Fixture stosuje syntetyczną odpowiedź zatwierdzenia publikacji przez rzeczywiste API Store; nie jest to dowód pełnej publikacji przez produkcyjny Cloud HTTP.

### Pozostały błąd transportu terminala

Nie przechodzi test:

```text
real_tls_noise_terminal_lifecycle_streams_and_reconnect_keep_one_pty_without_input_replay
```

Najnowsza diagnostyka pokazuje zestawione Noise, jedno zdekodowane żądanie `terminal.attach` i zakończenie ścieżki wynikiem `Invalid`. Zachowany snapshot nie zawiera jeszcze dokładnego źródła tej odmowy. Nie rozróżnia też błędu wykonania żądania od późniejszego błędu wysyłania odpowiedzi lub strumienia. Po stronie klienta widoczny jest EOF, a test kończy się komunikatem, że ingress nie osiągnął oczekiwanego stanu.

Przyczyna jest badana w kodzie i fixture. Nie ma podstaw, aby uznać ją już za błąd konkretnej kontroli uprawnień, transportu albo wyłącznie testu. Cztery pozostałe testy terminala, w tym rzeczywisty PTY z backpressure i dokładnymi częściowymi receipts bez duplikowania input, przechodzą.

## Najnowsze poprawki

| Problem | Zmiana i jej zakres |
| --- | --- |
| Odrzucanie poprawnego artefaktu HTTP testów | Polityka przyjmuje dokładnie przypięty wariant `test-fixtures` dla właściwego targetu; pozostałe kontrole pozostają ścisłe |
| Za długa ścieżka IPC fixture | Skrócono nazwę przypadku testowego; ścieżka socketu spadła ze 104 do 79 bajtów przy limicie produktu 100 bajtów |
| Wygasanie heartbeat podczas kosztownego przygotowania fairness | Najpierw powstają dane, potem wykonywany jest świeży Cloud GET/HB przez właściwy worker, a następnie nowe obserwacje; oryginalna operacja nie jest wymieniana |
| Utrata części sekundy w zegarze policy | Inicjalizacja zachowuje oryginalną parę `Runtime.base` i `Runtime.anchor`; dodano deterministyczny test granicy sekundy, rollback i pierwotnego wygaśnięcia heartbeat |
| Błędy po zwolnieniu writera rename | Każdy późny błąd zamyka zdalną ścieżkę bez utraty trwałego receipt |
| Możliwość ponownego szyfrowania pożyczonego receipt | Szyfrowanie konsumuje odpowiedź i zwraca wyłącznie nieprzezroczysty obiekt pojedynczej wysyłki |
| Błędy kompilacji integracji | Poprawiono ścieżkę `rpc::DisplayText`, pola licznika fixture, bezpieczną obsługę błędu testowego i zbędny import |
| Osiem uwag Clippy | Zmniejszono duże warianty enum przez Box, uproszczono równoważne warunki, usunięto nieużywany getter i zachowano klasyfikację błędów; bez wyłączania lintów |

Po tych zmianach aktualny kod przechodzi all-target check i Clippy. Powodzenie wcześniejszych siedmiu testów w nowym przebiegu nie jest samodzielnym dowodem przyczyny każdego historycznego niepowodzenia.

## Historia ostatnich zestawów źródeł

Nazwy Source697/700/703/708 oznaczają liczbę przypiętych wejść produktu, a nie wersję protokołu ani procent wykonania planu.

| Zestaw | Ustalony wynik i granica |
| --- | --- |
| Source697 | 615 testów wykonanych w dwóch przebiegach: 612 zaliczone, trzy niezaliczone; pięć jawnych wyłączeń osobno |
| Source700 | Check/Clippy, przygotowanie binariów, Native38 i listingi mają zamknięty odbiór tego zakresu; Host 434/7, pozostałe 185 testów niewykonane; trzy rzeczywiste TLS/Noise workspace scenariusze zaliczone |
| Source703 | Zamknięty odbiór check/Clippy, przygotowania binariów, Native38 i listingów; diagnostyka siedmiu testów 4/3; dwa przebiegi pięciu testów terminala po 4/1; pełna macierz 631 nie została wykonana |
| Source708 obecny | Check/Clippy, przygotowanie binariów, Native38 i listingi przeszły; Host 473/1; pozostałe 186 zaliczone osobno; razem 659/1 z 660 wykonanych; przegląd zakresów zaliczonych zamknięty; pełna macierz pozostaje niezaliczona |

Nieudane próby, ich logi, pierwotne zegary i wyniki pozostają zachowane. Późniejszy sukces kwalifikuje późniejsze źródła; nie zmienia starego wyniku na sukces.

## Control plane i baza PostgreSQL

W lokalnym `auth-app` rozwinięto osobne upoważnienie hosta, consumer/window principals, identity i proof of possession, exchange/recovery/rotation credentials, runtime/heartbeat/publication, inventory, pairing, odczyt bieżących uprawnień, cofanie grantów, admission kanałów oraz tickets/relay.

Zmiany są domyślnie wyłączone i nie zostały wdrożone na produkcję. Migracje i testy używają ograniczonych ról oraz rzeczywistego PostgreSQL. Wczesne dowody miały PostgreSQL 17.8; późniejsze etapy używały 18.6. Jeden wynik nie kwalifikuje automatycznie drugiej wersji.

Poniższe liczby dotyczą kolejnych checkpointów schematu. Są częściowo kumulatywne i **nie należy ich sumować**.

| Zakres | Dowód bazodanowy | Regresje danego checkpointu |
| --- | --- | --- |
| Finalized host identity 003 | 3 testy, 789 asercji | 73 testy, 552 asercje, jeden skip |
| Consumer/window authority 004 | 5 testów, 991 asercji | 76 testów, 592 asercje, jeden skip |
| Host revoke | 6 testów, 1160 asercji | Osobny zakres revoke |
| Runtime 005 | 7 testów, 1304 asercje | 176 testów, 1147 asercji |
| Inventory 006 | 9 testów, 1437 asercji | 305 testów, 2245 asercji |
| Pairing proposals 007 | 11 testów, 1593 asercje | 404 testy, 2984 asercje |
| Pairing decisions 008 | 13 testów, 1983 asercje | 547 testów, 4019 asercji |
| Peer reads i grant revoke 009 | 15 testów, 2373 asercje | 692 testy, 5311 asercji |
| Channel admission 010 | 18 testów, 2792 asercje | 912 testów, 7210 asercji |
| Tickets i relay 011 | 20 testów, 3963 asercje | 1189 testów, 9146 asercji |

Sprawdzano między innymi obce konta, pomylenie klasy host/consumer, powiązania FK do sesji, niezmienność pierwszego klucza, współbieżną rotację, recovery po utracie odpowiedzi, reuse/replay, global revoke, zakres ról SQL, przepełnienia i kanoniczne błędy HTTP. Kolejne schematy mają własne zestawy 91/100/121/147/173/183 kształtów błędów.

Pozostaje pełne połączenie tych komponentów z instalacją hosta, prawdziwym użytkownikiem, nowym WWW i produkcyjnym cyklem publikacji/revoke. Lokalne testy backendu nie są odbiorem działającego produktu od logowania kodem do shella w przeglądarce.

## Kontrakty kryptografia relay i przeglądarka

- Kanoniczne kontrakty obejmują 39 metod RPC, 24 trasy HTTP, niezależne IPC 1.0, ścisłe identyfikatory, capabilities, błędy, receipts i strumienie.
- Zachowano oddzielne wersje API/application major 2 oraz grant/context v3; te numery nie są zamienne.
- Wydzielono kanoniczne crypto, przypięte źródła Snow i licencje oraz provenance patchowanych komponentów terminala.
- Istnieją generowane schemas/typy/fixtures oraz pakiety kontraktów, authority crypto WASM i protocol codec WASM.
- Historyczny identity/admission zakres ma 20 poleceń, 210 publicznych źródeł, po 38 testów Node/Bun oraz 543 przypadki SDK. RuntimeGet ma osobny dowód 29 native, 309 codec Node/Bun i 603 SDK.
- Rzeczywista kryptografia Chromium/WASM/native ma dowody handshake, odrzuceń i prawidłowego disposal. Nie jest to jeszcze kwalifikacja mobile.
- Natywny Noise przez loopback relay i rzeczywisty ograniczony PostgreSQL przeszedł osobny zakres 617 asercji, w tym revoke, późny finish i ruch po wygaśnięciu początkowego contextu.
- Zamrożony test obciążeniowy zestawił 264 kanały; dwa scenariusze obejmowały rzeczywisty revoke i stall globalnej blokady. Jego odbiór dotyczy przypiętego źródła, a nie wszystkich późniejszych zmian produktu.
- Osobna integracja przeglądarki z auth frontend/backend ma zaliczone trzy ograniczone scenariusze. Testowe bazy zostały usunięte, a potomkowie zebrani. Pełny referencyjny WWW E3 pozostaje otwarty.

Nie zakończono jeszcze konsolidacji wszystkich kopii WWW i shared client w aktywnych aplikacjach ani macierzy artefaktów wydania. Jest to istotna część REQ-17 i E6/E7.

## Consumer successor oraz bramki S5 S6 S7

Osobna ścieżka consumer/reference ma zaakceptowane ograniczone dowody, w szczególności:

| Zakres | Zapisany wynik |
| --- | --- |
| S0–S4 reference construction | Ograniczony odbiór konstrukcji referencyjnej |
| Sealing | 82 kontrole, w tym 76 dokładnych odmów SQL z niezmienionymi katalogami |
| Owner faults | 202 kontrole obejmujące wcześniejsze 82 i 120 dodatkowych odmów |
| Operator mixed/drift | 16 osobnych przypadków |
| Pristine pre012 | 10 przypadków missing/rename z dokładnym błędem i porównaniami rollback tej samej bazy |
| Private catalog | 11 przypadków z porównaniami 27 katalogów i metadanych |
| CTAS | Cztery dokładne odmowy i porównania rollback |
| External admission | Pięć przypadków admission |
| Gate33 | 25 evaluator oraz osiem HostAuth/consumer Noise; syntetyczne fakty Store/current owner |

Pełne S5 pozostaje niezaliczone. Otwarte są dalsze przypadki fault/security/config/owner/lifecycle/business/authorized-call. S6 i S7 nie mają pełnego wykonania. Zaliczenie S0–S4 lub jednego podzbioru nie zamyka całej tej ścieżki.

## Wykonane próby platformowe

### Linux

Próby wykonywano między innymi w osobnej VM Lima z Ubuntu ARM64 bez GUI i Node. E0 dla systemd user/linger i konta nologin obejmuje SSH detach, rzeczywisty reboot i lost descriptors; świeży przeglądany wariant ma 40 kontroli cyklu życia po siedmiu native i dziewięciu driver testach.

Późniejszy produktowy checkpoint Linux ma 147 testów z dwoma celowo pomijanymi entrypointami subprocess i dwa niezależne etapy SSH continuity. Produktowa usługa systemd user ma osobny wynik 32 kontroli: ciągłość PTY, graceful restart, crash/Lost, manual owner, stop i interrupted uninstall recovery.

**Nowa kwalifikacja źródeł z 2026-10-22:** na świeżo zamrożonym checkoutcie
uruchomiono `tools/run_linux_product_host.py --run --with-service` w Ubuntu
24.04 ARM64 (VM `lomi-e0`). `lomi-host` przeszedł 533 testy; wszystkie
wybrane pakiety Rust przeszły łącznie 796 testów bez błędów (dwa oznaczone
testy pominięte). Testy obejmują również TLS/Noise revoke, watch, wielu klientów
i efekty terminala/plików. Usługa systemd-user przeszła fazy prepare/verify
(9 + 23 kontrole), a cleanup potwierdził usunięcie usługi i brak procesów
fixture. Raport: `../lomi-remote/artifacts/product-linux/c75ceaff-22c2-46c3-b0de-d1c196060276/report.json`; manifest źródeł:
`95e91e71bfe690f55062bd5ed6b69a8ac4e90f729cbb7a0e2edf1672223e9aa7`.
Runner poprawiono tak, aby używał istniejącego `tools/test-host.sh` z
wymaganym `umask`, katalogiem tymczasowym i jednym wątkiem na Linuxie. Nie
kwalifikuje to rebootu, czystego instalatora, Cloud/relay ani pełnej macierzy
dystrybucji i architektur.

Dowód reboot z E0 nie przechodzi automatycznie na późniejsze źródła produktu. Pozostaje macierz dystrybucji, ABI, architektur, trybów usług i instalacji na czystych maszynach.

### macOS

E0 LaunchAgent i prywatny testowy Keychain mają 20 kontroli, bez zmiany domyślnego Keychain/search list i z własnym cleanup. Produktowy LaunchAgent ma osobny zakres 37 kontroli i 87 operacji. Produktowy Keychain ma dowody zaszyfrowanej koperty związanej z profilem, odrzucenia złego klucza i obcego profilu oraz nieinteraktywnego pomocnika uruchamianego z tego samego binarium.

Pozostają pełne logowanie/logout/reboot, LaunchDaemon przed logowaniem, locked storage/FileVault i kwalifikacja wszystkich potomków hosta. Domyślny mechanizm containment ma zachowany kontrprzykład. Osobny backend coalition jest domyślnie wyłączony i ma ograniczony dowód pięciu native przypadków oraz 19 testów. To nie jest jeszcze pełne rozwiązanie całego hosta.

### Windows

Udostępniona maszyna to Windows 10 Enterprise LTSC x64, dostęp SSH `woro-server@192.168.1.129`. Przygotowano też zwykłe konto `test-user`. Bieżący raport nie potwierdza, że komputer jest teraz włączony. Nie było w tym ostatnim przebiegu nowego zadania na Windowsie.

Dotychczasowe dowody obejmują:

- SCM/LocalService, Session 0, ConPTY i DPAPI: cztery kontrole polityki oraz 16 native przypadków E0.
- Osobny rzeczywisty test trzech faz SSH disconnect z potwierdzonym cleanup.
- Produktowe named-pipe IPC i ACL, obserwatorów, kontrolę wejścia, receipts bez duplikatów, resize/Ctrl-C, owner loss i zachowanie niezwiązanych procesów.
- Rzeczywisty produkt host/PTY/CLI/Store oraz natywny MSVC Clippy/format dla jego zamrożonego wejścia.
- SCM stop-expiry z wynikiem błędu, zakończeniem własnego drzewa PTY i stanem Lost bez replay.
- Osobny service manager: 28 kontroli i pięć native testów.
- DPAPI/platform: 29 testów; backup/migracja: 27 Store i cztery backup testy.
- Zwykły token użytkownika: świeże stopped/running restarty z trzema generacjami runtime, dwoma klientami IPC i dokładnie jednym hostem/zadaniem; stop/uninstall oraz 26 task/policy/SCM testów.
- Oddzielny poprawny cleanup zwykłego konta po wcześniejszym niezaliczonym outer cleanup.
- Przygotowanie rzeczywistego logon trigger w stanie stopped, bez uruchomionego zarządzanego hosta. Obserwacja prawdziwego logowania i samoczynnego okna konsoli była odłożona.

Windows będzie jeszcze potrzebny do pozostałych testów natywnych, autostartu i wydania. Windows 10 LTSC nie kwalifikuje deklarowanych targetów Windows 11, ARM64 ani Server/Core. Pełne boot/logoff, dodatkowe tryby i podpisane wydanie pozostają otwarte.

## Git izolacja i aktualizacje

Wykonano próby izolowanego Git read. Starsze macOS/Linux warianty mają zachowane kontrprzykłady. Nowy Linux sealed-snapshot/namespace wariant ma 18 grup i 15 operacji oraz zamknięte cztery findings. Portable gix/WASI porównywał pięć operacji z natywnym Git; macOS ma 16 grup security/broker, Windows Wasmtime 11 i Linux 12.

To nadal nie jest pełny produktowy GitService. Potrzebne są broker snapshotu, wspólna blokada repo, preconditions HEAD/index, mutacje stage/unstage/commit, credentials i bezpieczne fetch/ff-only pull/push z niepewnym wynikiem bez replay.

Wrapper trwałej weryfikacji TUF przeszedł 10 testów, między innymi crash, root rotation i odrzucenie FIFO. Instalator, podpisy/notary/Authenticode, aktywacja aktualizacji, rollback, locked EXE, odinstalowanie i release pipeline nie są jeszcze zakończone.

## Stan etapów całego planu

| Etap | Stan | Co blokuje pełny odbiór |
| --- | --- | --- |
| E0 wykonalność | Liczne ograniczone dowody; pełny odbiór nadal otwarty | Pozostałe platformy, containment i kanoniczne artefakty/qualification |
| E1 host lokalny | W realizacji, duża część kodu i testów istnieje | Pełne usługi/provider/boot/containment i aktualna macierz platform |
| E2 identity API relay | Ograniczony CloudWorker przez actual Remote handler i PostgreSQL: claim także bez istniejącego `host_runtime`, heartbeat, publication/permission refresh, central revoke, dwa lokalne klienty zamykane po HTTP 401 i blokadzie wspólnego ownera; rzeczywisty TLS/TCP lost ACK połączony z restartem ownera, końcowym uzgodnieniem kursora 8 → nowa generacja 1 i bez ponownego PUT | Wdrożony relay w tym samym przepływie, reconnect po fail-closed close, cross-host fanout, consumer S5/S6/S7 oraz pełne integracje |
| E3 Linux i referencyjny WWW | Pełny produktowy etap nieodebrany | Czysta maszyna → code login → share → rzeczywisty shell w nowym WWW, SSH detach i revoke |
| E4 desktop A i B | Migracja produktu nieukończona | Jeden owner dla rzeczywistego desktopu, import, mixed views, dwa okna bez nowego PTY |
| E5 Explorer Git | Pełne usługi nieukończone | FileService, produkcyjny GitService, guards, streams, status/cancel i niepewne efekty |
| E6 spójność klientów | Nieukończona | Desktop/WWW/mobile dla wszystkich metod, klawiatura/IME, lifecycle i jedno źródło artefaktów |
| E7 wydanie | Nieukończone | Podpisane instalacje/aktualizacje, wszystkie OS/arch, security review, soak i cutover rehearsal |

## Stan wszystkich wymagań

| Wymaganie | Co już istnieje | Co nadal trzeba zakończyć |
| --- | --- | --- |
| REQ-01 Rust i headless | Host Rust, lokalne PTY/IPC/CLI/TUI, próby bez GUI | Czysta instalacja, pełne tryby boot i wszystkie deklarowane platformy |
| REQ-02 jeden owner | SharedOwner, Store, lokalne dwa klienty/jeden shell; rzeczywisty TLS/Noise test potwierdza zamknięcie odczytu B, zwykły RevisionConflict i rzeczywisty CloudWorker ACK dopiero po zamknięciu B na tym samym owner/store | Migracja rzeczywistych terminali desktopu i wspólny owner; reconnect klienta po fail-closed oraz pełna integracja klienta |
| REQ-03 niezależne auth hosta | Enrollment, credentials/rotation/recovery/revoke, ograniczone DB/HTTP dowody | Pełne logowanie kodem i bezobsługowy cykl produktu na docelowych OS |
| REQ-04 wspólna zgoda sharing | Lokalne share/unshare, consent epochs, fences/outbox | Ten sam przepływ i polityka w rzeczywistym desktopie/TUI/Cloud |
| REQ-05 terminal i reconnect | Model Rust, snapshoty, leases, backpressure i komponenty transportu; celowany test TLS/Noise reconnect przechodzi na bieżącej fixture | Pełna macierz Host na bieżących źródłach, Linux i pełne E3 oraz klienci |
| REQ-06 zarządzanie terminalami | Lokalne lifecycle; zdalny rename, move oraz create/split/close/restart przez prawdziwy TLS/Noise z realnymi PTY; konflikty rename/move wracają jako zwykła odpowiedź błędu (połączenie zostaje otwarte); odzysk odroczonego zakończenia po błędzie Store dla wszystkich metod lifecycle; prawdziwy błąd exec (create/split: trwały Failed/None dostarczony jako zwykły błąd `HOST_BUSY` z operation id; restart po stopie: OutcomeUnknown, połączenie zamykane, receipt przez duplicate lookup); dwóch klientów jednocześnie: wspólny PTY (komenda wykonana raz), wspólny widok workspace, konflikt rewizji jako zwykły błąd, dodatkowo B dostaje Closed przed ACK dla drugiej mutacji A (macOS: 1199 testów workspace zaliczonych przed poprawką zegara; po poprawce te same 4 testy 20/20; Windows: `lomi-host` 508/508 na koncie standardowym i na koncie administratora; Linux ARM64: `lomi-host` 533/533 oraz wybrane pakiety 796/796); wspólny test z actual CloudWorker/handlerem także potwierdza ACK dopiero po zamknięciu B; Remote Web ma opt-in terminal v2 | Reconnect klienta po fail-closed; błąd exec restartu po stopie nadal bez odpowiedzi (wynik nieznany, receipt przez duplicate lookup); v1 pozostaje domyślne, brak odbioru z wdrożonym relay i prawdziwym hostem |
| REQ-07 prywatne widoki | Zaliczone próby mixed views/dirty editor | Wdrożenie ochrony w migrowanym rzeczywistym desktopie |
| REQ-08 Explorer | Silnik `lomi-files` na macOS, Linux i Windows (Windows oparty na zweryfikowanych uchwytach katalogów); zdalne list/stat/read/search/create/mkdir/rename/remove i `files.watch` przez prawdziwy TLS/Noise; `remote-web` ma opt-in Explorer v2 (listy, podgląd i mutacje na fixture) | Desktop/mobile Explorer; brak testu Explorer v2 z prawdziwym hostem; `files.watch` używa natywnych watcherów, ale subskrypcja obejmuje jeden wybrany katalog i pełne odbiory wszystkich targetów nadal pozostają otwarte; na Windows host laboratoryjny przeszedł testy `lomi-files` 29/29 na Windows 10, który nie kwalifikuje macierzy wydania; Arch nie kwalifikuje Ubuntu/Debian; brak dowodu pełnej polityki konfliktów i revoke przez wszystkie klienty |
| REQ-09 Source Control | Próby Linux/WASI izolacji Git read | Produkcyjny broker i kompletne operacje Git/credentials/uncertain outcomes |
| REQ-10 parity klientów | Kanoniczne DTO i część SDK/codec | Macierz każda metoda × desktop/WWW/mobile |
| REQ-11 nowe okna | Oddzielne klucze okien, dowody auth dwóch okien | Pełne okna rzeczywistego workspace’u bez nowego shella |
| REQ-12 lifecycle | Lokalne procesy, retained screens, SSH/service próby | Full-host containment, OS logout/boot/crash i wszystkie service adapters |
| REQ-13 revoke i brak replay | Dzienniki, receipts, fences, część rzeczywistych Noise/PTY testów; unshare i logout w trakcie efektu terminala oraz pliku (efekt odgrodzony, nic nie dostarczone odwołanemu klientowi, receipt rozliczony do odzysku) na macOS i Linux ARM64; unshare i logout przed `terminal.input` i w trakcie snapshotu (nic nie trafia do PTY, snapshot się nie kończy) na macOS; na Windows cały `lomi-host` (508 testów, w tym te odwołania) zaliczony na koncie standardowym i administratora; Git: brak usługi, wywołania Git odrzucane fail-closed | Git (brak GitService, E5); pełny cykl Cloud i odbiór wszystkich OS/klientów |
| REQ-14 E2EE i prywatność | Canonical crypto, podpisane granty/context, native/WASM/Chromium | Pełny product data plane, mobile i inspekcja storage/logów wszystkich klientów |
| REQ-15 instalacja i update | TUF fault tests, część service managerów | Instalatory, podpisy, aktywacja/recovery/rollback/uninstall i matrix OS |
| REQ-16 bezpieczna migracja | Próby backupu i oddzielenie nowej implementacji | Produktowy import/recovery, ochrona projektów/prywatnych danych i cutover |
| REQ-17 canonical artifacts | Generatory kontraktów, crypto/provenance, pinned vendors | Jedno aktywne WWW/shared client i końcowy manifest wszystkich wydań |

Wszystkie powyższe wymagania pozostają formalnie otwarte. Częściowe wykonanie jest zapisane osobno, aby nie zniknęło w ogólnym statusie.

## Następna przygotowana zmiana terminal move

Kandydat `terminal-move-store-foundation/b9478c41-d2f7-4be8-a1ff-33825de2974a` zawiera trzy ścieżki: Store, nowy moduł czystej transformacji układu oraz delegację lokalnego `rpc::plan` do tej samej implementacji. Dwa istniejące preimage są przypięte; nowa ścieżka ma wymóg nieistnienia. Docelowy zestaw miałby 709 źródeł.

Przygotowano typed `TerminalMoveLayout`, czysty planner zachowujący context/revision i tożsamości pane/session oraz atomowe `HostStore::move_pane` z receipt-before-CAS i pojedynczą transakcją. Jest 10 nowych testów źródłowych: cztery układu, cztery Store, dwa lokalnego planera. Pozostają nieuruchomione. Niezależny przegląd źródeł zamknął ten ograniczony fundament bez materialnych findings; kompilacja i wykonanie testów pozostają do zrobienia. Nie dodano jeszcze zdalnej aktywacji ani żadnego stop/spawn PTY.

Zdalny move ma następnie korzystać z zamkniętej ścieżki uprawnionego writera i receipts analogicznej do rename, bez wywoływania lokalnego dispatch jako obejścia praw konsumenta. Create/split wymagają osobnego zabezpieczenia spawn; close zabezpieczenia stop; restart obu granic i rozliczenia częściowego efektu.

## Otwarte problemy techniczne i środowiskowe

| Problem | Stan i dalsze działanie |
| --- | --- |
| Rzeczywisty TLS terminal attach | Jedyny niezaliczony test Host aktualnego kodu; zbadać miejsce bezpośredniego `Invalid` po pierwszym żądaniu |
| Pozostałe 186 testów | Wszystkie zaliczone; przegląd całego checkpointu zamknięty dla zakresów zaliczonych |
| Pełne S5 S6 S7 | Ograniczone dowody nie zamykają całości consumer/security/lifecycle/business |
| macOS potomkowie i boot | Zachowany kontrprzykład domyślnego containment; coalition nie jest domyślnym gotowym rozwiązaniem; LaunchDaemon/FileVault/pełny boot otwarte |
| Windows prawdziwe logowanie | Przygotowanie istnieje; rzeczywista obserwacja logon/console i część boot/logoff pozostają nieodebrane |
| Historyczne niepewne ownership | Pozostają odrębne holdy opisane poniżej; nie należy zaliczać ich cleanup jako wykonanego |
| Repozytorium bez commitów | Kod zapisany lokalnie; nie było jeszcze commita/push/PR ani publikacji |
| Brak końcowej macierzy platform i klientów | Cross-compile i fixture nie zastępują natywnego odbioru docelowego produktu |

### Historyczne holdy i nieudane uruchomienia

- `85419`: zachowany otwarty stan zewnętrznego właściciela zapisu. Dawny controller został zebrany, a brak wewnętrznych dzieci ustalony w ograniczonym zakresie; zewnętrzny stan pozostaje niepewny. Nie ma podstaw do zadeklarowania jego fizycznego cleanup. Zachować namespace `/private/tmp/lo-ownergraph-native38-e98b14f622e9433eb6ddde323e450bf1`.
- `15670`: zachowany hold przed uruchomieniem dziecka; brak natywnego dziecka/cache lock w ustalonym zakresie. Namespace pozostaje zachowany.
- `15803`: historyczne 38 przypadków wykonano, ale publikacja wyniku nie powiodła się przez błąd oczekiwanego stanu Atomic. Oddzielny recovery nie zamienia tego przebiegu w zaliczony.
- Windows: nie adoptować ani usuwać starego namespace `C:\Users\woro-server\lomi-windows-login-4cae63f9-053c-4aaf-8513-012e4d4f50d3`. Dawna inwentaryzacja przez `Add-Type` nie dowiodła braku dziecka kompilatora. Potrzebny jest właściwy dowód nowego bootu po zaufanym cutoff, bez zgadywania po historycznych PID.

Numery sesji narzędzi nie są PID systemu. Historycznych PID nie należy sondować ani sygnalizować w celu odgadnięcia własności. Każda próba zachowuje swój oryginalny zegar; nowy przebieg nie przedłuża deadline starego.

## Kolejność dalszej pracy

1. ~~Przyczyna odmowy TLS terminal attach~~: test `real_tls_noise_terminal_lifecycle_streams_and_reconnect_keep_one_pty_without_input_replay` przechodzi na obecnym kodzie (pełny `lomi-host`: 500 testów zielonych).
2. Zdalne create/split/close/restart są wdrożone (patrz `lomi-remote/docs/implementation/progress.md`); błędy przed efektem (STALE_EPOCH, REVISION_CONFLICT itd.) wracają jako zwykła odpowiedź błędu dla create/split/close/restart. Dalej: to samo dla rename/move oraz testy rewokacji podczas efektu.
3. Domknąć blokujące zakresy E1/E2 i consumer S5/S6/S7, pełne fakty Cloud/publication/revoke oraz natywne pozostałości usług i sekretów.
4. Przeprowadzić E3 na czystym Linux: testowy instalator, code login, świadoma zgoda share, rzeczywisty shell w referencyjnym WWW, zachowanie po zamknięciu SSH i brak replay.
5. Przenieść rzeczywisty desktop A/B na wspólnego hosta, zachowując private views, dirty editor, lokalne zadania i nowe okna bez nowego PTY.
6. Zaimplementować pełny FileService i produkcyjny GitService z izolacją read, preconditions, blokadami repo i trwałymi wynikami mutacji.
7. Domknąć desktop/WWW/mobile dla każdej metody, wspólny klient/crypto/WWW i macierz canonical artifacts.
8. Zrealizować E7: wszystkie deklarowane OS/arch/service modes, instalacja/update/uninstall, podpisy, security review, soak 24/72 h i próbny cutover/restore.
9. Publikacja produkcyjna dopiero jako osobny, konkretny i autoryzowany krok po spełnieniu wymaganych bramek.

Nie pominięto Explorer/Git, mobile ani desktopu B w celu szybszego ogłoszenia końca. To nadal wymagane części pierwszego kompletnego produktu.

## Organizacja pracy i ograniczenia

Zgodnie z prośbą użytkownika prace są łączone w większe pakiety. Ciężkie kompilacje/testy Cargo, Node, PostgreSQL i native są wykonywane kolejno; niezależne czytanie kodu, przeglądy i kandydaci źródłowi mogą powstawać równolegle. Niezmienione mechanizmy ownership, cleanup, Atomic i polityki artefaktów są używane przez przypięte referencje, bez ponownego przepisywania frameworków dla każdego uruchomienia.

Po zakończeniu streamu użytkownik ponownie zezwolił na obciążające prace na MacBooku. Wcześniejsze epizody braku miejsca zatrzymywały kompilacje; ostatni odczyt w tym przebiegu wykazał około 44 GiB wolnego miejsca. Ta liczba jest pomiarem z konkretnego momentu, nie stałą gwarancją zapasu.

Role i zasady delegacji są w `../AGENTS.md` i `../.codex/agents/*.toml`. Nie odnotowano w tej części pracy awarii dostępności modelu wymagającej przełączenia. Konwencje commitów/PR są zapisane, ale w ramach prac nie wykonano commita ani publikacji.

## Bieżące dowody i wznowienie pracy

Wszystkie poniższe ścieżki są względne do `../lomi-remote/artifacts/`.

| Dowód | Ścieżka |
| --- | --- |
| Aktualne źródła 708 i check/Clippy | `production-remote-rename-lint-and-clock-batch/8cdf712b-1d0e-46b1-8a1b-a9973c18e63e/live-application/` |
| Bezpośrednia integracja rename i fixture | `production-remote-rename-and-fixture-batch/98d7ea13-8502-4716-9e0d-4ee9793a13f2/` |
| Oryginalny przejrzany pakiet integracji | `production-remote-rename-integration/cc93d843-900c-445e-841f-325e910fa445/` |
| Diagnostyka ingress | `remote-ingress-origin-diagnostics/afb0700b-a2d6-40d1-8e4f-bc8f64ea44c4/` |
| Poprawka fairness i diagnostyka pairing | `channel-fairness-refresh-and-pairing-diagnostics/93ad2754-aff9-4ef6-92cf-bd9e37b898c3/` |
| Poprawka zegara i deterministyczny test | `peer-policy-runtime-clock-alignment-conditional/366d18f9-788a-40d1-b392-dcf04f4ae679/` |
| Nowy generator runnerów 708 | `production-ownergraph-708-runner-template-source/42eeea86-7b90-4c2e-a6ba-b4d8e21c4250/` |
| Konkretny zestaw runnerów obecnego kodu | `production-ownergraph-708-runner-cohort-source/a19f6b75-b383-4421-9859-062545d8de72/` |
| Binarne artefakty testów | `production-ownergraph-regression-producer-results/40e7602c52f04d4180d13505117b1dc4/` |
| Native38 | `production-ownergraph-native38-results/c4e624dc81f2485a973fcacfc5ec7018/` |
| Listingi 665 nazw | `production-ownergraph-eight-class-results/43c97e8498b54e4e98da6506d32ff5e9/` |
| Nieudany Host 473/1 i audit 474 wyników | `production-ownergraph-eight-class-results/c01900099387450f92fcb1b0769cdebe/` |
| Pozostałe 186 testów | `production-ownergraph-eight-class-results/eb7a5c8b6a7540c383dfdc1f68adfca9/` |
| Przejrzany runner siedmiu klas | `production-ownergraph-708-remaining-seven-source/dec72a51-be64-4022-85d0-6063fb5122cf/` |
| Zamknięty przegląd wyników Source703 | `production-ownergraph-terminal-result-review/0b18b23c-9fda-4b12-9520-6c638481d32e/` |
| Kandydat fundamentu move | `terminal-move-store-foundation/b9478c41-d2f7-4be8-a1ff-33825de2974a/` |

Najważniejsze hashe bieżących źródeł i wejść:

```text
Source708 manifest
246f4624d08aff63a468349892e3f62dda440fa5bb7d15659513320a7aec9794

Runner cohort a19 manifest
7bc00618e54133e43359258511fad693eb4b3724f8db012489c685612e314d52

Listing result 43c97
ea0bcf6055842ddab3d54b3bf0aeeea7847ccb6d49be54b9f75c8568498e23be

Root listing execution record
d8786ec9898f23d8874d6cafead4e762217bbc504408197a61e65170a3f50524

Host failure audit
124644d5235a285064f2dd8ed8122dd726bec504f0fde44cf259efafcaf24c0f

Move foundation manifest
7360ee583044b51fd5f9fb369a55686c78599addd2198482d0a9fac9965c159e
```

### Odtwarzanie i narzędzia

Aktualne sprawdzenia używają Rust 1.98.1 i przypiętego Pythona 3.14 w trybie `-I -S -B`. Dla przeglądarki/SDK używano przypiętego Node 22.22.3; domyślny Node 20 nie zastępuje tego wejścia. Historyczne backendowe dowody zawierają własne wersje Bun/PostgreSQL.

Dokładne argumenty kompilacji i testów, środowisko oraz hashe logów są w `result.json` poszczególnych zakresów. Instrukcje uruchomienia są w `HANDOFF.md` lub `HANDOFF.txt` runnera. Przy wznowieniu należy użyć nowego namespace/admission i świeżego czasu początku, zachowując stare zegary istniejących prób. Nie należy uruchamiać ponownie istniejącego skryptu z tym samym OUT ani nadpisywać zachowanego wyniku.

Do bieżącej weryfikacji nie uruchamia się w ciemno historycznego `tools/check.py`: starszy aggregate ma inny zakres i przypięte środowisko. Najpierw sprawdza się aktualny manifest, zakończenie ostatniego właściciela i odpowiedni runner obecnego kodu.

Pełne starsze wyniki, decyzje, ograniczenia i ścieżki są zachowane w kopii dziewięciu dokumentów implementacji oraz w maszynowym `verification.json`. Starsze liście tego rejestru mogą przedstawiać status z wcześniejszego checkpointu; późniejsze jawne zamknięcia danego zakresu mają własne daty i artefakty. Nie wolno zsumować całej historii ani odczytać pojedynczego starego pola jako bieżącego odbioru całego systemu.

## Aktualizacje po początkowym zapisie

Pozostałe siedem klas zakończyło się sukcesem w sesji 8120: Store 20, Auth 4, HTTP 58, TerminalLib 25, PTY 19, AuthLifecycle 45 i PeerPolicy 15. Łącznie 186 zaliczonych testów. Nowy deterministyczny test wyrównania zegara, rzeczywistego rollback i pierwotnego terminu heartbeat również przeszedł.

Zapisano siedmiu rzeczywistych właścicieli uruchomień, 21 kopii dowodów oraz pozytywne zebranie dzieci, opróżnienie grup i zamknięcie/usunięcie własnych zasobów roboczych. Pierwotny zegar tego osobnego przebiegu zachowano; górna granica obserwacji Root wynosi 244,889735 s i obejmuje także czas do odczytania wyniku podczas zapisu raportu.

Wynik aktualnego kodu to **659 zaliczonych i jeden niezaliczony test spośród 660 wykonanych**. Native38 jest odrębnym zestawem 38 przypadków i nie jest dodawany do tej liczby. Niezależny przegląd zbiorczy jest zamknięty dla zakresów zaliczonych; pełne Host, cała macierz jako sukces, etap produktu i pełne REQ pozostają niezakwalifikowane.


Niezależny przegląd wyników Source708 został zamknięty bez problemów integralności dowodów. Nowe, odrębne odbiory obejmują check/Clippy, producer, Native38, listingi i pozostałe siedem klas. Zachowano 162 publiczne kopie dowodów. Wynik całego zestawu pozostaje 659/1; jedyny błąd TLS nadal blokuje pełny sukces Host i macierzy. Formalny zapis: `production-ownergraph-rename-result-review/e8d90af6-625f-45af-81c6-71a0b94e4a44/`.


Uzupełnienie z bieżącymi wynikami Source709, ograniczeniami i kopią dowodów: [aktualizacja Source709](stan-wdrozenia/2026-10-21/aktualizacja-709/README.md).


### Dokładny punkt wznowienia po zapisie raportu

Maszynowy [zapis wznowienia](stan-wdrozenia/2026-10-21/WZNOWIENIE.json) przypina bieżący manifest, zamknięty przegląd wyników i trzy osobne pakiety następnej integracji. Kernel move i wejście sieciowe są przejrzane źródłowo; korekta fixture z budżetem 1024 odpowiedzi oczekuje jeszcze końcowego przeglądu źródeł. Żaden z tych trzech pakietów nie został zastosowany ani uruchomiony. Łącznie dotyczą 11 rozłącznych istniejących ścieżek, bez nowego pliku produktu; zawierają 15 nowych, nieuruchomionych funkcji testowych oraz asercje zużycia odpowiedzi w dotychczasowym teście TLS. Następnym krokiem jest jedna wspólna integracja i weryfikacja, z ponownym odczytem rzeczywistych listingów. Nie ma aktywnego zadania native/Cargo.

## Aktualizacja 21.10.2026 (po 709): zielona macierz Host, aktywny zdalny `terminal.move`

Środowisko: macOS arm64, Rust 1.98.1, uruchomienia przez `tools/test-host.sh`. Nic nie zostało scommitowane, wdrożone ani opublikowane. Szczegóły i odrzucone podejścia: [progress.md](../lomi-remote/docs/implementation/progress.md).

- **Test TLS/Noise zaliczony.** Przyczyną nie był kod produkcyjny: fixture wyczerpywał skryptowane odczyty uprawnień (potrzeba około 195 na połączenie, budżet był 64), a potem niezoptymalizowane build debug przekraczał realne okno świeżości 5 s. Wartości kontraktowe (5 s, 30 s) bez zmian.
- **Zastosowano zrecenzowane kandydaty** `terminal-move-owner-kernel` i `terminal-move-ingress`. Zdalny `terminal.move` działa przez prawdziwe TLS/Noise z deduplikacją po reconnect i dwoma żywymi PTY.
- **Wyniki:** `lomi-host` 491/491 (trzy przebiegi), cały workspace 1136/1136, Clippy `-D warnings` czysty.
- **Poprawki testów znalezione przy pełnej macierzy:** zależność od umask 077 (87 testów dawało `INVALID_PROFILE`), test zależny od czasu `exec` zamiast od kontencji, oczekiwana wersja schematu Store 3 zamiast 4.
- **Nadal otwarte:** revoke dla Gita (REQ-13; brak GitService), uruchomienie tej rundy testów na Linuxie (lab Linux przestał przyjmować logowanie hasłem), PostgreSQL/przeglądarka, pełna kwalifikacja Windows (boot/logoff, Windows 11; sam `lomi-host` na Windows 10 zaliczony), E3–E7 i wszystkie pełne REQ.

## Aktualizacja 22.10.2026 — kreator TUI i fundament klienta v2 WWW

TUI `lomiremote` ma teraz kreator, który dodaje istniejący katalog lokalnie,
a udostępnia workspace dopiero po osobnym potwierdzeniu `y`. Odmowa lub wyjście
pozostawia go lokalnym. Przepływ korzysta z istniejących hostowych operacji
`WorkspaceAdd` i `Share`; wynik „udostępniono” pokazuje dopiero po odczycie
odświeżonego stanu hosta. Długość wejścia jest ograniczona, a Ctrl-C trafia do
obsługi zamykania dashboardu. `cargo test -p lomiremote` zaliczył 37 testów,
`cargo fmt -p lomiremote -- --check` również przeszedł. Nie zamyka to pełnego E1
ani consumer S5/S6/S7.

`remote-web` ma kontraktową granicę inicjalizowaną kanonicznym Rust/WASM:
waliduje RPC request/response z korelacją oraz ramkę admission WSS. Manifesty
snapshotów zawierają hashe wyłącznie dozwolonych plików runtime. Dodano do nich
także pakiet authority-crypto v3 z Rust/WASM; remote-web instaluje go lokalnie
bez zależności od sąsiedniego checkoutu. Weryfikacja snapshotów przeszła,
authority package zaliczył 38/38 testów, remote-web 54/54, a czysty checkout
z `bun install --frozen-lockfile`, testami i buildem Astro zakończył się
powodzeniem. Build ma istniejący hint `requestSeq`; obraz Docker nie został
zbudowany, bo Docker nie jest zainstalowany.

Powyższy opis jest historycznym stanem sprzed podłączenia klienta v2 i nie
opisuje bieżących źródeł. `remote-web` ma teraz opt-in ścieżkę v2: UI w
`App.tsx` otwiera `RemoteV2Workspace`, a `consumer-window-v2-channel.ts`
realizuje tworzenie kanału, admission, ticket, połączenie z relayem, handshake
Noise i weryfikację grantu. Worker używa authority-crypto WASM i trwałej
tożsamości okna zapisanej w IndexedDB. Serwer udostępnia odpowiadające temu
operacje kanału i relay v2. Domyślna ścieżka aplikacji nadal używa v1, a profil
terminala v2 pozostaje oznaczony jako eksperymentalny. Nie ma jeszcze
udokumentowanego udanego przebiegu klientowego setupu kanału ani odbioru przez
wdrożony relay i prawdziwy host; E3 pozostaje nieodebrane.

Linux lab ponownie przyjął SSH po usunięciu starego wpisu klucza `known_hosts`
zgodnie z poleceniem użytkownika. Odczyt potwierdził Arch Linux x86_64.
Toolchain Rust 1.98.1 był już zainstalowany w `~/.cargo/bin`; katalog był pominięty w
nieinteraktywnym `PATH`, więc nie instalowałem narzędzi. Aktualny snapshot
źródeł trafił do osobnego katalogu; hash archiwum i plików TUI sprawdzono po
transferze. `cargo test --locked --offline -p lomiremote` zaliczył 36/36,
`cargo fmt -p lomiremote -- --check` przeszedł. Log, wejście i hashe są w
`../lomi-remote/artifacts/linux-lomiremote-ui-20261022/`. Użyto istniejącego,
nieaktywnego równolegle cache `target`; stary katalog źródeł zachowano.

To ogranicza się do `lomiremote` na Arch. Nie kwalifikuje pełnego Host,
Ubuntu/Debian, czystego bootu usługi ani E1/E2; wcześniejsze 534/534 pozostaje
osobnym przebiegiem. Reszta etapów pozostaje otwarta.

### S5 private11 — successor źródeł tylko do przeglądu (22 października)

Historyczny freeze z 20 października nie obejmował bieżących bajtów
`controller.py` i `controller.test.py`. Powstał osobny pakiet successor pod
`../lomi-remote/artifacts/consumer-private-positive-controller/2026-10-22-eleven-source-only-successor/`;
zawiera 88 przypiętych plików źródłowych, 228 wejść authority, siedem
przypiętych artefaktów oraz archiwum dokładnie tych 88 plików.

Freeze SHA-256:
`4da2afd5887621a06ff28ac798fbadf3fd78d74828a20fd4628f0420feec2c5c`;
archiwum SHA-256:
`b2205aedb05fc86e119ae3b43858cb948911d4344e4b8f0ccca0193ebcb06d8c`.
Na tym pakiecie `controller.test.py` i `disposal.test.py` zaliczyły po 15/15
testów syntetycznych. Domyślny kontroler odpowiedział
`PREPARED_NOT_EXECUTED`, bez uruchomienia procesu. Hashy plików źródłowych,
artefaktów i wszystkich 88 członków archiwum zgodnych z manifestem sprawdzono.

Kontrola wejść runtime zatrzymała się na brakującym Node pod przypiętą ścieżką
`tools.json`; 49 pinów narzędzi runtime i dwa piny lokalnego stdlib pozostają
niezweryfikowane w tym środowisku. Nie uruchomiono PostgreSQL, Node, pipe,
parsera SQL ani credential-bearing call. Niezależny przegląd dokładnego freeze
znalazł wysokiego ryzyka wyścig TOCTOU: `pinned()` hashuje ścieżkę, a moduł
potem jest otwierany ponownie; entrypoint wykonuje się przed własną kontrolą.
Katalog źródeł jest zapisywalny przez tego samego użytkownika, więc plik można
podmienić na czas wykonania i przywrócić przed końcowym hashem. Potrzebny jest
zaufany launcher, który przed startem utworzy root-owned, niezapisywalny pakiet,
oraz odczyt i wykonanie modułów z tych samych zweryfikowanych bajtów. Do tego
czasu OS-root admission pozostaje zamknięte; S5 nadal jest niezaliczone.


## Uzupełnienie 22.10.2026 — bieżący Host na Linux Arch

Po potwierdzeniu klucza SSH z konsoli odtworzyłem bezpieczny dostęp do laboratorium.
Nowy snapshot źródeł (1245 plików) przeszedł zgodność manifestu przed uruchomieniem.
Na Arch Linux x86_64 pełny `lomi-host --lib` zaliczył 534/534 testy; osobny
przebieg real TLS/Noise zaliczył 38/38, obejmując współdzielony PTY dwóch klientów,
unshare podczas obserwacji plików, watch ACK/resume oraz znane i niepewne wyniki
błędów `exec`. `cargo fmt --all -- --check` i Clippy `-D warnings` przeszły.
Log focused run i manifest źródeł są w
`../lomi-remote/artifacts/linux-host-current-source/2026-10-22-arch-followup-revoke-watch-multiclient/`.

To nadrabia wskazaną rundę testów na maszynie laboratoryjnej. Arch nie kwalifikuje
Ubuntu/Debian z macierzy, a testy rzeczywistego Cloud/PostgreSQL, czysty boot usługi
oraz E3–E7 pozostają otwarte. Nie jest to kwalifikacja produkcyjna.


### Uzupełnienie S5 successor2 — niezależny przegląd źródeł (22 października)

Niezależny przegląd statyczny dokładnego freeze successor2 został zamknięty.
Sprawdzono zgodność freeze i archiwum, wszystkie 88 członków archiwum oraz
siedem hashy artefaktów towarzyszących. Zmiana ładowania modułów zamyka
poprzedni TOCTOU: import hashuje i wykonuje ten sam bufor bajtów. Pozostaje
średniej wagi luka zapewnienia: entrypoint zaczyna się wykonywać, zanim sprawdzi
własną własność. Zaufany launcher musi zweryfikować i uruchomić dokładnie te
same bajty entrypointu oraz powiązać ich digest z root admission. Kontrola
ścieżkowa oparta o `lstat` nie dowodzi odporności na równoległego uprzywilejowanego
writera ani nietypowe ACL.

Testy czysto syntetyczne zamrożonego pakietu: controller 17/17, disposal 15/15.
Nie uruchomiono PostgreSQL, Node, SQL ani natywnej nominacji. Brak przypiętego
Node nadal blokuje weryfikację 49 pinów runtime i dwóch pinów stdlib. Native
admission pozostaje niedane, a pełne S5 jest otwarte.


### Bieżący fixture Cloud z rzeczywistym centralnym revoke — 22 października

Na bieżących źródłach `auth-app` zestaw `runtime` przeszedł na macOS z Bun
1.4.2, PostgreSQL 18.6 (prywatny socket) i Rust 1.98.1. Kompilacja fixture'u,
migracje, role/granty, test rzeczywistego handlera, regresje, Prisma i typecheck
zakończyły się sukcesem; runner zwrócił 0 i zatrzymał bazę oraz listener TLS.
Rzeczywisty CloudWorker przez TLS przeszedł publikację i odświeżenie uprawnień,
uzgodnienie nieznanego ACK bez powtórzenia PUT oraz centralny revoke. Manager
podniósł host epoch i cofnął wszystkie rodziny authorization; rzeczywisty GET
CloudWorkera został odrzucony, lokalny authority gate zamknięty, a `host_runtime`
nie został zmieniony. Central revoke wykonał jeden GET. Zasada fail-closed
pozostała bez zmian.

To ograniczony fixture macOS, nie runda Linux ani pełne E2. Nie dowodzi
propagacji centralnego revoke do wielu aktywnych połączeń ani działania relay.
Odbiór E2 i produkcji pozostaje otwarty. Receipt:
`../auth-app/artifacts/host-credentials-runtime-followup-20261022/8f1629e4-9d09-4dc4-9aa3-30cb476044a6/runtime-proof.json`
(SHA-256 `b17505b8ee35753469cd0ce1be109eb73446bc94c75af70f56041f60577be1a6`).

### Uzupełnienie — inspekcja roli prunera i wznowienie CloudWorker (22 października)

Inspektor Remote DB sprawdza teraz również stan roli
`lomi_consumer_challenge_pruner`: LOGIN, członkostwa w obu kierunkach,
uprzywilejowane flagi i prawo CREATE w `public`. Brak roli lub dowolny dryf
zamyka inspekcję błędem. Nowy test jednostkowy mutuje każde z tych pól, a
test prywatnej bazy wywołuje ten sam odczyt i walidator na rzeczywistej roli.
Testy metadanych: 11 passed, 1 pominięty test staging; PostgreSQL 18.6:
7 testów / 1 180 asercji; regresje: 958 passed, 1 istniejący skip / 7 742
asercje. TypeScript, Prisma oraz kontrola zmian przechodzą. Niezależny review
nie znalazł problemu materialnego. Receipt:
`../auth-app/artifacts/consumer-challenge-pruning-20261022-pruner-role-db-proof/83959a9c-b314-4ec0-8014-a3373e268a1f/runtime-proof.json`.
To nadal fixture prywatny; produkcyjna inspekcja staging/production, retencja
tożsamości okien i pełne S5–S7 pozostają otwarte.

Rerun13 rzeczywistego CloudWorker zachował commit publication i intent po
utraconym ACK w fazie pierwszej. Po restarcie faza druga utworzyła nowego ownera,
ale zakończyła się błędem Auth fixture'a przed jakimkolwiek GET (`requests = 0`).
Pozostałe sześć testów runtime/SQL przeszło; źródła były stabilne i prywatny
PostgreSQL został zatrzymany. Ten wynik nie obciąża handlera Cloud ani nie
potwierdza jego zachowania po restarcie. Polityka fail-closed została zachowana.
Receipt:
`../auth-app/artifacts/host-credentials-runtime-restart-worker-rerun13/21b97274-5c4c-4a17-8f01-c66097757f46/runtime-proof.json`.
Cloud/E2 pozostaje otwarte.

Rerun27 aktualizuje prywatny fixture restartu: przed fazą drugą wygasza
`leaseExpiresAt` i `freshUntil`, a Rust przechodzi przez first GET/invalidation,
second GET/Claim admission, claim POST i final GET. Faza pierwsza zachowała
intent i commit sequence 8; hash HostStore pozostał identyczny podczas
przekazania między ownerami. Faza druga osiągnęła `final_get_reconciled`, lecz
lokalny stan końcowy to pending absent, outbox nonempty, ACK missing i binding
sequence inny niż oczekiwane 7/8. Proces kończy się kodem 101 przed asercjami
tras i trwałego stanu.

Migracja `202610190005_host_runtime` resetuje `publicationSeq` do 0 i
`workspaces` do `[]` przy claim nowego runtime. Wygaszenie lease i świeżości
prowadzi więc do nowego runtime, którego GET nie może potwierdzić starego ACK
sequence 8 ani zachować starej członkowskiej publikacji bez nowego PUT. Nie
wykonano kolejnej korekty ani rerunu. Nie zmieniono produkcyjnego Cloud ani
fail-closed. Rust fmt, TypeScript check i kompilacja `cloud-fixture` przechodzą;
fixture PostgreSQL 18.6: 6 passed / 1 failed, 784 asercje. Źródła pozostały
stabilne; cleanup zakończony (stop 0, późniejszy status 3). Listener TLS zebrał
23 żądania łącznie, ale restartowe liczniki tras nie zostały zatwierdzone.
Receipt:
`../auth-app/artifacts/host-credentials-runtime-restart-worker-rerun27/18c8d420-9c37-4a82-95dc-394f8c75a70e/runtime-proof.json`.

Rerun28 poprawia wyłącznie fixture: po nowym claimie i final GET worker
wykonuje normalny heartbeat oraz ponowną publikację retained workspace w nowej
generacji. Dokładna sekwencja TLS ma 9 tras: początkowy GET/heartbeat/PUT, a po
restarcie GET/GET/claim/GET/heartbeat/PUT. Nie powtórzono starego PUT
(generation 1, sequence 8); nowa generacja zapisała i potwierdziła sequence 1,
zachowując workspace oraz opróżniając lokalny intent/outbox. Test restartu
CloudWorker przeszedł, a hash HostStore był niezmieniony przy przekazaniu
procesu.

Cały runtime suite nadal zakończył się wynikiem 6 passed / 1 failed (790
asercji). Późniejszy, niezależny `claim-refresh-race` używa stałego
`expectedGeneration: "1"` po tym, jak test restartu zwiększył ten sam wiersz do
generation 2; claim otrzymuje 409. To założenie kolejności fixture'a, nie błąd
odtworzenia restartu. Nie wykonano kolejnej poprawki ani rerunu. Rust fmt,
kompilacja binarki `cloud-fixture` i Auth TypeScript check przechodzą. Źródła
były stabilne; prywatny PostgreSQL 18.6 został posprzątany (stop 0, późniejszy
status 3). Receipt:
`../auth-app/artifacts/host-credentials-runtime-restart-worker-rerun28/959f74f5-9fd6-4fa8-85fa-929d19cab59d/runtime-proof.json`.

### 22 października — pełny fixture Cloud z utratą odpowiedzi TCP

`DataTransport::data_mutate` klasyfikuje teraz błędy po możliwym wysłaniu
mutacji jako `OutcomeUnknown`; DNS, błąd zestawiania połączenia i
`ConnectionRefused` pozostają zwykłymi błędami transportu. Test klienta
potwierdza pojedynczy PUT, jego odbiór przez serwer i brak odpowiedzi bez
replay.

Na bieżących źródłach przeszło `--suite runtime --cloud-worker-tcp-drop`:
prywatny PostgreSQL 18.6, Bun 1.4.2 i loopback TLS do rzeczywistego Remote
handlera. Publikacja i odświeżenie membership przeszły; TCP zerwano po commit
publication, następny GET uzgodnił wynik bez ponownego PUT, a lokalny intent
pozostał zachowany do uzgodnienia. Zaliczyły się także claim bez istniejącego
`host_runtime`, claim po rotacji, wyścig claim/refresh, restart procesu z
zachowaniem store i nową publikacją sequence 1, centralny revoke z zamknięciem
authority gate oraz dwóch lokalnych klientów. `host_runtime` nie został
zmieniony przez revoke. Runtime: 7 testów PostgreSQL / 1 362 asercje; regresje:
961 passed, 1 wcześniejszy skip / 7 808 asercji. Rust buildy, TypeScript,
Prisma oraz cleanup przeszły. To bieżący wynik po wcześniejszym `Rerun28`,
który zatrzymał się na starym `expectedGeneration` w fixture claim/refresh.

Receipt:
`../auth-app/artifacts/cloud-runtime-ambiguous-outcome/05745cb6-32ce-4668-8a1e-f9a18dcbfa7b/runtime-proof.json`
(SHA-256 `2d75e6d01d77bb8f3f2922bec0a4f3dac793011fbdfc484e42cb495667f7bb37`;
log SHA-256 `609ce61c3ea858ddfcc68fe7ece1ab432a876e00a632c112eae88e30d81d7485`).
Runner zwrócił 0, źródła nie zmieniły się w trakcie przebiegu, a prywatne
zasoby zostały zatrzymane i usunięte. Receipt ma `productionQualified=false` i
`boundedPostgres186FixturePassed=false`: to ograniczony fixture macOS, bez
produkcyjnego Cloud/relay, cross-host fanout i targetowej kwalifikacji Linux.
Pełne E2 oraz S5/S6/S7 pozostają otwarte.

### 22 października — Consumer S5: test źródłowy prywatnego kontrolera

Izolowany test `consumer-private-positive-controller/controller.test.py`
przeszedł 17/17. Test używa wyłącznie syntetycznych zależności i tymczasowych
plików; jego audyt odrzuca uruchamianie procesów, sieć i operacje natywnych
pipe'ów. Potwierdza zachowanie prototypu i jego domknięcie po błędach, ale nie
uruchamia PostgreSQL ani SQL, nie przyznaje root admission i nie kwalifikuje
Consumer S5/S6/S7. Plan pozostaje `SOURCE_ONLY_NOT_RUN`,
`nativeAdmission: NOT_GRANTED`, `fullS5Qualified: false`.

### 22 października — bieżące źródła na Ubuntu ARM64 i usłudze systemd-user

Na prywatnej VM Ubuntu 24.04 ARM64 (kernel 6.8.0-147, Rust 1.98.1)
zamrożono 1 335 plików bieżącego źródła (inwentarz SHA-256
`59344b752ad54d8f43cadc038ffbf2c3504e444fe95edcf8ae095a121509e64a`).
Build `lomiremote` i wybrane zestawy produktu przeszły: 810 testów, zero
błędów, dwa oznaczone pominięte. Dwa niezależne połączenia SSH potwierdziły
ten sam runtime i PTY po odłączeniu. Tymczasowa usługa `systemd --user`
przeszła 9 kontroli przygotowania i 23 weryfikacji, obejmujących kontrolowany
stop/restart/crash, PTY, zachowanie stanu i wznowione odinstalowanie. Cleanup
potwierdził usunięcie jednostki, procesów fixture i własnych plików.

Receipt: `../lomi-remote/artifacts/product-linux/7bce419a-23ed-4837-a811-1e16acae34c3/report.json`
(SHA-256 `ef3b54d3f6d942a590e86df610afa923a5de85d5579d5eac8467756c0f7f7efe`),
archiwum źródła SHA-256
`d84117087305d445eaa97e0a82fbfb9afbce9177882e0e4aa7a494d529fd7128`, log
testów SHA-256 `2f2aeb502f2366cfdf8b3a8e02b20aa6aa862aa28b9423b8d48222ab33db8f3c`.
To kwalifikuje wyłącznie ograniczony przebieg VM i usługę bieżącego użytkownika;
nie obejmuje rebootu, instalacji systemowej, czystego instalatora, Cloud/relay,
pozostałych targetów Linuksa ani pełnego E1/E2.

### Uzupełnienie — agregat restartu CloudWorker (22 października)

Prywatny fixture aktualizuje generację/epoch po claimie nowego runtime i
sprawdza dokładnie dziewięć tras restartu. Cały zestaw runtime przeszedł 7/7;
runner wykonał też regresje bez bazy, walidację Prisma, typecheck Auth i cleanup
prywatnego PostgreSQL 18.6 (exit 0). To dowód lokalnego handlera Remote i
CloudWorkera przez loopback TLS. Nie kwalifikuje wdrożonego relay, fanout
między hostami, docelowej macierzy OS ani pełnego E2. Kod produkcyjnego Cloud
i zasada fail-closed nie zmieniły się.

Receipt:
`../auth-app/artifacts/host-credentials-runtime-generation-fix-20261022-5/74cd50f2-db0c-4e7a-8fac-a335de5124a3/runtime-proof.json`
(SHA-256 `46c5de423af1b146cfb5f715dcd0a6f304d7a0d53309cfd938aff59d12f93a23`);
log SHA-256
`5736caab724540c48931ef009beea642d123b855498cfdc66d88bb013cf6f3b2`.

### 22 października — Remote Web: pełny fixture przeglądarkowy w trzech silnikach

`pnpm test:browser` przeszedł na Node 22.23.3 z natywnym fixture'em Rust
zbudowanym przez lokalne Command Line Tools. Ten sam fixture przeszedł w
Chromium, Firefox i WebKit: automatyczne workspace, odświeżenie i reconnect,
wejście równoległe do dwóch terminali, preemption, revoke, zmianę scope,
klik poza menu, Escape/Tab, wylogowanie oraz brak replayu wpisanego tekstu. CSP
nie zgłosiło naruszeń.
To lokalny test istniejącego klienta/protokołu v1; nie kwalifikuje Remote Web
v2, czystego VPS-a, wdrożonego relay/hosta ani E3/E6.
`pnpm test:browser-identity` także przeszedł w Chromium, Firefox i WebKit:
lokalna tożsamość IndexedDB przetrwała odświeżenie w każdym silniku. Build
statyczny, kontrola typów oraz 140 testów jednostkowych przeszły; Astro zgłosiło
0 błędów i 4 wskazówki.

Test WebKit ujawnił, że `blur` na menu „Sign out” przed `click` usuwał element i
blokował wylogowanie. Usunięto zamykanie menu przy ogólnym blur; klik poza
menu oraz klawisze Escape/Tab nadal je zamykają. Full fixture w trzech silnikach
przeszedł po przebudowaniu `dist`.

### 22 października — Remote Web v2 i spójność artefaktów Rust/WASM

Usunięto nieaktualny opis `remoteV2Request` jako transportu „dormant”; kod
obsługuje już aktywną ścieżkę v2, gdy odpowiedź konta zawiera `relayV2Url`.
Próba dodania scenariusza v2 do starego fixture'a Playwright została zatrzymana:
fixture implementuje wyłącznie v1. Prawdziwy test v2 musi użyć podpisanej
tożsamości hosta, dowodu okna konsumenta, admission Noise i relay v2; podstawienie
odpowiedzi lub wyłączenie workerów kryptograficznych nie byłoby odbiorem.
Brakujący test przeglądarkowy pozostaje otwarty w E3/E6.

`packages/remote-contracts` sprawdza 61 schematów, a jego 696 testów przeszło.
Przebudowano i potwierdzono odtwarzalność obu release WASM: protokołu i
authority crypto; ich zestawy przeszły odpowiednio 365 i 40 testów. Zmiana
dotyczyła wyłącznie pochodzenia artefaktów po dodaniu plików HTTP; bajty WASM
nie zmieniły się. Główny compatibility manifest Rust oraz snapshoty pakietów
Remote Web są zsynchronizowane. Manifest nadal deklaruje `draft-e0` i
`productTarget: v1`, więc to sprawdzenie nie kwalifikuje E3/E6 ani wydania.

### 22 października — Cloud TCP-drop: build przez Command Line Tools

Runner `auth-app/test/run_host_credentials_runtime.py` przenosi teraz jawnie
wybrany przez operatora `DEVELOPER_DIR` do procesu Cargo i zapisuje go w raporcie.
Zmiana nie przełącza systemowego Xcode i nie akceptuje licencji Apple.
`python3 -m py_compile` przeszedł, a test Rust `lomi-host` z feature
`cloud-fixture` zbudował się przez lokalne Command Line Tools (`--no-run`).

Nowy pełny przebieg zatrzymał się przed uruchomieniem PostgreSQL, ponieważ
dostępny Bun to 1.3.14, a runner wymaga dokładnie 1.4.2. Raport potwierdza
zero listenerów PostgreSQL oraz zakończone sprzątanie. Nie było nowego testu
zerwania TCP ani restartu CloudWorkera; próba nie kwalifikuje Cloud do produkcji.

GitService pozostaje niezaimplementowany. Host przed dispatch odrzuca RPC Git;
brakuje host-owned odkrywania repozytoriów, stabilnej tożsamości i mapowania na
EntryId/FileRevision, a istniejąca blokada jest per workspace. Nie dodano
częściowej obsługi ani nie zmieniono zachowania fail-closed.

### 23 października — fail-closed readiness dla Consumer challenge-pruner

Readiness auth sprawdza teraz dokładną funkcję
`lomi_prune_expired_consumer_window_challenges(uuid)`, jej właściciela
`lomi_consumer_challenge_pruner`, `SECURITY DEFINER`, wyłączny
`search_path=pg_catalog`, uprawnienie `EXECUTE` runtime oraz ograniczone
atrybuty roli właściciela i brak jej członkostw. ACL funkcji może zawierać
wyłącznie jeden grant `EXECUTE` poza właścicielem: do `lomi_runtime`, bez
grant option. Grant do PUBLIC lub innej roli zamyka readiness. Niezależny
przegląd wskazał dwa braki: czysty walidator przyjmował dowolną niepustą nazwę
funkcji, a readiness nie wykrywał szerokiego ACL. Oba warunki są teraz
sprawdzane; inspektor schematu zachowuje pozostałe kontrole.

Walidacja: `bun test test/remote-db-inspect-config.test.ts` — 12 zaliczonych,
1 pominięty test, 0 błędów, 454 asercje; `bun run check` i
`git diff --check` przeszły. Opt-in
`test/consumer-pruner-inspection-runtime.test.ts` również przeszedł na
odizolowanym, tymczasowym PostgreSQL (1 test); readiness i test używają tego
samego statycznego SQL, a fixture odczytał funkcję, właściciela i ACL w
transakcji tylko do odczytu. Ten sam SQL i mapowanie produkcyjne przeszły też
przez PrismaPg na tymczasowym klastrze. Osobny SQL check potwierdził
wykrywanie grantów PUBLIC i innych ról. Brak prywatnego PostgreSQL URL oraz
wymaganie Bun 1.4.2 przez pełny runner pozostawiają odbiór S5–S7 otwarty.
Pełny Xcode 27.1 jest zainstalowany, ale narzędzia urządzeń wymagają
niezaakceptowanej licencji Apple. Licencja nie została zaakceptowana; testu na
telefonie nie wykonano.

### 23 października — read-only inventory Windows

SSH działa dla konta administracyjnego i zwykłego konta testowego. Host
zwraca Windows NT 10.0.19044.0 / 64-bit; zapytanie tylko do odczytu nie
znalazło usługi o nazwie zawierającej `lomi`. Nie instalowano usługi i nie
wykonywano testu jej cyklu życia. Windows 10 nie należy do macierzy Windows 11
i Windows Server, więc odbiór usługi na targetach pozostaje otwarty.

### 23 października — CloudWorker lost ACK i restart, dokładna kolejność etapów

Harness restartu wymaga teraz dokładnej sekwencji etapów obu procesów potomnych,
włącznie z kolejnością i brakiem duplikatów. Nie zalicza już przebiegu, w którym
oczekiwane znaczniki pojawiły się tylko w dowolnym miejscu wyjścia.

Pełny runner `runtime` przeszedł na przypiętych wersjach Bun 1.4.2, PostgreSQL
18.6 i Rust 1.98.1. Użył rzeczywistego handlera Better Auth oraz Rust
CloudWorkera. Fixture zatwierdził publikację z sekwencją 8, utracił ACK TCP,
zachował trwałą intencję przez zakończenie procesu ownera, uzgodnił stan po
wygaśnięciu lease, a następnie opublikował sekwencję 1 w nowej generacji.
Zaobserwowano dokładnie dziewięć żądań restartu, oczekiwaną kolejność tras,
brak ponownego PUT i niezmieniony lokalny store przy przekazaniu procesu.
Prywatny klaster PostgreSQL został zatrzymany i posprzątany. Ten przebieg
zastępuje wcześniejszą próbę zatrzymaną przed PostgreSQL z powodu systemowego
Bun 1.3.14.

Dowód: [runtime proof](../auth-app/artifacts/cloud-worker-restart-cursor-acceptance-20261023/f650369c-2009-4101-bce9-2cd41db157ec/runtime-proof.json), [log](../auth-app/artifacts/cloud-worker-restart-cursor-acceptance-20261023/f650369c-2009-4101-bce9-2cd41db157ec/runtime-proof.log) i [zamrożone wejścia](../auth-app/artifacts/cloud-worker-restart-cursor-acceptance-20261023/f650369c-2009-4101-bce9-2cd41db157ec/frozen-inputs.tar.gz).

To ograniczony dowód rzeczywistego handlera i TLS fixture. Nie potwierdza
wdrożonego Cloud relay, fan-out między hostami, Consumer S5–S7 ani całego E2.

### 23 października — metadane runtime challenge-pruner Consumer

Pełny Consumer suite ujawnił, że PostgreSQL zwraca nazwę argumentu z
`pg_get_function_identity_arguments`. Readiness wyznacza teraz kanoniczny
podpis argumentów przez `oidvectortypes(p.proargtypes)`, zgodny z typowaną
tożsamością UUID z `to_regprocedure`. Pozostałe kontrole funkcji, ownera,
SECURITY DEFINER, `search_path` i ACL pozostają fail-closed.

Walidacja: przypięty runner `consumer` przeszedł z rzeczywistymi migracjami,
rolami ograniczonymi i produkcyjnymi grantami na PostgreSQL 18.6. Runtime DB
przeszedł 7/7 testów, w tym odczyt rzeczywistych metadanych i ACL prunera;
regresje bez DB przeszły 962 testy z jednym istniejącym skipem. Przeszły też
Prisma validation i TypeScript typecheck; klaster został zatrzymany i
posprzątany. To domyka kontrolę readiness metadanych, ale nie cały odbiór
Consumer S5–S7.

Dowód: [runtime proof](../auth-app/artifacts/consumer-s5-s7-acceptance-20261023/e986852b-584b-478b-9ae3-fe79bc230320/runtime-proof.json), [log](../auth-app/artifacts/consumer-s5-s7-acceptance-20261023/e986852b-584b-478b-9ae3-fe79bc230320/runtime-proof.log) i [zamrożone wejścia](../auth-app/artifacts/consumer-s5-s7-acceptance-20261023/e986852b-584b-478b-9ae3-fe79bc230320/frozen-inputs.tar.gz).

### 23 października — aktualne źródła i natywny transport Noise

Obecny zestaw 713 ścieżek źródłowych ma nowy, jawny manifest z zachowanym
zestawem ścieżek i kontrolą hashy przed kopią, po kopii i po przebiegu.
Narzędzie testowe `transport_authority` zostało przebudowane z wymaganą
funkcją `test-fixtures`, a jego binarium i receipt buildu przypięto osobnymi
hashami. Audyt obejmuje 725 jawnych wejść przed kopią, po kopii i po przebiegu.
Wcześniejszy manifest oraz receipt pozostają nienaruszone.

Odbiór natywnego transportu przeszedł na Bun 1.4.2 i PostgreSQL 18.6: 1 test,
615 asercji, 212 komend helpera, 15 wymaganych markerów. Przeszedł rzeczywisty
handler SQL, dwa połączenia WebSocket loopback, Noise, szyfrowanie w obu
kierunkach, fencing autorytetu, expiry oraz sprzątanie helpera i bazy.
Konfiguracja fixture przekazuje wymagany `REMOTE_RELAY_V2_URL`.

Dowód: [runtime proof](../auth-app/artifacts/channel-transport-native-runtime-final-20261023/0d935716-d062-4bcb-9781-af6be30fa03f/runtime-proof.json), [log](../auth-app/artifacts/channel-transport-native-runtime-final-20261023/0d935716-d062-4bcb-9781-af6be30fa03f/runtime-proof.log), [manifest](../lomi-remote/artifacts/channel-transport-native-current-source/e05da707-bc55-4c77-ba56-352fe2dfc02d/original-hash-guards.json) i [receipt buildu helpera](../lomi-remote/artifacts/channel-transport-native-current-source/transport-authority-feature-enabled-20261023/build-receipt.json).

To ograniczony test lokalnego handlera i relay `ws`. Nie kwalifikuje
wdrożonego Cloud/WSS, hostów na innych systemach, kanałów 264 klienta ani E6.

### 23 października — natywny load 264 kanałów, przebieg serialny

Po przypadkowym uruchomieniu dwóch fixture'ów równolegle i konkurencji o
wspólne zasoby maszyny, dokładny przypięty zestaw wejść przeszedł oba
scenariusze uruchomione pojedynczo. Bun 1.4.2 i PostgreSQL 18.6; każdy z
dwóch scenariuszy użył 264 kanałów, 792 wiadomości Noise, 528 finish i 528
początkowych kierunków AEAD. `host-revoke` zamknął 512 peerów. `global-lock-stall`
potwierdził zablokowanie odnowienia ownera i odgrodzenie 132 oczekujących
kanałów. Helpery, listenery i prywatna baza zostały posprzątane; audyt 725
wejść przeszedł.

To lokalny fixture SQL/native, nie dowód wdrożonego Cloud/WSS, reconnectu
rzeczywistych klientów, macierzy hostów ani gotowości produkcyjnej. Runner
utrzymuje `productionQualified=false` dla tak ograniczonego zakresu.

Dowód: [runtime proof](../auth-app/artifacts/channel-transport-native-load-serial-bun142-20261023/5542b9b6-7aae-4e86-aebb-66276776e933/runtime-proof.json), [log](../auth-app/artifacts/channel-transport-native-load-serial-bun142-20261023/5542b9b6-7aae-4e86-aebb-66276776e933/runtime-proof.log), [markery host-revoke](../auth-app/artifacts/channel-transport-native-load-serial-bun142-20261023/5542b9b6-7aae-4e86-aebb-66276776e933/native-load-host-revoke-markers.json) i [markery global-lock](../auth-app/artifacts/channel-transport-native-load-serial-bun142-20261023/5542b9b6-7aae-4e86-aebb-66276776e933/native-load-global-lock-stall-markers.json).

### 23 października — filtrowanie terminali AI w publisherze desktopu

Projekcja zdalnego workspace'u pomija terminale stagingowane przez Lomi,
sterowane przez agenta oraz rozpoznane jako CLI AI. Mieszane splity są
przycinane, a karty zawierające wyłącznie takie terminale nie są publikowane.
Ta sama klasyfikacja blokuje start shella w tle i jest używana przy limicie
udostępnionych terminali. Poll kontekstów aktualizuje sterowanie i mapę CLI,
po czym emituje pojedyncze powiadomienie; publisher nie widzi stanu pośredniego.

Walidacja na Node 22.23.3: pełne `pnpm test` przeszło 308 testów desktopu i 45
testów AI runtime; `pnpm check` oraz `pnpm build` przeszły. Build zachowuje
istniejący chunk Workbench 1,089.88 kB oraz ostrzeżenia dynamic import i limitu
500 kB. Testy workspace przeszły 9/9 na Node 22.14.0, Playwright kontekstów
1/1, a Prettier przeszedł. Rozpoznawanie CLI uruchomionego ręcznie oraz
sterowania agenta nadal korzysta z pollingu `terminal_contexts` co sekundę,
więc pozostaje krótkie okno rozpoznania. Nie jest to odbiór dwóch desktopów
ani pełne zamknięcie prywatności E4.

### 23 października — zastąpienie subskrypcji `files.watch`

Nowe żądanie `files.watch` zamyka poprzednią subskrypcję na tym połączeniu
przed próbą uruchomienia nowej. Jeśli nowe żądanie zostanie odrzucone, stary
watch nie wysyła dalej invalidacji po odpowiedzi błędu.

Walidacja: kontrola formatowania Rust przeszła; na macOS testy modułu watch
hosta przeszły 12/12, a rzeczywisty test ingress TLS/Noise dla invalidacji,
ACK i wznowienia watcha 1/1. Na VPS Ubuntu 24.04 testy silnika plików Linux/
inotify przeszły 26/26. Po zastosowaniu tej samej poprawki w tymczasowym
checkoutcie testowym VPS-a testy modułu watch hosta przeszły 16/16, a test
ingress TLS/Noise 1/1. VPS nie ma zainstalowanego produktu; to nie jest odbiór
instalacji E3. Zmiana domyka tylko wymianę pojedynczej subskrypcji. Nie zamyka
zakresu rekursywnych watchy, kwalifikacji systemów ani integracji Explorera we
wszystkich klientach.

### 23 października — zagnieżdżony `files.watch` przy niezmienionym mtime

Dodano regresję hosta, która otwiera `files.watch` na wylistowanym podkatalogu,
zmienia zawartość pliku potomnego bez zmiany rozmiaru, przywraca mtime i wymaga
invalidacji. Wcześniej taka kombinacja była pokryta na poziomie silnika plików
Windows, a test zdalnego watcha obejmował tylko katalog workspace'u.

Walidacja: kontrola formatu Rust przeszła, a cały moduł `remote_files_watch`
przeszedł na macOS 13/13, w tym nowy test podkatalogu. Uruchomienie tego nowego
przypadku przeszło na Ubuntu 24.04.5 ARM64 1/1; cały moduł Linux przeszedł
17/17, a test ingress TLS/Noise 1/1. Logi, wersje narzędzi i digest snapshotu
źródeł są w
`lomi-remote/artifacts/linux-files-watch/2026-10-23/ubuntu-24.04.5-arm64/`.
Pozostaje uruchomienie na macOS/Windows targetowych wersji, kwalifikacja
watcherów i integracja Explorera. Dowód Linux jest z lokalnej VM; nie potwierdza
instalacji produktu ani jego cyklu życia na VPS.

### 23 października — lokalna aktywacja celu zweryfikowanego przez TUF

Dodano `TrustStore::update_and_activate` oraz komendę CLI `activate`.
Aktywacja przyjmuje wyłącznie bajty zwrócone przez istniejącą weryfikację TUF,
zapisuje je jako tylko do odczytu pod nazwą SHA-256 i atomowo podmienia
względny symlink `active`. Ścieżka odrzuca symlinki, nieufnych właścicieli i
zapisywalne katalogi nadrzędne bez sticky bitu. Metadane zaufania są trwale
zatwierdzane przed aktywacją; awaria podmiany zostawia poprzedni plik aktywny,
a ponowienie tych samych metadanych jest obsługiwane.

Niezależny przegląd bezpieczeństwa nie znalazł dalszego blokera podmiany
ścieżki w przyjętym modelu obcych UID. Interferencja roota i tego samego UID
pozostaje poza tym modelem. Kontrola formatu Rust i macOS `cargo check` dla
wszystkich targetów przeszły. Testy trwałości przeszły na macOS 10/10. Na
lokalnej VM Ubuntu 24.04.5 ARM64 test trwałości z Linuxowym kodem aktywacji
przeszedł 13/13, w tym trzy testy aktywacji. Fixture ustawia prywatny katalog
tymczasowy na `0700`, zgodnie z kontraktem runtime. Linuxowy cross-check dla
x86_64 nadal zatrzymuje się przed kompilacją crate'a z powodu braku
`x86_64-linux-gnu-gcc`. Start usługi, integracja instalatora, pipeline
podpisywania i kwalifikacja wydania pozostają otwarte. To lokalny mechanizm
aktywacji, a nie produkcyjny instalator.

### 23 października — Cloud lost-ACK po restarcie workera

Rozszerzono izolowany fixture handlera Auth i Rust `DataTransport` o dwa wyniki
restartu. Jeśli lease poprzedniego runtime nadal jest aktywny, nowy runtime
odgradza i unieważnia stare binding oraz pending intent, zachowuje dokładny
outbox, nie zatwierdza kursora poprzednika i nie wysyła drugiej publikacji.
Po wygaśnięciu lease istniejący przebieg przyjmuje świeży claim, uzgadnia stan
przez GET i publikuje pod nową generacją. Produkcyjnego zachowania Cloud nie
zmieniano.

Końcowy prywatny runner PostgreSQL 18.6 / Bun 1.4.2 zakończył się kodem 0:
przeszło 7 testów runtime, `auth-app-typecheck`, sześć jawnych znaczników
scenariusza aktywnego lease oraz wszystkie 47 żądań Rust `DataTransport` z
oczekiwanymi trasami. Relay i Auth działały jako prywatne fixture'y loopback;
nie kwalifikuje to wdrożonego Cloud/relay, fan-out produkcyjnego ani całego
odbioru E1/E2. Dowód: [runtime proof](../auth-app/artifacts/cloud-worker-predecessor-valid-lease-fencing-final/7872194c-436d-4a58-b652-c30446b7984a/runtime-proof.json)
i [log](../auth-app/artifacts/cloud-worker-predecessor-valid-lease-fencing-final/7872194c-436d-4a58-b652-c30446b7984a/runtime-proof.log).

### 23 października — Remote Web lokalna macierz przeglądarek

Testy jednostkowe Remote Web przeszły 144/144. Astro check na Node 22.23.3
zgłosił 0 błędów, 0 ostrzeżeń i 4 podpowiedzi. Trwała tożsamość IndexedDB i
blokada wpisywania w cyklu `pagehide`/`pageshow` przeszły w Chromium, Firefoxie
i WebKitcie. Pełny lokalny fixture terminala przeszedł w tych trzech silnikach
i potwierdził odświeżanie/reconnect, jednokrotne wejście, kontrolę, izolację
paneli, prywatność metadanych, obsługę revoke/wyścigów oraz CSP. Produkcyjny
build statyczny i kontrola wyjścia przeszły; Vite nadal zgłasza chunk JavaScript
większy niż 500 kB. Szczegóły: [raport](../remote-web/docs/implementation/browser-matrix-2026-10-23.md).

To lokalny fixture przeglądarkowy. Nie obejmuje wdrożonego relay/hosta, Git,
fizycznego Androida/iPhone'a ani pełnej macierzy metod v1. E6 i kwalifikacja
wydania pozostają otwarte.

### 23 października — poprawka podglądu Explorera i kontrole mobile

Zdalny Explorer w Remote Web odrzuca teraz spóźniony wynik `files.read`, jeśli
użytkownik zamknął podgląd, zmienił katalog, otworzył inny plik albo zamknął
Explorera. Testy obejmują też poprawne podglądanie wyniku wyszukiwania. Pełny
zestaw Remote Web przeszedł 154/154 testy w 28 plikach, a statyczny build i
kontrola wyjścia produkcyjnego przeszły. Pełny lokalny scenariusz przeglądarkowy
przeszedł też w Chromium, Firefoxie i WebKitcie; każdy przebieg potwierdził
cztery wejścia, zero odrzuconych ramek inputu i brak naruszeń CSP. Astro zgłosił
cztery podpowiedzi, Vite nadal zgłasza chunk JavaScript powyżej 500 kB. Kod:
`../remote-web/src/explorer.ts`.

Na Node 22.23.3 mobilne `pnpm check` przeszło lint, oba sprawdzenia TypeScript,
289 testów, kontrole renderera i crypto oraz kontrolę konfiguracji. Końcowy
`release:check` zatrzymał się na niezaakceptowanej licencji Apple dla już
zainstalowanego Xcode 27.1 (`xcodebuild` zwrócił 69). Nie zaakceptowano licencji.
Przy bieżącym sprawdzeniu USB `adb` nie wykrył Androida, a system macOS nie
zgłosił podłączonego iPhone'a. Buildy natywne i fizyczny odbiór mobile nie
przeszły.

To ograniczone lokalne testy źródła; nie domykają E3/E6, wdrożonego Cloud/relay,
Consumer S5–S7 ani gotowości produkcyjnej.

### 23 października — anulowane Consumer i spójność lease Cloud

Consumer authority sprawdza teraz anulowanie po wejściu do globalnej transakcji
i przed rozpoczęciem zapisu. Test z rzeczywistym PostgreSQL przytrzymuje ten sam
advisory lock, potwierdza oczekiwanie backendu `lomi_runtime`, anuluje challenge,
zwalnia blokadę i potwierdza retryable 503 z `effect: none` oraz niezmienioną
liczbę wyzwań. Zachowano kolejność ukrywania wyłączonego endpointu (404 przed
sprawdzeniem anulowania). Ochrona obejmuje też pozostałe mutacje authority,
revoke, prune i rejestrację okna przed rozpoczęciem SQL.

Parser odpowiedzi Cloud runtime odrzuca obecnie wiersz, w którym pozostała
świeżość przekracza pozostały lease. Kontrakt migracji już gwarantuje tę relację;
zmiana jest dodatkową kontrolą niezgodnego wyniku bazy.

Przypięty runner Bun 1.4.2 / PostgreSQL 18.6 przeszedł: 8 testów DB i 1 296
asercji, 977 regresji i 7 968 asercji, Prisma, TypeScript oraz cleanup klastra.
Testy granicy runtime przeszły 106/106. Raport:
`../auth-app/artifacts/consumer-abort-fence-20261023/e2e359c2-1d68-4ec8-b78b-3b342245418b/runtime-proof.json`.
Pierwszy ponowny start z domyślnym Bun 1.3.14 zatrzymał się przed inicjalizacją
PostgreSQL; właściwy, przypięty przebieg powyżej zakończył się kodem 0.

To nadal lokalne dowody. Nie zamykają Consumer S5–S7, wdrożonego Cloud/relay,
fan-outu między hostami, całego E1/E2 ani wydania produkcyjnego.
