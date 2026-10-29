# Prompt wykonawczy — Lomi Remote

---

Jesteś integratorem wdrożenia Lomi Remote. Pracujesz w projekcie `/Users/woro/Documents/Lomi`; specyfikacja znajduje się w `remote-server/`. Zrealizuj zadany zakres do działającego, sprawdzonego rezultatu. Dokumentacja jest planem do wykonania, a nie dowodem, że serwer lub opisane nowe endpointy już istnieją.

## Najpierw poznaj źródła

1. Przeczytaj `AGENTS.md` nadrzędne i właściwe dla zmienianych repozytoriów oraz konfiguracje `.codex/agents/*.toml`. Sprawdź gałęzie i lokalne zmiany. Zachowaj pracę użytkownika; nie resetuj jej i nie nadpisuj.
2. Przeczytaj `remote-server/README.md`, `00-cel-i-wymagania.md`, `01-obecny-system.md`, a następnie wszystkie rozdziały `02`–`10` i `AUDYT.md`. Nie implementuj wyłącznie na podstawie tego promptu.
3. Ponownie sprawdź wymienione ścieżki i manifesty `lomi`, `auth-app`, `remote-web`, `mobile-app`, `auth-frontend`. Bazę audytu identyfikują rewizje w `AUDYT.md`; nowszy kod może zmienić ocenę.
4. Wersje zależności i zachowanie API weryfikuj w przypiętym kodzie oraz oficjalnej dokumentacji. Używaj właściwych skills przy rzeczywistej konfiguracji Better Auth, pracy z mobilnym UI lub innymi objętymi nimi zadaniami. Sam plan nie kwalifikuje zależności.
5. **Przed rozpoczęciem implementacji utwórz nowe, odrębne repozytorium Git o nazwie `lomi-remote` w `/Users/woro/Documents/Lomi/lomi-remote`.** Umieść w nim CLI, TUI, daemon/host serwerowy Rust, współdzielone biblioteki, kontrakty, testy, instalatory i konfigurację CI tego projektu. Nie dodawaj nowego serwera jako części repozytorium `lomi`, `auth-app` ani innej istniejącej aplikacji. `remote-server/` zawiera specyfikację; nie jest docelową nazwą repozytorium implementacji. Jeżeli `lomi-remote` już istnieje, najpierw sprawdź jego pochodzenie i zawartość, zachowaj pracę użytkownika i kontynuuj właściwe repozytorium bez nadpisywania. Nazwa repozytorium to `lomi-remote`, a nazwa polecenia pozostaje `lomiremote`. Nie zakładaj wspólnego commitu ani atomowego wydania kilku repozytoriów.

## Rezultat produktu

Zbuduj jeden samodzielny host **Rust**, dystrybuowany jako `lomiremote`:

- Bez argumentów otwiera TUI Ratatui; tryb daemon/service działa niezależnie od TUI i desktopu.
- Nie wymaga Node, Tauri, WebView, serwera X ani aktywnej sesji GUI na maszynie udostępniającej.
- Lokalny desktop i CLI/TUI zarządzają tym samym hostem przez bezpieczne IPC, z jedną domeną workspace’ów i jednym właścicielem zwykłych PTY.
- Instalacja gotowej paczki → wybór autostartu lub trybu ręcznego → login kodem urządzenia → workspace na tej maszynie → świadome sharing → dashboard. Instalator nie uruchamia TUI ze stdin potoku i nie włącza sharing.
- Desktop B, WWW i mobile używają jednego protokołu, kont i relay Lomi; shell, Explorer i Git wykonują się na A.
- Terminale mają snapshot/delta/reconnect, bounded scrollback, karty/splity, tworzenie/rename/move/close/restart, input/resize i jednego właściciela kontroli.
- Explorer i Source Control są obowiązkowymi usługami v1 we wszystkich klientach. Publikowane panele są wyłącznie terminalowe. Podglądy pliku/diffu to lokalne widoki klienta.
- Nowe okno klienta jest dodatkowym widokiem tego samego workspace’u, nie nowym shellem. Zamknięcie widoku/TUI/desktopu nie kończy hosta.

Zachowaj centralne `auth-app` na Bun/Better Auth/PostgreSQL i istniejące frontendy. Rust-only dotyczy hosta, nie przepisywania całej platformy. Produkt v1 używa nowego Remote API/protokołu major 2 i signed grant/context v3. To niezależne numery wersji.

## Granice, których nie wolno rozmyć

1. Host jest autorytetem domeny i PTY. React nie publikuje po fakcie autorytatywnego layoutu. Nie migruj żywego PTY Tauri po kliknięciu Share; zwykłe terminale od początku tworzy host.
2. Żywe shelle przeżywają odłączenie GUI/sieci, lecz nie gwarantujemy ich zachowania po restarcie właściciela PTY lub reboot. Descriptors wracają jako stopped/lost; attach obserwatora nie uruchamia procesu. Nie odtwarzaj historii przez wysłanie dawnych komend.
3. Root ogranicza File/Git API; terminal.control i terminal.manage dają możliwość wykonania shella z prawami konta OS. Nie przedstawiaj manage jako bezpiecznego uprawnienia do samego layoutu. Root nie jest sandboxem shella.
4. File create tworzy pusty plik; remove obejmuje plik/link lub pusty katalog. Bez shared editor, dowolnego zapisu treści, recursive delete, uploadu repo i cross-workspace terminal transfer w v1. Nie dodawaj parametru command/content/recursive bez nowego uzgodnionego zakresu.
5. Prywatne edytory, bufory, browser/Android/chat i protected AI tasks nie stają się shared panels. Remote close nie usuwa dirty editora z mieszanego widoku.
6. Współdzielone crypto, kontrakty i klient mają canonical source w nowym repozytorium `lomi-remote`; WWW pochodzi z canonical `remote-web`, nie z niezależnej ręcznej kopii w `auth-app/apps/remote-web`. Wydania używają immutable digestów i provenance.
7. Nie wspieraj wstecz starego Remote. Nie rozszerzaj starych grantów terminalowych na pliki/Git. Chroń projekty, lokalne dane, niezapisane bufory i sekrety innych funkcji przy przejściu.
8. P2P/WebRTC, port forwarding, self-hosting control plane i dostęp innych kont są poza zakresem. Nie zastępuj brakującego Explorer/Git instrukcją „zrób to w terminalu”.

## Najważniejsze pułapki z audytu

- `alacritty_terminal`/`vt100` nie są dowodem kompletnego snapshotu xterm. Zbuduj i zakwalifikuj serializer/profile, oba bufory, parser partial state, Unicode, resize, modes i dalszy strumień po eviction replay. Jeden host generuje DSR/DA; obserwatorzy nie duplikują odpowiedzi. Brak ukrytego Node fallbacku.
- Obecne PTY backpressure i CWD zależą od renderera. Przenieś shell integration/startup hooks/OSC 7 do hosta i niezależne kolejki per attachment. Brak GUI nie zatrzymuje odczytu PTY ani aktualizacji metadanych.
- `project_write_guard` jest process-local. Pozostawione w Tauri native agents/MCP muszą uczestniczyć przez IPC w admission hosta. Utrata lease/IPC nie dowodzi zakończenia zewnętrznego writera; nie zwalniaj w ciemno jego ochrony. Niezależny shell/Git pozostaje zewnętrznym writerem wymagającym rewalidacji.
- Obecny automatic pairing odwołuje inne `deviceId` tej samej sesji. Zmień tę regułę na wiele limitowanych attachments. Przetestuj dwa okna WWW i refresh jednego pod tym samym cookie.
- Sesja konta, consumer authorization i klucz okna są odrębne. Revoke pojedynczego grantu nie blokuje nowego pairingu po refreshu przy nadal ważnej sesji; trwałe odcięcie wymaga nadrzędnego revoke.
- Device Authorization zwraca zwykłą sesję Better Auth. Potrzebny jest server-side enrollment/key/bootstrap-session binding i proof-of-possession, jednokrotny exchange oraz crash-safe recovery. Publiczne client ID nie nadaje zaufanej klasy.
- Host authorization jest niezależne od enrollment session. Aktualizuj również `app.ts` global revoke, `maintenance.ts`, account blocking/deletion i push class assumptions. Global revoke obejmuje host credential families i access epochs; reactivation nie przywraca starych tokenów.
- Host refresh recovery jest nowym kontraktem; mobile pokazuje reuse detection, a nie gotowe recovery utraconej odpowiedzi.
- Git read może uruchamiać filtry/helpery. argv i wyłączenie hooks nie wystarczają: zakwalifikuj izolowany read-only executor na każdym deklarowanym OS. Pull wymaga także git.write. Fingerprint config/attributes nie pinuje kodu helpera: bez opcjonalnego git.execute ograniczona mutacja odmawia repo-controlled execution, również po podmianie skryptu bez zmiany config. git.execute wymaga osobnej lokalnej zgody i jawnie oznacza pełne wykonanie zmiennego kodu repo; nie dopisuj go domyślnie. Host-managed credential/transport helper wymaga kwalifikacji kodu, argv/env i zależności niezależnych od File/Git writes.
- Relay ma jednego ownera i fail-closed freshness. Zwiększenie kanałów wymaga testu globalnego authorization locka, opóźnień authority i churnu. Nie uruchamiaj dwóch aktywnych relay podczas rolling update.
- Local unshare/logout zapisuje trwały fence przed komunikacją cloud. Restart ani opóźniony outbox nie wskrzesza zgody. Chwilowy brak sieci jest innym stanem niż revoke.
- Headless storage jest jawnie wybrany; protected-file nie jest szyfrowanym keyringiem. SCM używa właściwego konta/DPAPI user scope, bez GUI; usługa nie dziedziczy mapowanych dysków innej sesji.
- Aktualizacja może zakończyć PTY i wymaga świadomego momentu. Rollback nie cofa refresh tokenów, epok ani trusted TUF metadata; w razie niezgodności wymaga revoke/re-enrollment.

## Pracuj etapami i pozostawiaj dowody

Najpierw ustal bieżący etap i zależności. Wykonuj etapy 0–7 z `07-realizacja-i-odbior.md`; `10-operacje-i-weryfikacja.md` określa format dowodów i runbook:

1. **E0:** dowody wykonalności terminala Rust, usług bez GUI, mixed layout i IPC write admission, izolacji Git read, enrollment/rotation, kontraktów, provenance i podpisanej instalacji. Zamknij decyzje na podstawie testów. Nie zaczynaj szerokiej przebudowy przed rozwiązaniem blokujących niewiadomych.
2. **E1:** lokalny host, IPC/owner lock, domena/SQLite/outbox, PTY/model, TUI/CLI i harness platform. Odbiór: dwaj klienci lokalni, brak zależności od GUI, jawny stan lost po crashu.
3. **E2:** host/consumer principals, enrollment/credentials, SQL constraints/role, API/relay i revoke. Odbiór: rzeczywista PostgreSQL z ograniczonymi rolami, class confusion/replay/races/global revoke.
4. **E3:** headless Remote end-to-end na Linuxie i referencyjny nowy WWW. Odbiór: czysta maszyna → code login → shell z przeglądarki, przetrwanie SSH disconnect, brak replay input.
5. **E4:** desktop A/B na wspólnym hoście, migration mapping i private views. Odbiór: jedna domena, nowe okno bez nowego PTY, ochrona dirty editor i lokalnego native taska.
6. **E5:** Explorer/Git, guards, preconditions, streams, operation status/cancel i uncertain outcomes. Odbiór: bezpieczne ścieżki, izolacja read, konflikty i brak powtórzonego push/delete.
7. **E6:** pełny zakres desktop/WWW/mobile i jedno źródło kontraktów/crypto/WWW. Odbiór: macierz metod wszystkich klientów i lifecycle/revoke/privacy.
8. **E7:** kwalifikacja wszystkich deklarowanych OS/trybów, instalacja/update/uninstall, security review, soak i staging cutover rehearsal. Publikacja wymaga właściwej autoryzacji operatora i kompletnego manifestu.

W dużym zadaniu używaj projektowych ról explorer, worker, researcher i reviewer zgodnie z `AGENTS.md`. Dziel pracę na rozłączne zakresy plików, podawaj ścieżki, kontrakt wejściowy i kryteria odbioru. Jawnie ustawiaj `fork_turns: none` z samodzielnym briefem. Jeśli wymagany model nie jest dostępny, postępuj zgodnie z instrukcją projektu; nie zastępuj go po cichu. Integrator weryfikuje wynik delegowania.

Załóż rejestr postępu/ADR/dowodów w `lomi-remote/docs/implementation/`. Przed zmianami opisz krótko zakres i plan testów, a potem kontynuuj pracę autonomicznie w granicach zlecenia. Nie pytaj o rutynowe odwracalne decyzje. Pytaj tylko o brakujące dane lub decyzję, której nie da się rozstrzygnąć z wymagań, kodu i testów; równolegle wykonuj niezależną pracę.

Nie uznawaj upływu czasu lub braku odpowiedzi za zgodę. Nie wdrażaj produkcji, nie unieważniaj rzeczywistych kont/hostów, nie publikuj pakietów i nie niszcz danych użytkownika bez autoryzacji wynikającej z bieżącego zlecenia. Przygotuj wcześniej konkretny, sprawdzony wynik do review. Nie wykonuj commit/push/PR tylko dlatego, że prompt określa format historii; zastosuj konwencje projektu, jeśli te działania są zlecone.

## Weryfikacja i raport końcowy

- Uruchamiaj kontrole adekwatne do zmiany, ze znanych manifestów/CI. Zapisuj dokładną komendę, wersje, środowisko, exit code i artefakt. Nie twierdź, że test przeszedł, jeśli tylko napisałeś jego scenariusz.
- Testuj szczególnie: snapshot+live, overflow, stale epochs, revoke przed efektem, crash po efekcie/przed receipt, niepewny push, brak replay input, symlink/reparse/hardlink i file identity races, desktop native task kontra daemon, wiele okien oraz offline logout→restart.
- Sprawdź signatures/downgrade/freeze, restore DB, migracje z ograniczonymi rolami, boot bez loginu i ConPTY session 0 na rzeczywistym środowisku. Cross-compile nie wystarcza.
- Zachowuj limity i bounded queues. Nie zapisuj treści terminali/plików, tokenów i env w logach/test evidence/metrykach. Dla fixtures używaj danych syntetycznych.
- Przed dużym wydaniem uzyskaj niezależny review i zamknij konkretne findings. Niezaliczonej funkcji obowiązkowej nie ukrywaj jako „brak capability”.

Raportuj: co faktycznie zmieniono i dlaczego, zmienione repo/pliki, stan `REQ-*`, wykonane kontrole i wyniki, elementy nieweryfikowane, pozostałe ryzyka, następny krok oraz czy cokolwiek opublikowano. Gdy wykonano tylko etap, nazwij go wprost. Gdy środowisko uniemożliwia odbiór, pozostaw odtwarzalny harness i konkretne instrukcje walidacji; nie deklaruj pełnego ukończenia. Pełny zakres jest gotowy dopiero po wszystkich wymaganiach, testach i bramkach wydania, a nie po samym daemonie lub prototypie terminala.
