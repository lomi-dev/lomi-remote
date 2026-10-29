# 05 — Logowanie, uprawnienia i bezpieczeństwo

## Granica zaufania

Terminal daje możliwość wykonywania poleceń **z prawami konta systemowego hosta**. Root workspace’u jest granicą operacji Explorer/Git, a nie sandboxem dla shella. Klient z terminal.control może uruchomić `cd`, czytać inne dostępne temu kontu pliki i wykonywać programy. TUI i Share remotely muszą komunikować to przy pierwszym udostępnieniu.

V1 jest systemem własnego konta Lomi i zaufanych użytkowników tego konta, nie publicznym serwisem multi-tenant z izolacją nieznanych osób. Na VPS rekomendujemy dedykowane konto o potrzebnych prawach. Kontenery, VM, shell sandboxing i współdzielenie z innymi kontami są osobnymi przyszłymi projektami.

Chronimy przed podsłuchem/zmianą danych transportu, klientami bez uprawnień, replay, stale grants, przejęciem ticketu, pomyłkami workspace’u, path traversal w API, nieautoryzowanym lokalnym IPC, niekontrolowaną utratą danych przy retry i wadliwymi aktualizacjami. Przejęty system hosta lub klient z pełnym terminal.control ma inne możliwości niż bierny relay; nie opisujemy E2EE jako ochrony przed przejętym endpointem.

Domyślny flow ufa centralnej usłudze identity w kwestii własności konta i pierwszego powiązania hosta z kluczem. E2EE ogranicza dostęp relay do treści, ale nie eliminuje zaufania do identity ani kodu WWW dostarczanego przez platformę. Historyczny pin nie zmienia się bez jawnego resetu/re-enrollment.

## Trzy różne tożsamości

1. **Konto Lomi**: człowiek i jego aktywność/stan w centralnej platformie.
2. **Host installation**: trwały host ID, para kluczy i upoważnienie do działania jako host tego konta. Nie jest otwartym oknem desktopu ani sesją przeglądarki.
3. **Consumer**: desktop B, przeglądarka lub mobile z własnym typem sesji i tożsamością kryptograficzną. Zalogowanie do konta nie jest samo w sobie prawem do dowolnego nieudostępnionego katalogu.

Na A desktop i CLI administrują jedną instalacją hosta. Desktop B jednocześnie może być klientem A i hostem własnych lokalnych projektów, ale identyfikatory i uprawnienia tych ról są rozdzielone. Remote workspace reference zawsze zawiera host ID i workspace ID; nie otwieramy przypadkiem lokalnego katalogu o podobnej nazwie.

## Logowanie serwera bez przeglądarki

Używamy istniejącego Better Auth Device Authorization jako etapu potwierdzenia użytkownika, zgodnego z kierunkiem RFC 8628. [`auth-app/src/auth.ts`](../auth-app/src/auth.ts) już zawiera plugin. Oficjalna dokumentacja rozróżnia zwracany token sesji Better Auth i access token OAuth; nie zakładamy wbudowanych refresh credentials nowego hosta. [Better Auth: Device Authorization](https://better-auth.com/docs/plugins/device-authorization), [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628).

Docelowy flow:

1. `lomiremote` generuje host key/ID i rozpoczyna krótkotrwały enrollment z publicznym client ID `lomi-remote-host`. W binarium nie ma client secret.
2. Serwer wydaje device code/user code i pozwala zatwierdzić **host enrollment** na stronie Lomi. Nazwa hosta jest opisem niezaufanym; UI pokazuje typ działania, kod i zakres.
3. Użytkownik na swoim telefonie/komputerze loguje się i zatwierdza. Rejestrujemy konkretny client class po stronie serwera, nie na podstawie dowolnego nagłówka ani body klienta.
4. Polling przestrzega `interval`, `slow_down`, expiry, rate limit i cancellation. Kod ma krótki TTL; nie służy do późniejszego logowania klienta B.
5. Otrzymany token sesji Better Auth jest używany wyłącznie jako bootstrap do **jednorazowej wymiany na host authorization**. Wymiana sprawdza zatwierdzony enrollment i powiązanie z host key/ID. Nie akceptuje dowolnej sesji konta jako prawa utworzenia dowolnego hosta.
6. Centralna platforma tworzy osobny record host authorization z account ID, host ID/key fingerprint, scope, credential family, expires/revoked. Użytkownik widzi go na liście urządzeń/hostów. Tymczasowa sesja enrollment jest zamykana po potwierdzonym zakończeniu; token nie zostaje stałym credentialem hosta.
7. Host zapisuje credential w wybranym backendzie sekretów, potwierdza registration i może publikować wyłącznie lokalnie zatwierdzone workspace’y.

Enrollment ma trwały, wygasający rekord serwerowy wiążący `enrollment_id`, client class, konto po approval, host ID, public key/fingerprint i **konkretną wydaną bootstrap session**. Powiązanie klucza powstaje przed approval i jest niezmienne. Przy exchange host podpisuje jednorazowy challenge zawierający enrollment ID, host ID, fingerprint, audience i expiry; backend sprawdza proof-of-possession i atomowo zużywa enrollment. Obca sesja tego samego konta, podmieniony klucz, ponowne użycie challenge lub inny client class są odrzucane. Wymaga to nowej integracji walidacji `/device/code`, `/device/token` i hooków, a nie dodania pól do klienta.

Utracona odpowiedź exchange nie tworzy nowej rodziny credentials przez zwykły retry. Ten sam operation ID i dowód klucza pozwalają w krótkim oknie odzyskać tę samą zabezpieczoną odpowiedź; po potwierdzeniu zapisu zamykamy bootstrap session. Po expiry recovery nowy enrollment odwołuje niepotwierdzony wynik. Dokładny mechanizm szyfrowania/retencji tej krótkiej odpowiedzi jest deliverable S0.4, z testem crash przed i po zapisie secret store.

Zmiany wymagają także `auth-frontend`: rozróżnienia „logujesz aplikację desktopową” i „upoważniasz host działający w tle”, bez dowolnych callbacków, redirectów i host names interpretowanych jako HTML. Standardowe client ID rozróżnia flow, nie stanowi sekretu ani samodzielnego zabezpieczenia.

### Czas życia i odnawianie

Proponowany punkt startowy: host access credential ważny 5 minut; losowy, rotowany refresh credential z maksymalnie 90-dniowym idle expiry, odnawianym przy regularnym użyciu, oraz administracyjnym revoke. Dzięki temu działający host nie wymaga interakcji co tydzień, ale długo nieużywany musi zalogować się ponownie. Ostateczne parametry potwierdzić w etapie 0 i account UI.

Refresh token jest ograniczony do host ID/authorization i audience Remote; nie daje dostępu do browser cookies ani ogólnych operacji konta. Backend trzyma hash tokena, numer rotacji/family i stan revoke. Jeden aktor hosta wykonuje odnowienie; zapis nowego credentialu musi być crash-safe.

Utrata odpowiedzi podczas rotacji wymaga nowego, ściśle ograniczonego mechanizmu odzyskania tej samej rotacji: jednorazowy rotation request ID, krótka zabezpieczona odpowiedź recovery związana z tym samym credentialem i proof-of-possession host key, bez wydawania nieograniczonych kolejnych refresh tokenów. Replay spoza tego okna lub konflikt rodziny odwołuje authorization. Istniejący flow mobile wykrywa reuse, ale nie implementuje tego recovery; bezpośrednie skopiowanie go może wylogować host po utracie odpowiedzi. To jawny kontrakt do implementacji i testów, nie funkcja gwarantowana przez sam plugin.

Host pracujący offline nie może przedłużać sobie dostępu zdalnego. Network failure daje stan retry/backoff; explicit 401/revoke zatrzymuje Remote i wymaga reauth. Nie usuwamy prawidłowego sekretu przy przejściowej awarii identity. Clock skew diagnozujemy; lokalne deadlines mierzymy monotonicznie.

## Polityka Share remotely

Jedno polecenie `workspace.share` jest dostępne z desktopu A i lokalnego TUI. Zapisuje:

- account ID i host installation;
- konkretny workspace ID, epoch i root identity;
- publikowane typy: `terminal`;
- zestaw możliwości workspace’u;
- policy `owner-account` albo opcjonalne `manual-device-approval`;
- czas i wersję świadomej zgody.

Domyślnie `owner-account`: dowolny aktualnie zalogowany klient **tego samego konta** może poprosić o grant, a host zatwierdza go według tej polityki. Odpowiada to obecnemu prostemu flow Share remotely. Nie wymagamy dodatkowego promptu w TUI przy każdym refreshu przeglądarki. Użytkownik może odwołać konkretny consumer, sesję konta albo całe udostępnienie.

Opcjonalny tryb ręczny nie jest wymagany do podstawowego działania. Nowy consumer czeka w TUI/desktopie A na akceptację. Zgodnie z jawną decyzją użytkownika z tej sesji identity okna przeglądarki może przetrwać odświeżenie w IndexedDB (ADR-18). Seed identity jest szyfrowany lokalnym, nieeksportowalnym kluczem AES-GCM i związany z kontem, autoryzacją/sesją konsumenta oraz konkretnym oknem. Nie daje to nowego uprawnienia: powrót nadal wymaga bieżącego admission i świeżego kanału. Logout i potwierdzone revoke usuwają właściwą lokalną identity; błąd storage blokuje jej użycie. Nie utrwalamy kluczy kanału Noise, grantów, tickets ani odszyfrowanych treści Remote.

Unshare i ponowne share tworzą nową workspace epoch. Stare granty i pending pairing nigdy nie odzyskują ważności. Zmiana root również wymaga nowej epoki i ponownej zgody.

## Capabilities grantu v3

| Capability | Co pozwala |
| --- | --- |
| `workspace.read` | Nazwa i terminalowa struktura danego workspace’u |
| `terminal.observe` | Snapshot/output jego terminali |
| `terminal.control` | Claim lease i input/resize |
| `terminal.manage` | Tworzenie, split, rename, move, close/restart terminali |
| `files.read` | Explorer, stat, podgląd i wyszukiwanie nazw |
| `files.write` | Create/mkdir/rename/remove w obrębie root |
| `git.read` | Status/diff/history |
| `git.write` | Stage/unstage/commit |
| `git.network` | Fetch/ff-only pull/push przy credentials hosta |
| `git.execute` | Opcjonalne pełne wykonanie kodu repo w mutacjach Git, po osobnej lokalnej zgodzie; nie jest domyślną capability |

`workspace.read` jest warunkiem pozostałych operacji. Control wymaga observe; manage również wymaga observe i jest **uprawnieniem wykonania shella**, bo create/restart wykonują startup scripts, mimo braku `terminal.control`. `files.write` wymaga `files.read`; `git.write` wymaga `git.read`; `git.network` wymaga `git.read`, a pull dodatkowo `git.write`. Backend odrzuca niepoprawne kombinacje, nie dopisuje cicho brakujących uprawnień. `terminal.manage` nie daje prawa zmiany hostowych shell profiles/env przez RPC. Macierz [09](09-kontrakty-i-stany.md) określa warunki per metoda.

Grant control-with-workspace-tools domyślnie zawiera podstawowe możliwości powyżej **z wyjątkiem `git.execute`**, po nowej zgodzie. `git.execute` wymaga co najmniej `git.read` oraz write/network dla konkretnej mutacji; samo nie nadaje nowej metody. Observe może dostać wyłącznie read capabilities wybrane w polityce, nigdy `git.execute`. Brak `terminal.manage` nie pozwala utworzyć terminala przez side effect file/Git API. W przyszłości pełny file editor będzie wymagał określenia nowych operacji i ich semantyki, nawet jeśli ma wspólną capability zapisu.

Zgoda na konfigurację repo i `git.execute` to odrębne warunki. Grant bez execute nie uruchamia helpera zależnego od modyfikowalnego worktree, nawet przy niezmienionym fingerprint config/attributes. Grant z execute jawnie dopuszcza pełne wykonanie kodu repo, w tym jego późniejszych wersji. Ograniczona ścieżka może używać tylko zakwalifikowanych host-managed credential/transport helpers niezależnych od danych wykonywalnych kontrolowanych przez File/Git API; szczegóły i testy w [04](04-protokol-workspace.md).

Podpis obejmuje posortowany/canonical capability set, account/host/consumer keys, nonce, grant ID/revision, workspace ID/epoch, host access epoch, runtime generation, expiry i wersję. Nowy format nie interpretuje starego `permissions: control` jako wszystkich powyższych uprawnień.

Capability jest ograniczeniem produktu/API. Przy pełnym terminal.control nie stanowi izolacji przed wykonaniem przez shell podobnej operacji plikowej/Git z prawami OS. Observe bez control jest odmiennym rzeczywistym poziomem dostępu.

## Logout i revocation: jednoznaczne efekty

| Działanie | Efekt docelowy |
| --- | --- |
| Logout WWW/mobile/desktop B jako konsumenta | Odwołanie jego sesji, grantów i kanałów; host A i inni klienci pracują |
| Zwykły logout strony konta użytej do enrollment | Nie usuwa wcześniej zatwierdzonego osobnego host authorization |
| `lomiremote logout` / „Revoke this host” | Odwołanie host authorization, wszystkich remote grants, local fence; lokalne PTY mogą działać |
| „Sign out” w desktopie A zarządzającym tym hostem | Bezpieczna akcja domyślna odwołuje także powiązane lokalne host authorization; UI informuje o zatrzymaniu local sharing |
| „Sign out of all devices”, blokada/usunięcie konta | Wszystkie consumer i host authorizations tracą ważność |
| Unshare workspace’u | Natychmiastowy fence tylko tego workspace’u, nowe epoch, usunięcie publikacji |
| Revoke grant / attachment key | Odcina wskazany grant/klucz; ważna sesja konta może nadal otrzymać grant dla nowej identity zgodnie z owner-account |
| Revoke consumer authorization/session | Trwale odcina nadrzędną sesję i wszystkie jej klucze/okna; refresh strony nie przywraca dostępu bez nowego loginu |

Zamknięcie GUI nie jest logout. Desktop może pokazać osobne świadome „Disconnect desktop, keep host signed in”, jeśli produkt potrzebuje pozostawienia usługi; nie jest to cicha domyślna ścieżka Sign out. Poświadczenia hosta nie są kopią desktop tokena.

UI „Usuń dostęp urządzenia/sesji” używa nadrzędnego revoke, nie tylko ephemeral browser key. Nowe okno ani refresh nie odwołują innych zdrowych attachments tej samej sesji. Sesja konta, consumer authorization i identity kryptograficzna okna to różne poziomy; limity obowiązują na każdym z nich.

Logout hosta i unshare najpierw zapisują lokalny trwały fence/tombstone oraz nową epokę w transakcji z outboxem, dopiero potem próbują revoke cloud. Po offline logout restart nadal blokuje sharing. Ponowny login nie publikuje automatycznie wcześniej odwołanych workspace’ów; wymaga ponownej zgody. Zwykła utrata sieci/freshness jest stanem przejściowym: można wznowić nadal ważną zgodę po świeżej autoryzacji. Błędu sieci nie zamieniamy w trwały logout.

### Egzekwowanie revocation

Host utrzymuje krótki authorization freshness deadline i lokalny generation fence. Brak potwierdzenia ważności w ustalonym budżecie (cel: najwyżej 5 s dla zdalnych writerów po utracie centralnej kontroli) blokuje nowe input/mutacje. Istniejące relay freshness jest dodatkowym zabezpieczeniem, nie jedynym wykonawcą polityki. Testy mierzą czas end-to-end, uwzględniając kolejki i request timeout.

Każda operacja sprawdza grant, capability, epochs i deadline przy przyjęciu oraz tuż przed efektem. Przy revoke czyścimy oczekujący input i cancelujemy niewykonane operacje. Rozpoczęty syscall lub wysłany `git push` może już mieć skutek; revoke go nie odwraca. Długie subprocessy otrzymują bezpieczne cancellation, a wynik może być `outcome_unknown`. Shell uruchomiony wcześniej przez legalny input nadal może pracować — cofnięcie dostępu nie jest cofnięciem historii poleceń.

## Sekrety i unattended boot

| Kontekst | Polityka |
| --- | --- |
| macOS/Windows po loginie | Backend OS dostępny dla dokładnego użytkownika; locked storage zatrzymuje Remote |
| Windows SCM | DPAPI user scope właściwego konta usługi, bez UI (`CRYPTPROTECT_UI_FORBIDDEN`); enrollment i zapis w tym kontekście. `CRYPTPROTECT_LOCAL_MACHINE` nie zastępuje izolacji konta |
| Linux z działającym Secret Service | Keyring, jeśli rzeczywiście dostępny po wybranym starcie |
| Linux headless / macOS daemon bez keychain | Jawnie wybrany backend `protected-file`, albo kwalifikowany provider system credentials, jeśli dostępny |

`protected-file` to świadomy tryb serwerowy: katalog 0700 i plik 0600 na Unix, właściciel = konto hosta, brak symlinków, atomic writes, kontrolowane backupy. **Nie nazywamy go szyfrowanym magazynem**. Chroni przez prawa OS; administrator hosta i posiadacz niezabezpieczonej kopii dysku może odczytać credential. Jest wybierany jawnie w kreatorze headless, nigdy jako automatyczny fallback po awarii keyring. Sekrety istniejących Chat/AI pozostają w dotychczasowych magazynach i nie są migrowane do tego backendu.

Opcjonalny systemd encrypted credentials kwalifikujemy dla konkretnych wersji/systemów. Nie szyfrujemy pliku kluczem zapisanym obok i nie reklamujemy tego jako ochrony. Wymaganie hasła przy każdym boot jest poprawną alternatywą tylko wtedy, gdy użytkownik wybrał tryb wymagający odblokowania, nie obiecaną usługą bezobsługową.

Klucze prywatne/refresh tokeny nie trafiają do SQLite domeny, logów, argv, URL ani telemetry. Rotation ma atomic secret store update i recovery journal bez plaintext secretów. Klon profilu/backup może sklonować host identity; restore wymaga jawnego fence/re-enrollment, nie dwóch aktywnych hostów z jednym kluczem.

## Lokalne IPC

Unix: prywatny runtime dir, socket z ograniczonymi prawami, sprawdzenie peer UID, owner/permissions katalogu, ochrona przed podmianą symlinkiem i blokada instancji. Windows: named pipe z jawnym DACL dla właściwego SID/operatora, odrzucenie remote pipe clients, kontrola tokena peer i brak szerokich domyślnych ACL. [Microsoft: Named Pipe Security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights).

Po połączeniu jest handshake IPC: wersja, role i krótki challenge związany z prywatnym discovery credential. Nazwa pipe/socket nie jest sekretem. Endpoint nie jest dostępny przez HTTP na `0.0.0.0`; frontend browser nie dostaje local admin API. Tauri zachowuje kontrolę trusted caller i nie daje uprawnień child browser webviews.

Proces tego samego konta OS jest w granicy zaufania lokalnego administratora profilu; nie udajemy izolacji od złośliwego procesu, który może czytać jego pliki i debugować hosta. Limity/validation obowiązują mimo poprawnego peer UID.

## Dystrybucja i aktualizacje

Wersja produkcyjna używa podpisanych targetów i metadanych aktualizacji z rootem zaufania, expiry, version/rollback protection i procedurą rotacji kluczy. Preferowany model to TUF; wybór biblioteki Rust i spakowanie bootstrapu jest zadaniem etapu 0. Nie implementujemy własnego protokołu podpisów zamiast gotowego modelu zagrożeń. [TUF: Security](https://theupdateframework.io/docs/security/).

Skrypty mogą dostarczyć przypięty hashem Rust bootstrap verifier, a ten weryfikuje metadane/target aplikacji względem dołączonego root. Hash bootstrapu jest wpisany w konkretne wydanie skryptu, nie pobierany jako dowolny `latest.sha256`. To nadal dziedziczy zaufanie pierwszego skryptu opisane w instalacji; działa bez Cargo/Node na urządzeniu użytkownika. Paczki macOS mają Developer ID/notarization, Windows Authenticode, a Linux podpisane metadane i artefakty.

Zaufane wersje metadanych TUF są trwałym stanem instalacji, chronionym ACL i zachowywanym między aktualizacjami. `--version` wybiera tylko target dozwolony przez bieżące poprawne metadane i politykę wersji aplikacji; nie omija expiry/antirollback. Recovery może wskazać starszą aplikację w nowych podpisanych metadanych, jeśli schema na to pozwala. Reset zaufania po purge/reinstalacji jest osobną jawną operacją z aktualnym rootem, nie obietnicą zachowania antirollback po usunięciu całego lokalnego stanu zaufania.

Aktualizacja jest domyślnie sprawdzana, ale nie instalowana w tle podczas pracy shelli. Procedura: stage i verify → sprawdź aktywne sesje/operacje i zgodę na ich zakończenie → quiesce → backup SQLite przez backup API → migracja → restart → health check → potwierdzenie wydania. Jeżeli są aktywne sesje, CLI wymaga świadomej opcji zakończenia zamiast ich cichej utraty.

Rollback binarium jest możliwy tylko przy zgodności schematu. W innym przypadku zatrzymanemu hostowi przywracamy backup domeny, zachowując monotoniczny stan zaufania aktualizacji i najnowszy poprawny stan rotacji sekretów. **Nie cofamy refresh tokenów ani epok do wartości z backupu**. Gdy zgodności credentials nie da się dowieść, wykonujemy revoke/re-enrollment i nowe epoki przed publikacją. Stare granty nie odżywają. Recovery kluczy autoryzacji i backup domeny to osobne obszary; [10](10-operacje-i-weryfikacja.md) opisuje procedurę. Zła migracja nie może uruchomić starego binarium na nowej bazie i nadpisać danych.

Usługa nie może uruchamiać podwyższonymi prawami launcherów/paczek zapisywalnych przez nieuprawnione konto. Podwyższenie przy instalacji boot mode służy wyłącznie rejestracji usługi i ACL, nie codziennemu wykonaniu shella jako administrator.

Uninstall zatrzymuje usługę, odwołuje authorization, usuwa rejestrację i binaria. Brak sieci daje zapamiętaną potrzebę revoke oraz instrukcję odwołania hosta z konta. Dane/projekty nie są usuwane; `--purge` dotyczy tylko wskazanych danych Lomi Remote i nie usuwa workspace roots. Logi/audit rejestrują typ operacji, actor ID, operation ID i wynik, bez treści plików/terminala/sekretów. Retencja jest ograniczona i konfigurowalna.

Punkt startowy retencji diagnostyki: 14 dni i maksymalnie 128 MiB na profil, z rotacją i wcześniejszym usuwaniem po osiągnięciu budżetu. Receipts zapisują hash wejścia i minimalny wynik mutacji, np. utworzone UUID lub commit ID; odczyty plików, snapshoty i pełne parametry zawierające treść nie są trwałym cache w bazie. Baza, jej WAL i backupy dziedziczą prywatne uprawnienia katalogu danych.
