# 03 — Instalacja, pierwsze uruchomienie, TUI i usługa

Wszystkie komendy i adresy instalatorów w tym dokumencie są **projektem interfejsu**, nie informacją o już opublikowanych endpointach.

## Instalacja jednym poleceniem

Linux (interfejs dystrybucji; publikacja pozostaje osobnym krokiem):

```sh
curl -fsSL https://lomi.dev/server/install.sh | sh
lomiremote
```

Windows:

```powershell
powershell -ExecutionPolicy Bypass -Command "irm https://lomi.dev/server/install.ps1 | iex"
lomiremote
```

Na macOS wszystkie tryby hosta wymagają podpisanego obrazu i administratorowego
custodiana terminali. Po pobraniu i zweryfikowaniu paczki instalator przyjmuje
`sudo ./install.sh admin-install KONTO manual|login|boot`, z jednym wybranym
trybem. Instalacja bez konta wskazuje tę jawną ścieżkę przed zmianami na dysku.
Po instalacji wypisuje dokładne polecenie kreatora dla wybranego konta, profilu
i trybu. Nie uruchamia kreatora przez stdin instalatora.

Instalator jest nieinteraktywnym bootstrapem: rozpoznaje OS/architekturę, pobiera gotową paczkę, weryfikuje ją, instaluje użytkownikowi i podaje następny krok. **Nie uruchamia kreatora przez stdin zajęte potokiem**, nie loguje konta i nie udostępnia katalogu. Jeśli aktualny shell nie widzi nowego PATH, wypisuje pełną ścieżkę do programu i instrukcję dla nowej sesji. Proces PowerShell nie może zmienić środowiska swojego procesu nadrzędnego.

Na VPS, gdzie instalator wywołano jako root, setup nie uruchamia domyślnie shella zdalnego jako root. Prowadzi do utworzenia/wyboru dedykowanego konta i sprawdzenia dostępu do workspace’u; nie przejmuje arbitralnie plików z `/root` przez zmianę właściciela. Zwykła instalacja użytkownika pozostaje bez podwyższonych praw.

Dla automatyzacji udostępniamy również pobranie skryptu do pliku i parametry `--version`, `--install-dir`, `--no-path`. `--version` przypina wersję zweryfikowanej paczki; inna wartość wymaga pobrania właściwego instalatora autoryzowanym kanałem. Zgodność wersji sprawdzamy również w podpisanych metadanych celu przed aktywacją. Instalator nie zmienia PATH ani plików shella; `--no-path` potwierdza tę politykę, a pełne polecenie działa także w nowej sesji. Skrypt sh ma być rzeczywiście zgodny z POSIX sh. Błędy pobierania, brak uprawnień, nieznany target i błędny podpis kończą instalację bez nadpisania poprzedniej wersji.

### Sekwencja instalatora

1. Rozpoznać platformę, CPU i ABI. Nie uruchamiać niezgodnego binarium ani nie kompilować Cargo na urządzeniu użytkownika.
2. Wybrać wersję z metadanych wydania. Obsługiwać pin wersji i kanał stable; brak automatycznego przejścia na prerelease.
3. Pobrać do prywatnego katalogu tymczasowego manifest, paczkę i podpisy. Ograniczyć rozmiar, czas i przekierowania do dozwolonych originów.
4. Zweryfikować podpisane metadane i hash paczki. SHA-256 pobrany z tego samego niezaufanego źródła nie zastępuje podpisu.
5. Bezpiecznie rozpakować: bez absolute paths, `..`, wyjścia przez symlink i zapisu poza staging.
6. Opublikować wersjonowany katalog, następnie atomowo przełączyć aktywny launcher/pointer. Nie podmieniać w miejscu pracującego EXE Windows.
7. Dodać PATH w zakresie użytkownika albo wypisać dokładną instrukcję. Zachować istniejące wpisy i konfigurację shelli.
8. Sprawdzić `lomiremote version` i poinformować, że usługę oraz workspace konfiguruje pierwsze uruchomienie.

Zaufanie do pierwszego skryptu pochodzi z HTTPS/domeny i sposobu jego dystrybucji. Skrypt dostarczony przez przejętą domenę może usunąć własną weryfikację. Oferujemy dodatkowo podpisane paczki i fingerprint/root metadata w repozytorium; nie opisujemy `curl | sh` jako niezależnego zabezpieczenia przed przejęciem kanału instalacji. Szczegóły aktualizacji w [bezpieczeństwie](05-logowanie-bezpieczenstwo.md).

## Pierwsze `lomiremote`: dokładny kreator

1. **Sprawdzenie instalacji.** Terminal interaktywny, wersja, data directory, existing host, prawa dostępu, shell i połączenie z platformą. Przy istniejącej konfiguracji od razu dashboard. Bez TTY wypisać pomoc i kod błędu zamiast zawisnąć w TUI.
2. **Autostart jako pierwszy wybór użytkownika.** „Uruchamiaj po zalogowaniu”, „Uruchamiaj po starcie bez logowania, jeśli system na to pozwala”, „Uruchamiaj ręcznie”. TUI pokazuje konkretny mechanizm OS, wymagane uprawnienia i konto procesu. To na razie plan konfiguracji; nie uruchamiamy jeszcze publicznego hosta.
3. **Tożsamość hosta.** Domyślna nazwa z hostname, możliwość zmiany, wygenerowanie trwałego klucza i host ID. Wybór storage sekretów zgodny z trybem startu.
4. **Logowanie konta.** Krótki kod i adres weryfikacji; otwarcie przeglądarki, jeśli jest dostępna. Na SSH można dokończyć logowanie w telefonie. Device code zostaje w RAM, nie w logu. Bez internetu można zapisać lokalny draft, ale Remote pozostaje wyłączone do dokończenia logowania.
5. **Pierwszy workspace.** Nazwa + lokalizacja na tej maszynie. Domyślnie bieżący katalog, nie cały home. Istniejący katalog trzeba odczytać i zweryfikować; utworzenie brakującego wymaga jawnego wyboru. Root `/`, `C:\` i katalog sekretów hosta nie są domyślnymi workspace’ami. Repo Git wykrywamy, nie inicjalizujemy automatycznie.
6. **Shell.** Wybór wykrytego profilu, domyślnego CWD = root i jawnych zmiennych środowiskowych. Sprawdzenie, czy profil działa pod kontem usługi. Nie kopiujemy całego env procesu instalatora ani sesji przeglądarki.
7. **Zakres udostępnienia.** „Udostępnij temu kontu terminale i narzędzia workspace’u” albo „Zachowaj lokalnie”. TUI wyjaśnia, że terminal działa z prawami konta OS; lista capabilities obejmuje Explorer, Git i zarządzanie terminalami. Domyślna polityka konta jest wspólna z Share remotely desktopu.
8. **Podsumowanie i commit.** Atomowo zapisać lokalną konfigurację/politykę i bazę. Zarejestrować host authorization, uruchomić usługę, sprawdzić IPC i autoryzację. Dopiero wtedy opublikować workspace. Błąd instalacji usługi zachowuje konfigurację i pokazuje stan „service setup failed”; użytkownik może uruchomić foreground.
9. **Dashboard.** Status hosta, workspace, adres Remote Web i instrukcja wyboru tego samego workspace’u w desktopie B/mobile. Nie umieszczamy tokenu dostępu w URL.

Kreator jest wznawialny. Przerwanie przed końcowym commitem nie włącza udostępnienia. Częściowy błąd rejestracji lub instalacji usługi ma zapisany etap naprawy; ponowienie używa tego samego host ID i idempotentnego operation ID. Konta usługi nie zmieniamy po zapisaniu sekretów bez jawnego przeniesienia profilu.

„Commit” kroku 8 nie jest transakcją obejmującą SQLite, cloud i OS service manager. To wznawialna sekwencja `draft → enrolled → local-configured → service-ready → shared`, z trwałym dziennikiem etapów bez sekretów. Publikację dopuszcza dopiero ostatni krok i aktualna zgoda. Błąd po enrollment pozostawia widoczną instalację `setup incomplete`, którą można wznowić albo odwołać; nie tworzy kolejnych host IDs. Dla trybu ręcznego `service-ready` oznacza uruchomiony i sprawdzony daemon bez rejestracji autostartu. Instalacja autostartu nie jest warunkiem używania Remote ręcznie.

## TUI Ratatui

`lomiremote` otwiera pełnoekranowy panel kontrolny podłączony do hosta. TUI **nie musi być stale otwarte**. Domyślnie nie renderuje shelli wewnątrz dashboardu; terminal może być otwierany w osobnym trybie attach po zakończeniu/przywróceniu ekranu TUI. Emulacja terminala nie jest rolą Ratatui.

```text
 Lomi Remote       vX.Y.Z         host: build-server     ● Online
 Account: user@example.com        Start: boot / dedicated user

 Workspaces            | Backend API: connected  Relay: connected
 > api-service   Shared| Clients: desktop B, mobile   Uptime: 2d
   frontend      Local | Path: /srv/projects/api-service
                      | Terminals: 3 running / 1 exited
                      | Access: own account / control + workspace tools

 [Enter] details  [a] add  [s] sharing  [d] devices  [?] help
 [q] close TUI — host keeps running
```

Ekrany: dashboard, workspace details, dodanie/rename/remove workspace, shell profiles, access/devices, service/autostart, logs/doctor i ustawienia. Details pozwala zobaczyć terminale i ich exit state, utworzyć kartę, zatrzymać sesję oraz skopiować bezpieczny adres workspace’u.

Obsługa: pełna klawiatura, widoczny focus, wyszukiwalna lista, wklejanie ścieżek, terminal resize, czytelność 80×24 oraz fallback bez kolorów. Nazwy hostów, plików i logi są traktowane jako niezaufany tekst — bez interpretacji ANSI. Potwierdzenie jest wymagane tylko dla realnej utraty sesji, revoke, usunięcia lub zmiany praw, nie dla wyjścia z TUI.

`q`/Ctrl-C zamyka panel i przywraca terminal, a nie daemon. „Stop host” jest osobną akcją pokazującą liczbę działających sesji. Panic i błędy TUI przywracają raw mode/alternate screen przez mechanizmy zgodnej wersji Ratatui i guardy; daemon pozostaje niezależny. Renderowanie jest event-driven, z ograniczonym odświeżaniem podczas zmian; bez ciągłego 60 FPS w idle.

## Kontrakt CLI

```text
lomiremote                              # TUI / setup przy pierwszym wejściu
lomiremote setup [--non-interactive ...] # jawne parametry + zgoda
lomiremote login                        # rozpoczyna trwały device flow hosta
lomiremote login code                   # jawnie pokazuje bieżący kod i URL
lomiremote login status [--json]
lomiremote logout --confirm             # revoke host authorization, unshare
lomiremote status [--json]
lomiremote doctor [--json]
lomiremote logs [--follow]
lomiremote workspace list [--json]
lomiremote workspace add --name NAME --path PATH
lomiremote workspace share WORKSPACE_ID --confirm # jedyna polityka v1: owner-account
lomiremote workspace unshare WORKSPACE_ID --confirm
lomiremote workspace remove WORKSPACE_ID --confirm
lomiremote workspace removal-status WORKSPACE_ID [--json]
lomiremote terminal list --workspace WORKSPACE_ID
lomiremote terminal create --workspace WORKSPACE_ID --profile PROFILE_ID
lomiremote service install --mode login|boot --account ...
lomiremote service start|stop|restart|status|uninstall
lomiremote daemon start                  # odłączony proces bez autostartu
lomiremote daemon stop --confirm         # kontrolowany shutdown
lomiremote daemon run                    # foreground dla supervisora/debug
lomiremote update --confirm [--version X.Y.Z] [--json]
lomiremote uninstall --confirm [--purge] [--json]
lomiremote maintenance status JOB_ID [--json] # odczyt wyniku przekazanej operacji Windows
lomiremote version
```

CLI używa tego samego IPC i command admission co TUI. Formaty JSON są wersjonowane, stdout zawiera dane, stderr komunikaty. Kody: `0` sukces lub jawnie opisane przyjęcie zadania, `2` błędne argumenty, `3` setup/auth required, `4` daemon unavailable, `5` permission denied, `6` version mismatch, `7` operation uncertain. Powyższe nazwy opcji odpowiadają kontraktowi implementacji; przyjęcie zadania Windows nie jest potwierdzeniem zakończenia, a status nie ponawia mutacji. Globalne `--profile-dir PATH` wybiera istniejący profil. Parametry instalacji usługi i wymagane potwierdzenia są właściwe dla danej platformy.

Nieinteraktywny setup nie przyjmuje refresh tokena przez argv. Używa device flow lub jednokrotnego, ograniczonego bootstrap credential przez chroniony plik/stdin. Nie zapisuje sekretów w shell history. Usunięcie workspace’u usuwa rejestrację, politykę i jego sesje, **nie katalog projektu**. Unshare odcina klientów, ale nie zabija terminali.

## Macierz autostartu

| Platforma | Ręcznie | Po zalogowaniu | Boot bez interaktywnego loginu |
| --- | --- | --- | --- |
| Linux/systemd | Odłączony host lub foreground | Jednostka `systemd --user` | Włączona user unit + linger; preferowane konto dedykowane dla VPS; opcjonalnie system unit z `User=` |
| macOS | Odłączony host | LaunchAgent użytkownika | Osobny LaunchDaemon z `UserName`, uprawnieniami administracyjnymi i dostępnym storage |
| Windows | Odłączony host / foreground | Task Scheduler: logon trigger właściwego SID | Prawdziwa usługa SCM z runtime `windows-service`, pod dedykowanym kontem |

To trzy różne obietnice. User service/LaunchAgent/logon task nie oznacza automatycznie startu przed loginem. Instalacja autostartu jest jawnie wybrana w kreatorze i może wymagać systemowej autoryzacji. Host nie pracuje stale jako root/Administrator/LocalSystem dla wygody.

Linux: wykryć brak systemd/DBus i pokazać instrukcję foreground dla innego supervisora. Linger sprawdzić po konfiguracji i pokazać rzeczywisty stan, nie tylko zamiar. Konto musi mieć dostęp do katalogów, Git i shell profile.

macOS: LaunchDaemon nie ma sesji GUI, schowka, zwykłego SSH agenta ani gwarantowanego dostępu do login keychain. FileVault lub zaszyfrowany home mogą wymagać odblokowania przed dostępem do plików. Nie obiecywać hosta działającego przed odblokowaniem dysku. Nowe możliwości zdalnego odblokowania FileVault nie eliminują tego kroku.

Windows: SCM wymaga raportowania stanów start/stop, obsługi control handler i procesu bez UI. Testować ConPTY, profile PowerShell, UTF-8, konto usługi, DPAPI, Job Objects i stop drzewa procesów w session 0. Nadanie „Log on as a service” i konfiguracja poświadczeń konta odbywa się przez OS; hasła konta nie zapisujemy w TOML. Usługa nie korzysta z mapowań dysków innej sesji logowania, nawet tego samego użytkownika; dla udziałów używać UNC i praw konta usługi. Jeśli adapter tworzy proces pod tokenem innego użytkownika, osobno ładuje profil i buduje środowisko; `CreateProcessAsUser` nie zapewnia tego sam. Nie stosować impersonacji zamiast uruchomienia całego hosta pod wybranym kontem bez osobnego uzasadnienia.

## Lifecycle w praktyce

| Zdarzenie | Efekt |
| --- | --- |
| Zamknięcie TUI lub desktopu | Host, PTY i sharing pozostają według ustawionej polityki |
| Rozłączenie klienta / uśpienie mobile | Lease input wygasa, PTY nadal pracuje |
| Utrata internetu | Lokalne sesje pracują; dostęp zdalny przestaje być autoryzowany; reconnect po odnowieniu kontroli |
| Unshare workspace’u | Natychmiastowy local fence, odwołanie grantów i kanałów; PTY pracuje lokalnie |
| `service stop` | Blokada nowych operacji, flush DB, zakończenie PTY; brak automatycznego restartu po świadomym stop |
| Awaria hosta | Supervisor może restartować; nowy proces oznacza nowe session epochs i utratę żywych PTY |
| Reboot | Start zgodny z trybem autostartu; katalog i karty odtwarzane, procesy nie są kontynuowane |
| Logout konta hosta | Cofnięcie host authorization i remote access; lokalna praca może trwać |

Idle policy hosta: domyślnie `always-on` przy zainstalowanym autostarcie, bez godzinnej pauzy z desktopu. Możliwe `manual` i `pause-remote-after-idle`; pauza dotyczy sieci, nie zabijania terminali. TUI pokazuje stan rzeczywisty i wznowienie. Samo zainstalowanie desktopu nie włącza startu przy boot.

## Pliki konfiguracyjne i diagnostyka

Proponowane lokalizacje:

| OS | Konfiguracja / dane | IPC |
| --- | --- | --- |
| Linux user | `$XDG_CONFIG_HOME/lomiremote`, `$XDG_DATA_HOME/lomiremote` z normalnymi fallbackami XDG | Prywatny podkatalog `$XDG_RUNTIME_DIR`, sprawdzony owner i mode |
| macOS user | `~/Library/Application Support/LomiRemote` | Prywatny krótki runtime path; limit długości Unix socket uwzględniony |
| Windows user | `%LOCALAPPDATA%\LomiRemote` | Named pipe nazwany profilem i SID, z jawnym ACL |
| Dedicated boot profile | Home/data directory właściwego konta usługi | ACL tylko dla uprawnionych operatorów tego profilu |

Config TOML zawiera ustawienia endpointów, logów, idle i service mode, nie sekrety. SQLite trzyma domenę; secret store ma osobne uprawnienia. Config zapisujemy atomowo z numerem wersji. Zmiana endpointu identity/relay wymaga nowego logowania i pinów, nie przenosi poświadczeń do innej domeny.

`doctor` diagnozuje: wersję i zgodność IPC, właściciela profilu, stan usługi i autostartu, clock skew, DNS/TLS/proxy, storage, shella, Git, prawa root, limity i ostatni kod błędu. Export diagnostyki wymaga redakcji tokenów, ścieżek i danych konta. Nie zawiera terminal transcriptów, zawartości plików ani env shelli.
