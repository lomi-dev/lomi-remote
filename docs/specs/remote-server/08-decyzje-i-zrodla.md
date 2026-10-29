# 08 — Decyzje architektoniczne i źródła

Źródła sprawdzono 18.10.2026. Dokumentacja upstream może opisywać inną wersję niż przypięta w repozytorium. Manifesty istniejących projektów nie są dowodem aktualnej konfiguracji usług produkcyjnych. Plan wymaga osobnej weryfikacji lockfile i API podczas implementacji.

## Skrócony rejestr decyzji

| ID | Decyzja | Uzasadnienie / konsekwencja |
| --- | --- | --- |
| ADR-01 | Jeden zewnętrzny host Rust dla desktopu i CLI | Jedna własność PTY i ta sama implementacja sharing; wymaga przebudowy desktopu |
| ADR-02 | Konta i relay w istniejącym auth-app | Zachowanie sprawdzonej autoryzacji i infrastruktury; brak drugiego backendu logowania |
| ADR-03 | TUI oddzielone od daemonu | Zamknięcie terminala/SSH nie wyłącza hosta; potrzebne lokalne IPC |
| ADR-04 | Nowy wire/API i signed capabilities | Brak kompatybilności pozwala poprawić model; stary control nie rozszerza dostępu |
| ADR-05 | Tylko terminal w shared panel union | Explorer/Git jako workspace services, podglądy lokalne klienta; Android/browser/chat później |
| ADR-06 | Terminal state w Rust, z bramką kwalifikacji | Obecny Node helper nie spełnia wymagań; pełny snapshot jest krytycznym zadaniem |
| ADR-07 | Host authorization niezależny od GUI | Długotrwała usługa bez cotygodniowego loginu; jawne revoke/rotation i osobna lista hostów |
| ADR-08 | Własne konto auto-approval jako domyślny flow | Zachowanie prostoty Share remotely; centralna identity pozostaje w granicy zaufania |
| ADR-09 | Relay-only dla sieciowego v1 | NAT i brak portów przychodzących bez dodatkowego protokołu; koszty relay pozostają operacyjne |
| ADR-10 | Snapshot/runtime state nie jest trwałym procesem | Bezpieczne restart semantics i brak replay komend; aktualizacja może kończyć PTY |
| ADR-11 | Kanoniczne źródła i immutable artefakty | Usunięcie faktycznej rozbieżności dwóch Remote Web i kopii protokołu |
| ADR-12 | Jawny headless secret backend | Obsługa serwera bez GUI przy uczciwej gwarancji storage; brak automatycznego plaintext fallbacku |
| ADR-13 | Host-owned admission także dla lokalnych writerów Tauri | Process-local guard przestaje wystarczać po rozdzieleniu procesów; IPC i bezpieczne recovery aktywnego writera |
| ADR-14 | Consumer session może mieć wiele limitowanych crypto attachments | Dwa okna nie mogą wzajemnie odwoływać grantów; parent revoke odcina wszystkie |
| ADR-15 | Enrollment związany z host key i bootstrap session, z proof-of-possession | Device code sam nie nadaje host principal; jednokrotny exchange i recovery są nowym kontraktem |
| ADR-16 | Restore domeny nie cofa credentials/epochs/TUF trust | Bezpieczny rollback wymaga zgodności albo revoke/re-enrollment; stare granty nie odżywają |
| ADR-17 | Git repository execution wymaga osobnej capability i lokalnej zgody | Config fingerprint nie pinuje kodu helpera; ograniczone granty odmawiają worktree-controlled execution |
| ADR-18 | Identity własnego okna przeglądarki przetrwa refresh w IndexedDB | Jawnie zatwierdzone przez użytkownika w tej sesji: seed szyfrowany lokalnym nieeksportowalnym kluczem AES-GCM, związany z kontem/sesją/oknem; świeży admission i Noise pozostają wymagane, bez trwałego inputu, grantów ani plaintext Remote |
| ADR-19 | Purge usuwa wskazane dane hosta po potwierdzonym revoke i zachowuje tożsamość instalacji oraz TUF | Decyzja implementacyjna dla wymaganego `uninstall --purge`: trwały fence poprzedza cleanup; utrata odpowiedzi i zablokowane sekrety nie stają się potwierdzonym usunięciem |

### ADR-19 — Zakres czyszczenia danych hosta

`uninstall` najpierw utrwala lokalne odwołanie dostępu. Usunięcie programu bez sieci zachowuje stan oczekującego revoke i wyświetla instrukcję odwołania hosta w koncie. Nie oznacza to potwierdzenia revoke przez Cloud. Rejestracja autostartu i binaria mogą zostać usunięte, a dane potrzebne do odwołania pozostają zachowane.

`--purge` dodatkowo czyści wskazane, zmienne dane Lomi Remote: ustawienia hosta i setupu, rejestracje workspace’ów, zgody sharing, zapisany stan terminali oraz poświadczenia Git. Czyszczenie rozpoczyna się dopiero po potwierdzonym odwołaniu autoryzacji, pod wyłączną blokadą profilu i po rozliczeniu writerów. Projekty i ich katalogi, prywatne dane desktopu, edytora, czatu i AI oraz nieznane pliki i rekordy pozostają zachowane.

Purge zachowuje minimalną tożsamość instalacji: HostID, IpcProfileID, klucz podpisujący i jego potwierdzoną inicjalizację, publiczną konfigurację niezbędną do ponownego otwarcia tej tożsamości oraz monotoniczny stan zaufania TUF. Nie tworzy ponownie bazy ze znanym UUID, nie przywraca dawnych credentials ani nie resetuje trust store. Reset zaufania jest osobną jawną operacją opisaną w [05](05-logowanie-bezpieczenstwo.md).

Etapy czyszczenia mają trwały dziennik i wynik. Zablokowany provider sekretów, nierozliczony writer albo niepotwierdzony cleanup daje wynik częściowy lub niepewny; samo uruchomienie procesu i brak pliku nie dowodzą zakończenia. Stan oczekującego revoke nie może blokować ścieżki hosta potrzebnej do uzyskania tego potwierdzenia. To doprecyzowanie zakresu implementacji; nie jest dowodem wykonanego odbioru ani publikacji.

## Zweryfikowane źródła techniczne

### Rust, TUI i terminal

- [Ratatui — installation](https://ratatui.rs/installation/) i [backends](https://ratatui.rs/concepts/backends/): Ratatui jest biblioteką TUI z backendami m.in. Crossterm. W chwili sprawdzania dokumentacja wskazuje linię 0.30.2, Crossterm 0.29 i MSRV 1.88. Dokładne dependency features sprawdzamy przy pinowaniu.
- [Ratatui — panic hooks](https://ratatui.rs/examples/apps/panic/): aktualny mechanizm inicjalizacji ma wsparcie przywracania terminala; stary recipe wymagający wyłącznie własnego hooka nie jest kompletną instrukcją dla wszystkich wersji.
- [portable-pty 0.9.0](https://docs.rs/portable-pty/0.9.0/portable_pty/): cross-platform interfejs PTY, już używany w projekcie; nie dowodzi działania wszystkich trybów usług.
- [Microsoft — pseudoconsoles](https://learn.microsoft.com/en-us/windows/console/pseudoconsoles): ConPTY zapewnia hostowanie aplikacji konsolowych i strumienie komunikacji; translacja konsoli Windows wymaga testów, nie utożsamienia z Unix PTY.
- [alacritty_terminal](https://docs.rs/alacritty_terminal/latest/alacritty_terminal/): model grid/terminala do oceny w spiku; dokumentacja nie gwarantuje eksportu snapshotu zgodnego z xterm Lomi.
- [vt100](https://docs.rs/vt100/latest/vt100/) i [Screen](https://docs.rs/vt100/latest/vt100/struct.Screen.html): model ekranu i snapshot/diff sequences, ale bez gwarancji zgodności całego produktu.
- [vte — README](https://github.com/alacritty/vte): parser nie przypisuje pełnej semantyki terminala; nie zastępuje samodzielnie emulatora.

### Start i zarządzanie usługą

- [systemd loginctl — enable-linger](https://www.freedesktop.org/software/systemd/man/latest/loginctl.html): linger uruchamia user manager przy boot i utrzymuje po logout; jednostkę trzeba dodatkowo skonfigurować/włączyć. Dostępność/uprawnienia zależą od systemu.
- [Apple — Creating Launch Daemons and Agents](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html): różnica między daemonem i agentem oraz konfiguracja launchd.
- [Apple — updating helper executables](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos): aktualne mechanizmy autoryzacji helperów należy brać pod uwagę przy integracji z desktopem.
- [Apple DTS — GUI session before login](https://developer.apple.com/forums/thread/775067): brak wspieranego sposobu tworzenia zwykłej sesji GUI użytkownika przed loginem; headless host nie może jej zakładać.
- [Apple Platform Security — FileVault](https://support.apple.com/en-ca/guide/security/sec8447f5049/web): na Apple silicon/macOS 26 opisano SSH unlock po restarcie przy spełnieniu warunków; nadal jest to odblokowanie, nie gwarancja automatycznej dostępności plików przed nim.
- [Microsoft — interactive services](https://learn.microsoft.com/en-us/windows/win32/services/interactive-services): izolacja usług i session 0; TUI nie powinno działać w procesie SCM.
- [Microsoft — service user accounts](https://learn.microsoft.com/en-us/windows/win32/services/service-user-accounts): konto usługi i jego uprawnienia wpływają na dostęp do systemu i zasobów.
- [Microsoft — Services and Redirected Drives](https://learn.microsoft.com/en-us/windows/win32/services/services-and-redirected-drives): mapowania dysków należą do sesji logowania; usługa nie przejmuje mapowań innej sesji.
- [Microsoft — CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw) i [CreateEnvironmentBlock](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createenvironmentblock): utworzenie procesu z cudzym tokenem nie zastępuje ładowania profilu/środowiska.
- [Microsoft — boot trigger](https://learn.microsoft.com/en-us/windows/win32/taskschd/boot-trigger-example--scripting-): Task Scheduler ma różne typy wyzwalaczy; logon trigger i boot trigger to różne konfiguracje.
- [windows-service](https://docs.rs/windows-service/latest/windows_service/): runtime dispatcher/control handler/status dla prawdziwej usługi SCM.
- [service-manager](https://docs.rs/service-manager/latest/service_manager/): pomoc w rejestracji usług różnych OS; wsparcie user-level i szczegóły backendów nie są identyczne.

### Konta, IPC i aktualizacje

- [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628): device authorization dla urządzeń bez wygodnej przeglądarki/input; kody, polling, `slow_down` i expiry.
- [Better Auth — Device Authorization](https://better-auth.com/docs/plugins/device-authorization): istniejący plugin jest fundamentem flow; samodzielnie wydaje token sesji Better Auth. Nie wynika z niego nowy model długotrwałych host credentials.
- [Better Auth v1.7.6 — routes.ts](https://github.com/better-auth/better-auth/blob/v1.7.6/packages/better-auth/src/plugins/device-authorization/routes.ts): wersjonowany kod `/device/token` tworzy zwykłą sesję; scope/client ID nie ustanawia proof-of-possession host key. Nowy binding opisany w planie jest projektem Lomi.
- [Microsoft — Named Pipe Security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights): kontrola DACL i uprawnień jest konieczna; domyślnego deskryptora nie uznajemy za wystarczający.
- [Microsoft — CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata): DPAPI user scope/no UI i machine scope mają różne granice dostępu; blob machine scope nie jest izolacją pojedynczego konta.
- [Git — configuration](https://git-scm.com/docs/git-config): hooks, fsmonitor, diff/textconv i credential helpers mają własną konfigurację i mogą uruchamiać procesy; ograniczenia zdalnych operacji wymagają jawnej polityki oraz testów.
- [Apple — Developer ID](https://developer.apple.com/developer-id/) oraz [Microsoft — SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool): platformowe podpisy binariów są oddzielne od całej polityki aktualizacji.
- [The Update Framework — security](https://theupdateframework.io/docs/security/): model zaufania, podpisane metadane i zagrożenia rollback/freeze/key compromise uzasadniają plan signed release/update.
- [TUF — specification, aktualizacja metadata](https://theupdateframework.github.io/specification/latest/): zaufany stan i kolejne wersje metadanych należy zachowywać; wybór starszego targetu w nowych metadanych nie jest cofnięciem stanu zaufania.

## Źródła lokalne i ograniczenia tej analizy

Dokładne linki do implementacji znajdują się w [analizie stanu obecnego](01-obecny-system.md). Szczególnie istotne są:

- deklaracje zależności: [`lomi/src-tauri/Cargo.toml`](../lomi/src-tauri/Cargo.toml), [`auth-app/package.json`](../auth-app/package.json), [`remote-web/package.json`](../remote-web/package.json), [`mobile-app/package.json`](../mobile-app/package.json);
- niezmienniki domeny i lifecycle: [`lomi/LOMI.md`](../lomi/LOMI.md);
- kwalifikacja kryptografii: [`lomi-remote-crypto/README.md`](../lomi/src-tauri/crates/lomi-remote-crypto/README.md);
- dokumentacja relay i jego ograniczeń: [`relay/README.md`](../auth-app/src/remote/relay/README.md);
- obecny mobile/web flow i historyczne wyniki prób: [`remote-web-parity.md`](../mobile-app/docs/remote-web-parity.md) oraz [`remote-web/README.md`](../remote-web/README.md).

Analiza była read-only względem aplikacji. Nie uruchamiano migracji, buildów, instalatorów, urządzeń, produkcyjnych API ani testów funkcjonalnych. Nie można na jej podstawie twierdzić, że docelowy Rust snapshot, Windows SCM czy nowe principals już działają. Właśnie dlatego plan zawiera konkretne spiki i warunki odbioru zamiast usuwać obecne bramki kwalifikacji.

Rozszerzony audyt i rewizje checkoutów są w [AUDYT.md](AUDYT.md). Nowe wymagania i specyfikację kontraktów łączą [00](00-cel-i-wymagania.md) i [09](09-kontrakty-i-stany.md), a wymagane dowody oraz procedury operacyjne opisuje [10](10-operacje-i-weryfikacja.md).
