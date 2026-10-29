# Lomi Remote — plan wspólnego systemu i serwera Rust

**Bieżący stan implementacji:** [szczegółowy raport prac i pozostałego zakresu](STAN-WDROZENIA.md). Zawiera aktualne wyniki, otwarte problemy i kopię rejestru dowodów. Poniższy opis zachowuje kontekst pierwotnego planu po audycie z 18.10.2026; nie jest aktualnym raportem wykonania.

Status: **plan po audycie dokumentacji; implementacja i kwalifikacja pozostają do wykonania**. Data analizy: 18.10.2026. W tym katalogu nie ma jeszcze serwera. Dokumentacja została porównana z kodem `lomi`, `auth-app`, `remote-web`, `mobile-app`, `auth-frontend` i źródłami upstream. Nie zmieniono kodu aplikacji ani działającej infrastruktury. Zakres ustaleń i ograniczenia są w [raporcie audytu](AUDYT.md).

Zacznij od [celu i wymagań](00-cel-i-wymagania.md). Do przekazania zadania agentowi służy gotowy [prompt.md](prompt.md); odsyła do całego planu i wymaga dowodów wykonania kolejnych etapów.

## Rekomendacja

Zbudować **jeden niezależny host Rust**, uruchamiany jako proces w tle. Dystrybuować go jako `lomiremote`; bez argumentów uruchamia TUI Ratatui, natomiast `lomiremote daemon run` uruchamia usługę. Desktop Lomi i TUI sterują tym samym hostem przez lokalne IPC. Desktop, WWW i mobile łączą się z hostem przez wspólny protokół Remote, istniejącą platformę kont i relay Lomi.

Agent wdrażający musi utworzyć **nowe, odrębne repozytorium Git `lomi-remote`** dla implementacji CLI i hosta serwerowego. Docelowy katalog lokalny to `/Users/woro/Documents/Lomi/lomi-remote`; obecny `remote-server` zawiera plan. Nazwa polecenia pozostaje `lomiremote`.

Host jest właścicielem workspace’ów, procesów terminalowych, operacji na plikach i Git. Interfejsy są klientami. **Share remotely w desktopie i udostępnienie przez TUI zapisują tę samą politykę i wywołują tę samą implementację.** Nie powstaje drugi system Remote dla CLI.

Nowy host, obsługa PTY, synchronizacja stanu terminala, TUI, IPC oraz zarządzanie usługą mają działać w Rust, bez Node, Tauri, WebView lub serwera X na maszynie udostępniającej. Istniejące interfejsy zachowują React/TypeScript, a centralny `auth-app` zachowuje Bun/Better Auth/PostgreSQL. Ujednolicenie wymaga wspólnych kontraktów i odpowiedzialności; nie wymaga przepisywania platformy kont na Rust.

## Zakres pierwszego kompletnego wydania

| Obszar | Zachowanie v1 |
| --- | --- |
| Instalacja | Skrypt POSIX i PowerShell pobierający gotowe, zweryfikowane wydanie |
| Pierwsze `lomiremote` | Wybór autostartu → logowanie kodem urządzenia → nazwa i katalog workspace’u → świadome włączenie udostępniania |
| Praca w tle | Niezależna od TUI, okna desktopu i połączenia klienta |
| Terminale | Shell hosta, stdin/stdout, resize, Ctrl-C, reconnect, scrollback, karty, splity, zamykanie |
| Explorer | Lista/drzewo, podgląd tekstu, wyszukiwanie nazw, tworzenie pustych plików i katalogów, rename oraz usuwanie pliku/linku/pustego katalogu z odpowiednimi uprawnieniami |
| Source Control | Status, diff, historia, stage/unstage, commit oraz fetch/pull/push według opisanej polityki poświadczeń i konfliktów |
| Desktop B | Pełnoprawny klient zdalnego workspace’u, nie tylko host |
| WWW / mobile | Te same operacje workspace’u, interfejs dopasowany do urządzenia |
| Nowe okna | Dodatkowe okno klienta na komputerze B; w WWW nowa karta/okno po działaniu użytkownika; mobile dodatkowy widok w nawigacji |
| Typy publikowanych paneli | **Wyłącznie terminale**; nazwy i struktura terminalowych kart/splitów są wspólne |
| Przyszłość | Android, przeglądarka, media, AI i udostępniane edytory jako osobne przyszłe możliwości |

Explorer i Source Control są usługami workspace’u. Podgląd pliku/diffu otwarty na B jest lokalnym widokiem B, nie udostępnionym panelem ani odbiciem edytora na A. V1 nie obejmuje wspólnego edytora, synchronizacji niezapisanych buforów ani współpracy nad tekstem. Operacje plikowe i Git są w tym planie częścią v1, a nie zastąpieniem ich komendami w terminalu.

„Zewnętrzny serwer” oznacza w v1 własną maszynę/VPS z zainstalowanym hostem, korzystającym z platformy kont i relay Lomi. Nie oznacza obowiązku samodzielnego wdrażania całej platformy kont. Pełne self-hosting control plane pozostaje poza pierwszym wydaniem.

## Jak korzystać z planu

0. [Cel, wymagania i słownik](00-cel-i-wymagania.md) — oczekiwany rezultat, zakres i identyfikatory wymagań `REQ-*`.
1. [Obecny system i fakty z kodu](01-obecny-system.md) — co zachować, co przebudować i gdzie.
2. [Architektura, model danych i stack](02-architektura.md) — granice procesów, własność stanu i struktura projektu.
3. [Instalacja, TUI i działanie usługi](03-instalacja-tui-usluga.md) — dokładna ścieżka użytkownika i różnice systemów operacyjnych.
4. [Protokół i działanie workspace’u](04-protokol-workspace.md) — połączenie, terminale, pliki, Git, karty i okna.
5. [Logowanie i bezpieczeństwo](05-logowanie-bezpieczenstwo.md) — tożsamości, zgody, uprawnienia, szyfrowanie i cofanie dostępu.
6. [Przebudowa czterech aplikacji](06-przebudowa-aplikacji.md) — konkretne powierzchnie zmian i przejście na nowy system.
7. [Etapy, testy i kryteria odbioru](07-realizacja-i-odbior.md) — zależności, backlog, ryzyka, estymacja i scenariusze końcowe.
8. [Decyzje i źródła](08-decyzje-i-zrodla.md) — uzasadnienia, źródła zewnętrzne i ograniczenia weryfikacji.
9. [Kontrakty i maszyny stanów](09-kontrakty-i-stany.md) — operacje, uprawnienia, warunki współbieżności i błędy.
10. [Operacje, migracja i dowody weryfikacji](10-operacje-i-weryfikacja.md) — wykonanie cutover, recovery, manifesty i odbiór.

[AUDYT.md](AUDYT.md) dokumentuje wykryte luki i ich poprawki; [prompt.md](prompt.md) zawiera instrukcję wykonawczą. Parametry wstępne, decyzje projektowe i wymagania mają odrębny status opisany w rozdziale 00. „Produkt v1” oznacza zakres wydania; nie jest numerem nowego protokołu.

## Decyzje, które porządkują całość

- Jeden host na profil użytkownika systemowego i instalację; desktop i CLI wykrywają istniejącego właściciela zamiast uruchamiać konkurencyjne hosty.
- Trwała tożsamość hosta jest niezależna od konkretnego okna GUI. Ma odnawialne, odwoływalne upoważnienie do konta.
- Host nawiązuje połączenia wychodzące HTTPS/WSS przez port 443. Nie trzeba wystawiać SSH, portu aplikacji ani publicznego IP hosta.
- W v1 połączenia zdalne przechodzą przez relay; direct/P2P, WebRTC i tunelowanie usług nie są potrzebne do tego zakresu.
- Udostępnienie dotyczy własnego konta Lomi. Domyślna polityka zachowuje dzisiejszy prosty dostęp z innych zalogowanych klientów tego konta. Tryb ręcznej akceptacji może być ustawieniem hosta.
- Uprawnienia terminala, plików, Git i zarządzania kartami są jawne i podpisane. Stary grant terminalowy nie staje się automatycznie grantem do plików.
- Stan workspace’u zmienia host; React nie publikuje już autorytatywnego stanu po fakcie.
- TUI i interfejsy nie są właścicielami procesów. Wyjście z TUI odłącza interfejs; zatrzymanie hosta jest osobną operacją.
- V1 zachowuje działające terminale przy utracie sieci i zamykaniu klientów. **Nie obiecuje zachowania żywego procesu po restarcie właściciela PTY lub całego komputera.**
- Nie utrzymujemy zgodności starego protokołu Remote. Zachowujemy pliki użytkownika, repozytoria, sekrety innych funkcji i lokalne niezapisane dane przez kontrolowany proces przejścia.

## Trzy najważniejsze bramki przed dużą implementacją

1. **Terminal w 100% Rust.** Obecny Remote odtwarza ekran przez Node i `@xterm/headless`. Prototyp Rust z `vt100` nie ma zakwalifikowanego pełnego snapshotu. Trzeba najpierw dowieść poprawnego snapshot + dalszy strumień w używanych klientach xterm.
2. **Prawdziwa wieloplatformowość.** Obecny produkcyjny Remote jest zakwalifikowany na macOS ARM64; osobny prototyp hosta jest Unix-only. Linux bez sesji graficznej i Windows ConPTY pod usługą wymagają rzeczywistych prób.
3. **Jedno źródło kontraktów i wydania.** `auth-app` wdraża dziś własną kopię Remote Web, różną od `remote-web`. Nie można rozszerzać protokołu, dopóki CI nie potrafi potwierdzić pochodzenia wszystkich artefaktów.

Pierwszym zadaniem implementacyjnym powinny być te trzy spiki oraz zamrożenie kontraktów, a nie budowa finalnego TUI. Szczegółowe kryteria i kolejność są w [harmonogramie](07-realizacja-i-odbior.md).
