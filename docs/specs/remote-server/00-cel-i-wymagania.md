# 00 — Cel produktu, wymagania i zasady interpretacji

## Efekt, który chcemy osiągnąć

Użytkownik instaluje Lomi Remote na swoim komputerze lub serwerze, loguje go do konta Lomi i świadomie udostępnia workspace. Następnie z desktopu na drugim komputerze, przeglądarki lub telefonu otwiera ten sam workspace: obserwuje i kontroluje terminale, tworzy karty i splity, przegląda oraz porządkuje pliki i korzysta z Git. Wszystkie te działania wykonuje maszyna udostępniająca. Zamknięcie interfejsu lub SSH nie kończy hosta ani jego terminali.

To jeden system Remote. `Share remotely` w desktopie i udostępnienie w TUI prowadzą do tego samego hosta, identyfikatorów, polityki i protokołu. Nie budujemy niezależnego produktu CLI z osobną listą workspace’ów.

## Status i moc poszczególnych zapisów

Ten katalog jest specyfikacją do realizacji, a nie gotowym serwerem. Audyt dokumentacji nie jest kwalifikacją implementacji. Rozróżniamy:

- **Wymaganie v1:** zachowanie oznaczone `REQ-*`, które musi zostać dostarczone i sprawdzone.
- **Decyzję projektową:** rekomendowany sposób realizacji, np. relay-only lub SQLite. Agent realizuje go, chyba że dowody ze spiku wykażą potrzebę zmiany; wtedy aktualizuje ADR i zależne kontrakty przed dalszym kodowaniem.
- **Parametr wstępny:** limit, czas lub estymację wymagającą pomiaru, a nie udowodnioną wydajność.
- **Bramkę kwalifikacji:** warunek, którego niespełnienie blokuje zależny etap albo deklarowanie wsparcia platformy. Nie wolno ominąć jej ukrytym fallbackiem.
- **Fakt z kodu:** stan sprawdzonych lokalnych checkoutów, nie deklarację o produkcji.

Wymagania poniżej formalizują zakres zastanego planu. Nie oznaczają osobnego zatwierdzenia przez użytkownika kosztu, harmonogramu, publikacji ani zmian produkcyjnych. Bieżące zlecenie obejmuje audyt i poprawę dokumentacji; przyszły agent otrzymuje zadanie implementacji dopiero po uruchomieniu [promptu](prompt.md) w takim kontekście.

W razie rozbieżności: wymagania produktu określają rezultat; [09](09-kontrakty-i-stany.md) precyzuje interfejsy i stany; [02](02-architektura.md)–[06](06-przebudowa-aplikacji.md) określają mechanizmy; [07](07-realizacja-i-odbior.md) oraz [10](10-operacje-i-weryfikacja.md) określają dowody odbioru. Konflikt trzeba poprawić w dokumentach, nie wybierać po cichu wygodniejszej wersji. Fakty o istniejącym kodzie ponownie sprawdza się przed jego zmianą.

## Słownik i role

| Pojęcie | Znaczenie |
| --- | --- |
| Maszyna A / host | Komputer lub VPS wykonujący shelle, operacje plikowe i Git |
| Maszyna B / konsument | Klient zdalnego workspace’u A; może niezależnie hostować własne projekty |
| `lomiremote` | Jedno dystrybuowane narzędzie z trybami CLI, TUI i daemon/service |
| Host installation | Trwały profil hosta, jego klucz i upoważnienie konta |
| Runtime hosta | Konkretny proces; ma generation i wygasający lease, nie jest trwałą instalacją |
| Projekt | Zarejestrowany katalog na A; nie kopia katalogu na B |
| Workspace | Nazwany kontekst projektu, terminalowe karty, sesje i polityka udostępnienia |
| Descriptor terminala | Trwała definicja panelu/profilu; nie żywy proces ani zapis dawnych komend |
| Sesja terminala | Konkretny shell/PTY i epoka; restart tworzy nową sesję |
| Widok / attachment | Lokalny odbiorca danych w oknie/panelu; zamknięcie nie kończy PTY |
| Capability | Podpisana możliwość API, egzekwowana na hoście i przy admission |
| Control plane | Konta, host authorizations, inventory, granty, tickets i revoke |
| Data plane | E2EE: stan workspace’u, terminale, wyniki plików/Git |
| Produkt v1 | Pierwsze kompletne wydanie; używa nowego Remote API/protokołu major 2 i crypto context/grant v3 |

Operator lokalny zarządza instalacją i zgodami z TUI/desktopu A. Konsument działa w granicach grantu. Operator platformy zarządza identity/relay i wydaniami, ale relay nie dostaje kluczy odszyfrowujących workspace. Konto OS hosta pozostaje granicą uprawnień shella.

## Wymagania i ślad do odbioru

| ID | Wymaganie v1 | Główna specyfikacja | Dowód zakończenia |
| --- | --- | --- | --- |
| REQ-01 | Rust host działa bez Node, Tauri, WebView i sesji GUI | 02, 03 | S0.1/S0.2; E1; test czystej maszyny |
| REQ-02 | Desktop i CLI używają jednego właściciela domeny i PTY | 02, 06 | S0.3; E4; jednoczesne TUI + desktop, test drugiego ownera |
| REQ-03 | Host loguje się kodem urządzenia i odnawia niezależne authorization | 05, 06 | S0.4; E2/E3; utrata odpowiedzi rotacji, restart, global revoke |
| REQ-04 | Share/unshare i zakres zgody są takie same w desktopie i TUI | 03, 05 | E3/E4; identyczne IDs/polityka; unshare podczas mutacji |
| REQ-05 | Terminal obsługuje shell A, input, resize, Ctrl-C, snapshot, reconnect i wielu obserwatorów | 04, 09 | S0.1; E1/E3; differential fixtures i slow client |
| REQ-06 | Tworzenie/rename/split/move/close/restart terminali synchronizuje wspólną domenę | 02, 04, 09 | E4/E6; dwaj równocześni klienci i revision conflict |
| REQ-07 | Publikowane panele są wyłącznie terminalowe; prywatne edytory i bufory są chronione | 02, 06 | S0.3; E4; dirty editor podczas remote close |
| REQ-08 | Explorer obsługuje listę, podgląd, szukanie nazw oraz określone mutacje w root A | 04, 09 | E5/E6; traversal, symlink/reparse, konflikty, nazwy nie-UTF-8 |
| REQ-09 | Source Control obsługuje status/diff/historię, stage/unstage/commit/fetch/ff-only pull/push | 04, 05, 09 | S0.3a; E5/E6; izolacja read, guards, credentials i uncertain push |
| REQ-10 | Desktop B, WWW i mobile wykonują ten sam zakres workspace services | 06, 09 | E6; macierz metoda × klient; każdy brak ma blokować deklarację kompletności |
| REQ-11 | Nowe okno/widok klienta nie tworzy drugiego shella | 04, 06 | E4/E6; dwa okna WWW pod jednym cookie i dwa okna desktopu |
| REQ-12 | Zamknięcie klienta/TUI i utrata sieci zachowują PTY; restart hosta jawnie kończy sesję | 02, 03 | E1/E7; SSH disconnect, OS logout, crash, reboot |
| REQ-13 | Cofnięcie uprawnień blokuje kolejne efekty; retry nie powiela niepewnych mutacji/input | 04, 05, 09 | E2/E3/E5; fault injection przed/po efekcie i receipt |
| REQ-14 | Treść terminali, nazwy/root i pliki/Git są E2EE i nie stają się cloud inventory/logami | 04, 05, 06 | E2/E6; inspekcja payloadów/logów/storage; clear po revoke |
| REQ-15 | Instalacja, wybrany autostart, aktualizacja i odinstalowanie mają określony wynik i recovery | 03, 05, 10 | S0.2/S0.6; E7; podpisy, locked EXE, boot bez loginu |
| REQ-16 | Przejście chroni projekty, prywatne dane i sekrety innych funkcji | 06, 10 | E4/E7; próbny import, przerwany import, backup/restore |
| REQ-17 | Kontrakty, crypto i Remote Web mają jedno źródło i odtwarzalne pochodzenie wydania | 02, 06, 10 | S0.5/S0.6; E6/E7; manifest digestów i brak driftu |

`E0`–`E7` oznaczają etapy z [07](07-realizacja-i-odbior.md). Powyższe są kryteriami przyszłych testów, nie raportem ich zaliczenia. Pełny zakres klientów nie może być zastąpiony samym demonstratorem Linux + terminal WWW.

## Zachowanie w podstawowych sytuacjach

1. **Nowa instalacja:** instalator dostarcza zweryfikowane binarium. Kreator wybiera tryb pracy i storage, zatwierdza konto, rejestruje lokalny root i dopiero po świadomej zgodzie publikuje workspace. Samo pobranie programu nie daje dostępu zdalnego.
2. **Desktop A:** zwykły terminal powstaje od początku w hoście. Share remotely zmienia politykę istniejącego zasobu; nie próbuje przenosić działającego PTY między procesami.
3. **Klient B:** po wyborze host/workspace pobiera E2EE metadane i attach. Explorer/Git wykonuje się na A. Folder o podobnej nazwie na B nie uczestniczy w operacji.
4. **Równoczesna praca:** wszyscy widzą wspólny układ terminali, lecz mają własny focus i scroll. Jeden lease pozwala na input i resize. Konflikt zmiany layoutu wymaga odświeżenia domeny.
5. **Awaria sieci:** shell A pracuje dalej. Klient odłącza input, nie przechowuje klawiszy do późniejszego wysłania. Przywrócenie sieci wymaga świeżej autoryzacji/handshake; nie jest ponowną zgodą na wcześniej odwołane sharing.
6. **Restart hosta:** descriptors wracają jako stopped/lost. Obserwator nie uruchamia shella przez samo attach. Uprawniony użytkownik może jawnie uruchomić nowy shell z nową epoką.
7. **Logout/revoke:** operacja odłączenia konta ma trwały lokalny stan blokady. Po restarcie nie wolno samoczynnie wznowić odwołanej publikacji z outboxu.
8. **Błąd operacji:** UI rozróżnia brak dostępu, brak credentials Git, konflikt, brak wsparcia, host offline i niepewny wynik. Timeout nie jest dowodem, że nic się nie wykonało.

## Granice pierwszego wydania

V1 nie obejmuje wspólnego edytora, zapisu dowolnej treści pliku przez Explorer, uploadu/downloadu repozytoriów, przenoszenia żywych terminali między workspace’ami, rekursywnego kasowania niepustych katalogów przez API, dzielenia z innymi kontami, direct/P2P, port-forwardingu ani self-hostingu całej platformy kont. `files.create` tworzy pusty plik; usuwanie obejmuje plik/link lub pusty katalog. Rozszerzenia wymagają jawnego kontraktu i testów, zamiast nieokreślonego parametru `recursive` lub `command`.

Terminal pozwala wykonać szersze operacje z prawami konta OS. Również tworzenie/restart terminala uruchamia shell i jego startup scripts: `terminal.manage` jest uprawnieniem wykonawczym. Granice API plików/Git nie są sandboxem terminala.

Docelowe OS i architektury znajdują się w [07](07-realizacja-i-odbior.md). To macierz do zakwalifikowania. Niezaliczonego targetu ani brakującej funkcji obowiązkowej nie reklamuje się jako kompletnego v1. Zmiana zakresu produktu wymaga jawnego uzgodnienia; zmianę implementacyjną w obrębie zakresu rozstrzygają dowody i ADR.
