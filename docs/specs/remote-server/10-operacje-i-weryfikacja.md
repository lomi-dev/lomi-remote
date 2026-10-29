# 10 — Operacje, migracja i dowody weryfikacji

Ten dokument opisuje przyszłe wykonanie. Nie jest instrukcją uruchomienia istniejących usług: nowy host/API nie zostały jeszcze zaimplementowane. Nazwy nowych artefaktów i gate’ów są specyfikacją do utworzenia. Faktyczne komendy należy pobrać z przypiętych manifestów, workflow i `--help`, nie wymyślać na podstawie nazwy zadania.

## Właściciele i przekazanie pracy

| Obszar | Odpowiedzialność wykonawcy | Wymagany wynik przeglądu |
| --- | --- | --- |
| Host/terminal/platform | Własność PTY, Rust state, IPC, storage, usługi i packaging | S0.1/S0.2, awarie procesów, dowody dla każdego OS/trybu |
| Identity/API/DB/relay | Enrollment, principals, migracje, role, revocation i skala | S0.4/S0.5, SQL z ograniczonymi rolami, replay/race/freshness |
| Desktop i klienci | Jedna domena, mixed views, adaptery i funkcjonalność | S0.3, zgodność metod i lifecycle wszystkich klientów |
| Release/operacje | Pochodzenie artefaktów, podpisy, backup/restore i cutover | S0.6, staging rehearsal, kwalifikacja i runbook incydentów |
| Integrator | Spójność wymagań/ADR/wersji i akceptacja dowodów etapów | Żaden obowiązkowy brak nie jest ukryty w statusie „done” |

Jedna osoba może pełnić kilka funkcji. Są to odpowiedzialności techniczne, a nie założenie o zatrudnieniu zespołu. Delegowanie agentom odbywa się według `AGENTS.md`; każdy dostaje ograniczony zakres plików i warunki odbioru. Przegląd bezpieczeństwa przed wydaniem powinien być niezależny od autora zmiany.

Na początku implementacji utworzyć wersjonowany rejestr postępu i dowodów w `lomi-remote/docs/implementation/` w nowym repozytorium `lomi-remote`. Ten katalog jest **proponowany**, obecny audyt go nie tworzy. Pliki `progress.md`, `decisions.md`, `evidence.md` i release manifest nie mogą zawierać sekretów ani transcriptów użytkownika. Zwięzły checkpoint obejmuje:

```text
Etap / zadanie / REQ IDs:
Status: not_started | in_progress | blocked | verified
Repozytoria i rewizje; lokalne zmiany:
Zakres faktycznie wykonany:
Komenda, środowisko i wersje:
Wynik: passed | failed | not_run, exit code, artifact:
Ograniczenia / nierozstrzygnięte ryzyka:
Następny konkretny krok i warunek jego odbioru:
```

`blocked` w rejestrze projektu oznacza faktyczną zależność zadania, nie zmianę stanu jakiegokolwiek narzędzia zarządzania celami. Brak VM/platformy, operatora podpisów lub dostępu do produkcji trzeba nazwać. Prace niezależne mogą trwać; nie symulujemy wyniku brakującego testu.

## Definicja ukończenia pojedynczego zadania

1. Zapisano problem, zmieniane repo/pliki i wymagania, które zadanie realizuje.
2. Zaktualizowano odpowiedni kontrakt i ADR przed zmianami klientów zależnymi od tego kontraktu.
3. Implementacja przechodzi właściwe dla zmiany build/lint/typecheck oraz testy pozytywne i wysokiego ryzyka. Przy każdej zmianie nie trzeba uruchamiać całej macierzy OS.
4. Test sprawdza zachowanie/niezmiennik; nie odzwierciedla jedynie szczegółu implementacji. Awaria procesu/DB wymaga rzeczywistego procesu/DB, a nie wyłącznie mocka.
5. Logi i artefakty testowe są zredagowane, a dokumentacja odróżnia wykonany test od planowanego.
6. Zapisano kompatybilność, migrację i ewentualny recovery; dla dużej zmiany zamknięto istotne findings review.
7. Brak testu lub znana luka pozostają jawne i blokują odpowiedni gate. Udany build nie kwalifikuje ConPTY, boot ani xterm snapshot.

Odbiór etapu wymaga powiązania dowodów z `REQ-*` i konkretną wersją wszystkich uczestników. Dowód staje się nieaktualny, gdy późniejsza zmiana dotknie weryfikowanego kontraktu lub mechanizmu. Status `verified` nie znaczy automatycznie „opublikowano”.

## Manifest wydania i pochodzenie

Każdy zestaw staging/release wskazuje:

- Commit i stan źródeł hosta, API/identity/relay, WWW, desktopu i mobile; release artifacts buduje się z odtwarzalnych, czystych rewizji.
- Wersje produktu, HTTP/RPC/IPC, grant/context, terminal profile oraz digest kontraktów i fixtures.
- Wersję SQLite schema, Prisma migration set i minimalny/maksymalny wspierany schema dla rollbacku.
- Digests paczek/binarium, obrazów kontenerów, WASM i bibliotek native mobile oraz źródło xterm renderer bundle.
- Target OS/arch/ABI, MSRV/toolchain, zależności runtime (np. Git), SBOM/licencje i stan podpisów/notarization.
- Qualification report dla funkcji i trybów autostartu, datę/środowisko pomiarów oraz znane ograniczenia.
- Rewizję root metadata/polityki aktualizacji; manifest nie zawiera kluczy prywatnych, haseł ani tokenów.

CI generuje Rust→schema/TS/OpenAPI i odrzuca drift w czystym checkout. Dla współdzielonych crypto i klienta wymaga immutable wersji/digestu. `auth-app` wskazuje artefakt z canonical `remote-web`; nie kwalifikujemy sąsiedniego repo, podczas gdy produkcja buduje inną kopię.

Obecny `remote-server` jest katalogiem specyfikacji. Zgodnie z wymaganiem użytkownika agent wdrażający **musi utworzyć nowe, odrębne repozytorium Git `lomi-remote`** w `/Users/woro/Documents/Lomi/lomi-remote`, z własnym wersjonowaniem i CI dla CLI/hosta oraz współdzielonych artefaktów. Nie umieszcza implementacji w repozytorium istniejącej aplikacji. Sam audyt i aktualizacja promptu nie tworzą ani nie publikują repozytorium. Agent nie może zakładać, że zmiany kilku repozytoriów mają wspólną transakcję Git.

## Staging: próba przed cutover

Użyć kont i fixture repo bez danych produkcyjnych. Zbudować manifest całego zestawu, a następnie przejść:

1. Czysta maszyna bez Node/Cargo/GUI → instalator → wybór trybu → device login na innym urządzeniu → jawne share.
2. Desktop B/WWW/mobile → ten sam host/workspace → terminale, Explorer, Source Control i zarządzanie kartami.
3. Dwa okna WWW pod jednym cookie, refresh jednego, równoległe obserwowanie; jeden lease input/resize. Revoke key odcina tylko jego grant; revoke sesji odcina wszystkie powiązane okna.
4. Zamknięcie SSH/TUI/desktopu A, logout OS i boot zgodny z macierzą; brak procesu GUI. Reboot tworzy stan lost/stopped, nie kontynuację dawnego shella.
5. Utrata identity/relay, opóźnione odpowiedzi, clock skew, full disk, przerwany exchange/refresh i crash po efekcie, przed receipt. Sprawdzić fence, recovery i brak replay.
6. Zmiany plików/HEAD przez zewnętrzny proces oraz native task równolegle z remote file/Git mutation. Sprawdzić konflikty i wspólne admission.
7. Update, przerwana migracja i restore; następnie global revoke i ponowna aktywacja konta. Dawne granty/refresh credentials pozostają nieważne.
8. Kontrolowany rollout próbny z domyślnie zamkniętymi feature gates, obserwacja metryk, soak i niezależny review.

Produkcję przełącza się dopiero po wynikach tej próby i autoryzacji właściwego operatora. Prace lokalne/staging przygotowujące zmianę nie powinny czekać na potwierdzenie dotyczące samej publikacji.

## Migracja centralnej bazy i usług

Brak kompatybilności starego wire nie znosi wymogu bezpiecznej migracji danych. Cutover jest oknem serwisowym Remote; zwykłe konta i push nie powinny być wyłączane przez przypadkowy cascade.

1. **Inwentaryzacja:** przypiąć manifest starego i nowego zestawu, migracje, DB roles, zależności `sourceSessionId`, push FK i global revoke/maintenance. Przećwiczyć na kopii/fixture z wersją PostgreSQL środowiska docelowego.
2. **Backup:** wykonać i sprawdzić restore centralnej bazy oraz konfiguracji usług; ograniczyć dostęp do backupu. Ustalić właściciela decyzji roll-forward/rollback i okno niedostępności. Nie kopiować sekretów do repo/logów.
3. **Zamknąć admission:** wyłączyć nowe legacy enrollment/pairing/publication, wydawanie tickets i nowe kanały przez feature gates. Wygasić/odwołać istniejące kanały. Pozostawić wymagane ścieżki revoke. Sprawdzić, że stary proces nie publikuje ponownie.
4. **Expand DB:** dodać nowe enrollment/authorization/credential/consumer/runtime byty i indeksy, constraints i potrzebne role. Nowe ograniczenia muszą działać przed otwarciem nowego admission. Nie usuwać jeszcze kolumn wymaganych przez stare binaria. Testować dokładne role z `ops/remote-database-permissions.sql`, nie superusera.
5. **Rozdzielić uprawnienia:** nowe ścieżki nie importują starych control grants jako file/Git grants. Unieważnić legacy pairing/grants/channels/tickets i host registrations według wersji/namespace, zachowując konto, consumer login tam gdzie zgodny i dane innych funkcji. Host przechodzi nowe enrollment.
6. **Wdrożyć zgodny zestaw:** identity/API/authority, relay i klientów z jednego manifestu. Relay najpierw przestaje przyjmować kanały i zwalnia owner lease; następca startuje po potwierdzonym zwolnieniu/expiry i fencing. Nie dopuszczać dwóch aktywnych ownerów ani nie udawać zero-downtime.
7. **Readiness i canary:** sprawdzić DB ownership, role, enrollment/key binding, publication CAS, runtime lease, revoke i pełny przepływ klienta testowego. Zweryfikować istniejący login i push. Otworzyć gates najpierw dla kont próbnych, potem planowanej grupy.
8. **Nowe upoważnienia:** użytkownik aktualizuje klienta, rejestruje host i ponownie zatwierdza sharing. Stary klient otrzymuje update-required. Sam login nie włącza sharing.
9. **Contract DB:** po ustalonym okresie obserwacji i braku starych procesów usunąć legacy owner columns/FK/checks/triggers. Zastąpić XOR web/mobile nowym spójnym modelem ownership; sprawdzić relacje pairing→grant i immutable owner. Osobna migracja z planem roll-forward.

Migracje nie mogą tworzyć tymczasowego okna akceptowania dowolnego `ownerId` lub wszystkich sesji `/device/token`. Revoke account/host i reactivation mają test przed otwarciem gates. Kopia produkcyjnej bazy nie jest automatycznie bezpiecznym środowiskiem testowym; wymagane są właściwe ograniczenia danych i dostępu.

## Lokalny import desktopu do hosta

1. Zatrzymać stare publikowanie Remote. Przygotować kompatybilne wersje desktopu/hosta; nie próbować adoptować żywego PTY Tauri.
2. Uruchomić dotychczasowy save/close flow. Niezapisane bufory muszą być zapisane lub zachowane przez istniejący mechanizm odzyskania; nie wymuszać utraty przez migrację. Poinformować o zakończeniu starych terminali i uzyskać zgodę w produkcie.
3. Przy zamkniętych writerach zrobić backup lokalnej domeny. Dry-run importu pokazuje liczbę projektów/workspace’ów/terminal descriptors i konflikty root/ID, bez ujawniania sekretów.
4. Transakcyjnie importować descriptors i trwałą mapę stary ID → nowy ID. Ponowienie używa tej mapy i nie dubluje terminali. Nie importować aktywnych lease, input, receipts starego protokołu, starych grantów ani wykonywalnych komend jako mechanizmu „wznawiania”.
5. Odtworzyć lokalne private-view references i terminalową projekcję. Nie kopiować niezapisanych edytorów do daemonu. Nowe karty wskazują stopped descriptors; nowy shell ma nową epokę i zatwierdzony profil.
6. Po sprawdzeniu danych dopuścić ponowną zgodę sharing. Zarchiwizować import marker/backup; nie usuwać katalogów projektów, Git ani sekretów Chat/AI. Usunięcie starego runtime z aktywnego builda następuje po odbiorze.

Przerwany import wraca do ostatniej zatwierdzonej transakcji. Jeżeli importer zmienił już lokalne referencje, rollback odtwarza spójnie domenę i mapping z backupu przy zatrzymanych procesach; nigdy częściową mieszankę starego GUI i nowego hosta.

## Aktualizacja i odzyskiwanie hosta

1. Pobrać i zweryfikować nowe metadane/target w staging instalacji. Sprawdzić zgodność IPC, schema i profilu. Aktualizacja GUI sama nie wymusza restartu hosta.
2. Zarejestrować zamiar maintenance w supervisorze/launcherze, aby stop nie uruchamiał automatycznego restartu starej wersji. Pokazać aktywne PTY/operacje; wstrzymać update do świadomej zgody na ich zakończenie albo okna bez sesji.
3. Włączyć local remote fence, odmówić nowych mutacji, zakończyć operacje bezpiecznie lub zapisać unknown. Zakończyć drzewa PTY i zatrzymać host. Nie obiecywać ich wznowienia.
4. Utworzyć spójny backup SQLite przez backup API po quiesce, nie zwykłe kopiowanie samego pliku przy aktywnym WAL. Migrować transakcyjnie z rollbackiem transakcji w razie błędu; pointer wersji przełączać atomowo według platformy.
5. Uruchomić nową wersję, sprawdzić IPC/schema/storage/shell i świeżą autoryzację. Nowy runtime claim/generation odcina stare kanały. Potwierdzić aktywną wersję i zakończyć maintenance.
6. Jeśli health zawiedzie, zachować redacted diagnostics i wstrzymać publikację. Wrócić do starszego binarium tylko przy zgodnym schema/kontrakcie, ewentualnie przywrócić domenę z backupu po zatrzymaniu procesów.
7. Nie przywracać starych refresh tokenów, starych TUF metadata ani dawnych epochs. Jeśli nowy sekret/authorization nie jest zgodny ze starszym runtime, odwołać go i wykonać re-enrollment. Po restore nowe epochs i jawne ponowne sharing zapobiegają odżyciu dawnych grantów.

Supervisor rozróżnia crash od świadomego stop/maintenance. Linux/systemd, launchd, Task Scheduler i SCM muszą mieć test tego rozróżnienia. Downgrade binarium przez ręczne kopiowanie EXE nie jest wspieranym recovery.

## Reakcje na typowe incydenty

| Zdarzenie | Działanie / bezpieczny wynik |
| --- | --- |
| Podejrzenie przejęcia host credential | Revoke authorization/family w koncie, access epoch i kanały; local fence, nowy enrollment i ewentualna rotacja klucza z jawną zmianą pinów |
| Utrata dostępu do hosta | Revoke z account UI; brak potrzeby wejścia na A. Jeśli A jest offline, freshness nie pozwala mu zdalnie wykonywać operacji |
| Skopiowany profil | Nie uruchamiać równolegle; runtime claim odmawia drugiemu. Restore/re-enrollment tworzy bezpieczne nowe powiązanie, bez kopiowania żywych lease |
| Brak keyring/DPAPI | Remote locked; bez automatycznego plaintext fallbacku. Local-only praca według dostępności domeny |
| Uszkodzona/full SQLite | Wstrzymać mutacje/publikację, zachować diagnostykę, przywrócić zweryfikowany backup przy zatrzymanym hoście; nie kasować DB i nie zaczynać „od zera” bez decyzji operatora |
| Zmiana gitdir/config/attributes lub podmiana kodu helpera | Unieważnić właściwy binding/trust; grant bez git.execute nie wykonuje repo-controlled helpera przy stałym config. Pełne wykonanie wymaga oddzielnej capability i lokalnej zgody |
| Revoke podczas push/delete/input | Zablokować dalsze efekty i cancel oczekujące; sprawdzić wynik już rozpoczętego działania, ewentualnie unknown; nie replayować |
| Compromise klucza wydania | Zamknąć publikację targetów, zastosować procedurę rotacji/recovery TUF, zweryfikować podpisany nowy zestaw; nie wyłączać signature checks |
| Uninstall bez sieci | Local fence i stop usługi, usunięcie autostartu/binarium, instrukcja centralnego revoke; purge nigdy nie usuwa workspace roots |

Nie obracamy tożsamości hosta w tle jako sposobu ominięcia pin mismatch. Zmiana host key jest widoczna jako kontrolowana rotacja/re-enrollment i unieważnia wcześniejsze konteksty.

## Obserwowalność i odbiór operacyjny

`status/doctor --json` odróżnia liveness procesu od gotowości Remote: IPC działa, domena gotowa, storage locked/unlocked, auth valid, runtime lease fresh, publication pending/acked, relay connected. Host offline w cloud nie znaczy, że lokalne PTY umarły. Endpoint publiczny nie ujawnia szczegółów wewnętrznej diagnostyki.

Metryki: aktywne sesje/attachments, długości kolejek i drops/resync, czas snapshotu, RSS/CPU, file/Git operations i conflicts, token rotation/recovery failures, authority latency/lock waits, freshness disconnects oraz czas revoke→fence. Używać kodów i agregatów, bez ścieżek, nazw plików, outputu i kont jako nieograniczonych etykiet metryk.

Przed wydaniem wypełnić macierz **OS × arch × tryb startu × funkcja × klient** wynikami `passed/failed/not_run` i artefaktami. Obowiązkowe wiersze wynikają z [REQ-*](00-cel-i-wymagania.md) i [07](07-realizacja-i-odbior.md). Nie zaliczać testu iOS wynikiem Androida ani SCM wynikiem procesu uruchomionego w interaktywnym PowerShell. Raport końcowy podaje oddzielnie: zaimplementowano, sprawdzono, opublikowano i pozostałe ograniczenia.
