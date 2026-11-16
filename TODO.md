# Lomi Remote — pozostałe prace

Stan przekazania: 2026-11-16. Kod jest zapisany jako praca w toku.
**Pełny test CLI i przeglądarki nie jest zakończony. Publiczny release CLI
pozostaje wstrzymany.**

## Obecny stan

- Nowy certyfikat Developer ID (G2) i nowe lokalne klucze TUF. Pakiety
  `0.1.8` i `0.1.9` zbudowały się lokalnie, podpisane i notaryzowane.
  Aktualizacja Hosta na Linuksie zachowała profil, logowanie i workspace.
- Naprawione i potwierdzone na Linuksie: pierwszy `setup` (usługa systemd)
  oraz snapshot terminala (format `trimmed-rows-v1`, ok. 3,8 KB zamiast 2 MB).
- Połączenia HTTPS Hosta są ponownie używane w obrębie jednej operacji z
  limitem czasu: mediana zapytania spadła z 218 do 128 ms.
- W przeglądarce naprawiono pętlę odnawiania sterowania, która blokowała
  wpisywanie (`remote-web` `d8fa15b`).
- **Główna blokada: opóźnienie RPC Hosta ok. 1,5–2 s.** Jeden wątek
  autoryzacji wykonuje po kolei: odczyt pairingu, kanał relay, odpytywanie
  `pending`, `GET runtime` i `POST heartbeat`. Ingress działa raz na cykl
  ok. 0,6–0,8 s, a jedno RPC potrzebuje dwóch cykli. Przez to odnowienie
  sterowania terminalem przekracza 1,5 s, gdy czeka za wpisywaniem, i kanał
  się zamyka (`TERMINAL_RPC_RENEW_TIMED_OUT`). Krótsze oczekiwanie bezczynności,
  mniejszy margines dowodu i szybka ścieżka dla input/resize nie zmieniły
  rytmu cyklu, dlatego zostały wycofane.
- Potrzebny projekt: zrównoleglenie zapytań control-plane albo bezpieczne
  ponowne użycie dowodu pairingu w kolejnych przebiegach. Bez rozluźniania
  świeżości dowodu, dzierżawy i kontroli uprawnień.
- Otwarcie workspace'u trwa 9–16 s. Mniej więcej co drugie otwarcie po
  restarcie Hosta kończyło się `CHANNEL_NOT_ADMITTED` lub komunikatem
  „could not be completed”; przyczyna nie jest ustalona.

## Kontrole przy zapisie kodu

- Testy biblioteki `lomi-host` na macOS: 98 przeszło, 12 przypadków wymagających
  Linuksa pominięto, bez błędów i filtrowania.
- Testy skryptu warunków wstępnych: 17 przeszło.
- `mobile-app`: pełne `pnpm check` na Node 22 przeszło; lint ma 16 istniejących
  ostrzeżeń i zero błędów. Testy konfiguracji Metro obejmują cztery przypadki.
- Kontrola wspólnego pochodzenia źródeł, schematów, WASM i kopii pakietów
  w konsumentach przeszła po aktualizacji manifestów.
- Formatowanie czterech zmienionych plików Rust i `git diff --check` przeszły.
  Globalne `cargo fmt --all -- --check` nadal wykrywa wcześniejsze różnice
  w niezmienianych plikach kryptografii i `lomi-platform/src/setup_journal.rs`.
- Te kontrole nie obejmują nowego testu na fizycznym Linuksie, pełnej
  sesji przeglądarki ani iPhone'a.

## Kolejność dokończenia

- [ ] Przywrócić SSH do Linuksa i sprawdzić adres IP, identyfikator uruchomienia
  systemu, profil Hosta, logowanie, usługę i udostępnione workspace'y.
  Stare PID-y, odczyty stanu i poświadczenia wykonania testów są nieaktualne.
- [ ] Uruchomić na Linuksie pełne testy biblioteki `lomi-host`, w tym nowe
  przypadki zaszyfrowanego `terminal.input` i `terminal.resize`, odrzucanie
  starych sekwencji oraz brak ponowienia po anulowaniu lub niepewnej wysyłce.
- [ ] Zbudować prywatne pakiety z konkretnego, zapisanego SHA obecnego `main`.
  Sprawdzić podpisy, zgodność źródeł i zachowanie instalatora na Macu i Linuksie.
  Nie promować ich na publiczny kanał aktualizacji.
- [ ] Zaktualizować wyłącznie wybrane Hosty testowe i potwierdzić zachowanie
  profilu, logowania, udostępnień i istniejących workspace'ów.
- [ ] Powtórzyć pełny proces CLI: logowanie przez przeglądarkę, gotowość Hosta,
  udostępnienie workspace'u i automatyczne otwarcie w `https://remote.lomi.dev/`.
  Sprawdzić też, że inne konto nie otrzymuje dostępu do cudzych workspace'ów.
- [ ] Na Macu i Linuksie sprawdzić w prawdziwej przeglądarce:
  utworzenie terminala, pełny snapshot, wpisanie polecenia i jego wynik,
  dodawanie kart kliknięciem i skrótem, przełączanie kart, oba podziały
  terminala i poprawne zamykanie kart oraz paneli.
- [ ] Potwierdzić utrzymanie sterowania i wyniku terminala po co najmniej
  90 sekundach bezczynności oraz poprawne odzyskanie połączenia.
  Jeśli błędy odnowienia lub zamknięcia kanału wrócą, ustalić ich przyczynę
  na podstawie aktualnych pomiarów, bez rozluźniania kontroli uprawnień.
- [ ] W osobnym katalogu testowym sprawdzić pliki: tworzenie, podgląd,
  zmianę nazwy i usuwanie plików oraz folderów.
- [ ] W tym samym katalogu sprawdzić Git: diff, stage, unstage, lokalny commit
  i historię. Nie wykonywać tych testów na osobistym projekcie użytkownika.
- [ ] Uzupełnić testy zgodności dla wspieranych wersji i architektur macOS
  oraz dystrybucji Linuksa; dotychczasowe testy urządzeń obejmowały Maca ARM64
  i Arch Linux x64. Nie deklarować obsługi każdego systemu na tej podstawie.
- [ ] Po zakończeniu testów przywrócić zwykłe logowanie diagnostyczne Hosta
  macOS, zamknąć własne tunele i serwery testowe oraz usunąć wyłącznie
  utworzone na potrzeby testów klucze dostępu i pustą bazę QA.
  Zachować profile, pęki kluczy, kopie zapasowe i dane użytkownika.
- [ ] Wrócić do testu iPhone'a po zakończeniu prac CLI i przeglądarki.
  Zapisana konfiguracja lokalnego Metro nie jest potwierdzeniem działania
  aplikacji na fizycznym telefonie.
- [ ] Dopiero po przejściu powyższych testów ocenić gotowość publicznego release'u.

## Lokalne materiały do wznowienia

Diagnostyka i pomocnicze skrypty pozostają poza repozytorium w
`~/.local/state/lomi-remote-verification/`. Ostatni zapis przed publikacją
kodu to `nov13-current-work-status-r50.json`. W szczególności przygotowano
test I/O Linuksa, runner Jammy, próby przeglądarki R13/R14 oraz test Files/Git;
nie były one wykonane na najnowszym pakiecie.

Te skrypty mają przypięte konkretne źródła, profile, hashe i jednorazowe
próby. Przed wznowieniem trzeba powiązać je z rzeczywistym, świeżym stanem;
nie zastępować brakujących odczytów fikcyjnym wynikiem i nie ponawiać
operacji o nieznanym wyniku.

Szybkie kontrole źródeł, które nie zastępują testów urządzeń:

```sh
cargo test --locked --release -p lomi-host --lib -- --test-threads=1
python3 -B -m unittest discover -s scripts -p test_e2e_readiness.py -v
node scripts/check-cross-target-provenance.mjs
```

Node wymaga wersji zgodnej z repozytoriami konsumentów, obecnie co najmniej
22.13. Skrypt `scripts/e2e-readiness.py` sprawdza tylko warunki wstępne;
nawet jego pozytywny wynik nie potwierdza pełnego procesu użytkownika.
