# Prosta strona do przechowywania plików
## !
1. Branch 'main' -- kod po wszystkich zabezpieczeniach.
2. Branch 'niezabezpieczona-aplikacja' -- wiadomo z nazwy.

   Komentarze dodane dla lepszego wytłumaczenia.
   
### 1. Szyfrowanie plików

Przy załadowaniu pliku do serweru przy pomocy widoku "Upload", plik zostaje zaszyfrowany. Przy pobieraniu - deszyfrowany.
Baza wiedzy:
- AES (Advanced Encryption Standard): Do szyfrowania plików wykorzystano algorytm AES w trybie CFB (Cipher Feedback). AES to jeden z najpopularniejszych algorytmów symetrycznych, zapewniający wysoki poziom bezpieczeństwa. 
- Tryb CFB jest odpowiedni do szyfrowania danych strumieniowych, co sprawia, że jest bardziej odporny na pewne rodzaje ataków. AES używa 32-bajtowego klucza (256 bitów) do szyfrowania danych.
- Generowanie IV (Initialization Vector): Do każdego szyfrowania generowany jest unikalny wektor inicjujący (IV), co zapewnia, że nawet te same dane będą szyfrowane w sposób unikalny za każdym razem

Opis Algorytmu:
- Algorytm szyfrowania: AES (Advanced Encryption Standard)
- Tryb pracy: CFB (Cipher Feedback Mode)
- Długość wektora inicjalizacyjnego (IV): 16 bajtów (128 bitów)
- Klucz: Przekazywany jako key, powinien mieć odpowiednią długość dla AES (np. 16, 24 lub 32 bajty)

Działanie:
1. Generuje losowy IV (wektor inicjalizacyjny), co zapewnia unikalność szyfrowania.
2. Tworzy szyfr AES w trybie CFB.
3. Szyfruje dane (encrypt_file) lub odszyfrowuje (decrypt_file).

### 2. Szyfrowanie hasel
Baza wiedzy:
- PBKDF2 (Password-Based Key Derivation Function 2): Hasła są przechowywane w bazie danych w formie skrótu, który jest generowany za pomocą funkcji generate_password_hash z biblioteki werkzeug.security. 
- Funkcja ta używa algorytmu PBKDF2 w połączeniu z losowym soleniem, co utrudnia ataki słownikowe oraz brute-force na hasła, lecz nie uniemozliwia danny typ ataku.

### 3. Potencjalne kierunki ataków

##### Brute Force logowania
**Jak wygląda atak brute-force na logowanie?**
<img width="452" alt="image" src="https://github.com/user-attachments/assets/139465f7-4f8a-4900-b005-39cd39dc5870" />

1. Atakujący uruchamia Hydrę i wskazuje adres URL formularza logowania.
2. Podaje listę możliwych nazw użytkowników i haseł (słownik lub losowe generowanie haseł).
3. Hydra wysyła setki/tysiące żądań HTTP do serwera, próbując różne kombinacje nazw użytkowników i haseł.
4. Jeśli poprawna kombinacja zostanie znaleziona, atakujący uzyskuje dostęp do konta użytkownika.

**Zabezpieczenie aplikacji przed atakiem brute-force**
Aby uniemożliwić atak Hydra i inne podobne ataki brute-force, należy wprowadzić ograniczenia logowania. Najlepszym rozwiązaniem jest:
- Limitowanie prób logowania: Wprowadzono limit dla prób logowania — użytkownik może próbować zalogować się tylko 5 razy na minutę z tego samego adresu IP.
- Jeśli próby logowania przekroczą ten limit, użytkownik zostanie zablokowany na 5 minut.
- CSRF: Wprowadzono ochronę przed atakami CSRF poprzez generowanie i sprawdzanie tokenów CSRF w formularzach, co zapewnia, że żądania pochodziły z zaufanych źródeł.

*Dodajemy:*
Rate Limiting (Flask-Limiter) – ogranicza liczbę prób logowania.
Blokada konta po 5 nieudanych próbach na 10 minut.
Zastosowanie parametrów w zapytaniach SQL, aby uniknąć potencjalnych SQL Injection.
![image](https://github.com/user-attachments/assets/5cd588a9-ec07-4f43-acc6-cabf3628537c)
Teraz widzimy tak zwane False-positive response. Hydra pokazuje że wszystkie hasła dla tego użytkownika są poprawne, kiedy w rzeczywistości tak nie jest.


##### Cookies Stealing
Atak "Cookie Stealing" (kradzież sesji) polega na przejęciu plików cookie użytkownika, w szczególności ciasteczka sesji (session), aby zalogować się na konto ofiary bez znajomości jej hasła. W ataku wykorzystuje się mechanizmy takie jak XSS (Cross-Site Scripting) lub wykradanie plików cookie przez malware.

**Przykład ataku**
![image](https://github.com/user-attachments/assets/45555af6-f6a8-4f79-9f23-4203adf0db6f)

1. Logowanie w przeglądarce A:
    Użytkownik loguje się do aplikacji w Google Chrome (lub innej przeglądarce).
    Przeglądarka zapisuje plik cookie session (np. session=xyz123).

2. Kradzież ciasteczek:
    Atakujący uzyskuje dostęp do ciasteczek sesji (np. przez XSS lub keyloggera).
    Kopiuje wartość session=xyz123.

3. Przeniesienie sesji do innej przeglądarki:
    Atakujący otwiera Firefox w trybie prywatnym i ustawia wykradzione ciasteczko session=xyz123.
    Przechodzi na stronę ofiary – system traktuje go jako autoryzowanego użytkownika.


**Zabezpieczenie przeciwko atakowi Cookie Stealing**

Aby zapobiec kradzieży sesji, stosuję następujące zabezpieczenia: 
1. Ustawienie flagi HttpOnly → zapobiega wyciekom cookie przez JavaScript (np. XSS).
2. Ustawienie flagi Secure → ciasteczko działa tylko na HTTPS.
3. Powiązanie sesji z adresem IP i User-Agent → ciasteczko działa tylko na oryginalnym urządzeniu.
4. Użycie SESSION_COOKIE_SAMESITE="Strict" → zapobiega atakom CSRF.
5. Regeneracja session po zalogowaniu → zapobiega przejęciu sesji.
6. W drugim kodzie sesje są zarządzane przy pomocy Flask-Session, co pozwala na bezpieczne przechowywanie sesji po stronie serwera. Pierwszy kod korzysta z domyślnego mechanizmu sesji w Flasku, co jest mniej bezpieczne, ponieważ dane sesji mogą być przechowywane po stronie klienta (w ciasteczkach).

### Różnice w branchach
Limitowanie prób logowania: W drugiej wersji dodano limitowanie prób logowania za pomocą flask_limiter, co nie występuje w pierwszej wersji.

Blokada konta: Po zbyt wielu nieudanych próbach logowania użytkownik zostaje zablokowany na określony czas (np. 5 minut), co nie było zaimplementowane w pierwszym kodzie.

Zabezpieczenie przed zmianą sesji (Session Fixation): W drugiej wersji aplikacji przed każdą próbą logowania jest sprawdzany adres IP oraz User-Agent przeglądarki. Jeśli się różnią, sesja jest unieważniana, co chroni przed atakami typu "session fixation".

Zabezpieczenia CSRF: W drugiej wersji użyto flask_wtf.CSRFProtect, co zapewnia ochronę przed atakami CSRF, podczas gdy w pierwszej wersji takie zabezpieczenie nie zostało uwzględnione.

Sesja wygasa po 5 minutach braku aktywności: W drugiej wersji aplikacji sesja użytkownika jest automatycznie wygaszana po 5 minutach nieaktywności, co zmniejsza ryzyko przejęcia sesji przez atakującego. W pierwszej wersji brak było takiego mechanizmu.

Logging i monitoring: W drugiej wersji wprowadzono logowanie aktywności użytkowników (logging), które może być przydatne w przypadku analizy bezpieczeństwa aplikacji. W pierwszym kodzie brak było tej funkcji.
