# Prosta strona do przechowywania plików

### 1. Szyfrowanie plików

Przy załadowaniu pliku do serweru przy pomocy widoku "Upload", plik zostaje zaszyfrowany. Przy pobieraniu - deszyfrowany.


Opis Algorytmu:
- Algorytm szyfrowania: AES (Advanced Encryption Standard)
- Tryb pracy: CFB (Cipher Feedback Mode)
- Długość wektora inicjalizacyjnego (IV): 16 bajtów (128 bitów)
- Klucz: Przekazywany jako key, powinien mieć odpowiednią długość dla AES (np. 16, 24 lub 32 bajty)

Działanie:
1. Generuje losowy IV (wektor inicjalizacyjny), co zapewnia unikalność szyfrowania.
2. Tworzy szyfr AES w trybie CFB.
3. Szyfruje dane (encrypt_file) lub odszyfrowuje (decrypt_file).
