# Podejrzane pliki kontra serwis do przesylania danych

Projekt realizowany w ramach nauki podstaw cyberbezpieczeństwa i analizy zachowania podejrzanych plików w kontrolowanym, edukacyjnym środowisku.

## Cel projektu:

Celem projektu jest zrozumienie, w jaki sposób serwisy do przesyłania danych mogą reagować na pliki o podwyższonym ryzyku, oraz jak można budować mechanizmy analizujące i klasyfikujące takie pliki. Zostanie również wspomniane jak można się bronić przed najważniejszymi atakami.
W ramach zadań tworzony jest symulowany podejrzany plik (wygenerowany za pomocą narzędzia Social Engineering Toolkit), który następnie trafia na prosty serwer napisany w Pythonie. Wszelkie zadania należy wykonywać w odizolowanym środowisku na maszynie wirtualnej. 

## Zadanie 1
1. Uruchom maszyny wirtualne
2. Wyłącz windows defender - Windows Security -> Virus & threat protection -> Manage settings -> Wszystko powyłączaj
3. Uruchom serwer -> Wejdź do folderu C:\Users\serwer\Desktop\serwer\app i uruchom aplikację poleceniem python app.py
4. Na kali Linuxie sprawdź czy aplikacja się otwiera (w przeglądarce internetowej wejdź na stronę 192.168.1.1:5000
5. Załóż konto

6. Tworzenie zainfekowanego pliku:
- Z uprawnieniami roota wykonaj polecenie setoolkit
- Wybierz opcję 1 - Social-Engineering Attacks
- Wybierz opcję 3 - Infectious Media Generator
- Wybierz opcję 2 - Standard Metasploit Executable
- Wybierz opcję 1 - Windows Shell Reverse_TCP
- Wpisz adres IP karty sieciowe na kali Linuxie
- Wybierz dowolny nieużywany port do nasłuchiwania
- Kiedy plik zostanie utworzony utwórz listener (yes)
- Kiedy listener zostanie utworzony (pojawi się linijka Started reverse handler) prześlij plik payload.exe na serwer

7. Na windowsie sprawdź czy plik znajduje się w katalogu uploads
8. Na windowsie wejdź na stronę internetową serwisu i pobierz plik (wybierz opcję keep)
9. Uruchom plik, kliknij w wyskakujące powiadomienie od windows defendera, wybierz opcję allow on device i zaakceptuj
10. Na kali Linuxie powinny pojawić się informacje o nawiązanym połączeniu. Wpisz komendę sessions aby sprawdzić informacje o sesjach
11. Połącz się z sesją poleceniem sessions -i [id sesji] --timeout 9999
12. Połączenie powinno być nawiązane i konsola na kalim powinna znajdować się w katalogu, w którym został zapisany plik na windowsie

## Zadanie 2 
1. Aby sprawdzić dostępne komendy wpisz .help
2. Korzystając z kali Linuxa wykonaj poniższe polecenia na windowsie:
- Stwórz nowy katalog
<details>
<summary>Podpowiedź</summary>
mkdir [nazwa] 
</details> 

- Skopiuj dowolny plik (np. payload.exe) na pulpit użytkownika serwer
<details>
<summary>Podpowiedź</summary>
copy .\payload.exe \Users\serwer\Desktop
</details>

- Stwórz plik i coś w nim napisz 
<details>
<summary>Podpowiedź</summary>
echo [tekst] > [nazwa pliku]
</details>

- Odczytaj zawartość utworzonego pliku 
<details>
<summary>Podpowiedź</summary>
type [nazwa pliku]
</details>

- Zmień nazwę pliku
<details>
<summary>Podpowiedź</summary>
ren [nazwa pliku] [nowa nazwa pliku]
</details>

- Usuń plik 
<details>
<summary>Podpowiedź</summary>
del [nazwa pliku]
</details>

- Wylistuj procesy 
<details>
<summary>Podpowiedź</summary>
tasklist
</details>

- Sprawdź informacje o systemie 
<details>
<summary>Podpowiedź</summary>
systeminfo
</details>

- Wylistuj informacje o kartach sieciowych i adresach IP 
<details>
<summary>Podpowiedź</summary>
ipconfig
</details>

3. Zakończ sesję poleceniem exit

## Zadanie 3
1. Zarejestruj się na https://www.virustotal.com/gui/sign-in
2. Kliknij w sekcję swoje dane w prawym górnym rogu ekranu, następnie API key
3. Skopiuj swój klucz
4. Stwórz w katalogu głównym plik .env
5. Wklej do pliku swój klucz w formacie VT_API_KEY=klucz
6. Przed pobraniem zainfekowanego pliku włącz sprawdzanie bezpieczeństwa pliku w aplikacji (emoji tarczy)
7. Obserwuj czy plik zostanie oznaczony jako niebezpieczny
