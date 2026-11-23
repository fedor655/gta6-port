# Boot log — первые запуски настоящего exe

Дата: 24.11.2026. Загрузчик: `loader/` (`gta6rt.exe`), копия игры `C:\gta6\GTA6.Xbox.v1.0.2.1-CYBERLEEK`.

## 1. Маппинг

```
[map] loaded, sections=10, functions=299257
[map] preferred base 140000000, image size 184995840, entry 56a1ec8
[map] mapped at 0000000140000000
[map] relocations applied: 598282 (dir64=598282, other=0), delta=0
[iat] 587 imports in 68 DLLs
```

* Образ лёг по предпочтительному адресу `0x140000000` с первой попытки. Для этого сам загрузчик
  собран с `/BASE:0x10000000 /DYNAMICBASE:NO` — иначе он занимает `0x140000000` и игре достаётся
  только релокация (проверено: при delta ≈ −5 ГБ все 598 282 релокации применяются, но это лишний
  риск для кода, который считает базу абсолютной).
* 587 импортов: 409 закрываются настоящими Windows-библиотеками (включая `MSVCP140`,
  `VCRUNTIME140`, UCRT, `WS2_32` — ординалы вида `#111` резолвятся через `GetProcAddress` по
  `MAKEINTRESOURCE`), 178 — стабы. Все 100 % импортов Xbox-библиотек (`xmem`, `xapu`, `AcpHal`,
  `d3d12_xs`, `Bink2Scarlett`, `libHttpClient.GDK`, …) — стабы.
* Проверка после бинда: 0 слотов IAT расходятся с таблицей.

## 2. TLS

Каталог TLS: `AddressOfIndex = 0x146E08B2C`, `StartAddressOfRawData = 0x14AF3D000`,
`EndAddressOfRawData = 0x14AF3E480` (шаблон 0x1480 байт), `SizeOfZeroFill = 0`, callbacks = 0.

Найденные грабли:

1. **Усечение 64-битных VA.** `AddressOfIndex` — полный 64-битный адрес. При чтении через
   `uint32_t` получается `0x46E08B2C` — свободная память, запись падает в AV. Все поля TLS-каталога
   держим в `uintptr_t`.
2. **Два разных массива.** `mov rax, gs:[58h]` (TEB.ThreadLocalStoragePointer) — это то, что
   использует код игры и `IMAGE_TLS_DIRECTORY`; `TEB.TlsSlots` (offset `0x1480`) — массив
   `TlsAlloc`. Загрузчик пишет блок в оба массива по одному и тому же слоту (7).
3. Блок TLS копируется из `StartAddressOfRawData` (шаблон лежит в области `.reloc`, а не в `.tls` —
   так в этом образе).

## 3. Стабы и ABI

Стаб — 40 байт машинного кода на каждый импорт:

```
mov rax, rcx ; mov r11, rdx ; mov r9, r8 ; mov rdx, rax ; mov r8, r11
mov r10, id64 ; mov rcx, r10 ; mov rax, &Gta6ShimCall ; jmp rax
```

Первая версия писала `id` по смещению +15 и затирала опкод `49 BA` — процессор уходил на байт
вперёд, в `00 00` (`add [rax], al`), и падал с записью по адресу 0. Симптом в логе:
`rip = stub + 0x10`, `write 0`. Исправлено: `id` пишется по +17, адрес обработчика — по +30.

Вторая ошибка: `id` был индексом в таблице биндов, а имена складывались подряд только для стабов →
`names[id]` выходил за границы (id 217 при 110 именах). Исправлено выравниванием вектора имён по id.

## 4. Что делает игра на старте

Порядок вызовов (каждый — `[stub]`/`[shim]` в логе):

1. `d3d12_xs.dll!D3D12ConfigureVirtualMemoryX(size=0x15FA40, …)` — стаб, вернул 0.
2. `xmem.dll!XMemAlloc(0x15FA40, …)` → `VirtualAlloc` 1,4 МБ. Игра использует указатель сразу.
3. `xmem.dll!XMemVirtualAlloc(base=0, size=0x600000000 (24 ГиБ), flags=0x20402000)` — резерв
   24 ГиБ. Флаги Xbox не совпадают с Win32: `0x20402000` → `MEM_RESERVE` (0x2000) плюс биты
   large pages/physical.
4. Серия `XMemVirtualAlloc` с `flags=0x20003000` на 1,2 / 2,3 / 0,6 / 0,6 ГиБ — это уже
   commit+reserve конкретных арен (похоже на раскладку 16 ГиБ памяти консоли).
5. `XMemVirtualAlloc(size=0x1400000, flags=0x20403000)` — `VirtualAlloc` вернул ошибку 122
   (`ERROR_INSUFFICIENT_BUFFER`) на commit; добавлен fallback на `MEM_RESERVE`, вызов вернул адрес.

## 5. Текущий блокер

После арен игра уходит в поиск per-thread data (функция `rva 0x55DC7F4`, паттерн
`gs:[58h] → [rax+index*8] → [rdi+0x10]`) и падает на `cmp dword ptr [rbx], 0x1E`
(`rva 0x55DC838`) при `rbx = 0x3E9`.

Ещё одна аномалия последнего прогона: после запроса
`XMemVirtualAlloc(size=0x1400000, flags=0x20403000)` процесс завершается с кодом
`0xC0000005`, но **VEH не получает ни одного AV** (в файл `gta6rt-faults.log` попадает только
`DBG_PRINTEXCEPTION_C`). То есть исключение либо возникает уже после снятия обработчика, либо
приходит из потока/контекста, который не доходит до VEH. Первый шаг дальше — прогон под
отладчиком (`cdb`/WinDbg) и/или `--no-run` + пошаговый вызов по RVA.

Гипотезы, в порядке проверки:

* шаблон TLS по `StartAddressOfRawData` — не то, что ждёт CRT (значение в `[block+0x10]` должно
  быть либо 0, либо валидным указателем на PTD; у нас получается 0x3E9);
* игре нужен не «сырой» блок TLS, а запись в его собственный диспетчер потоков (возможно,
  `TlsAlloc`-слот и `gs:[58h]`-слот должны быть разными индексами);
* флаги `XMem*` — не Win32-биты. `0x20403000` содержит `MEM_LARGE_PAGES` (0x20000000) и
  `MEM_PHYSICAL` (0x400000); `VirtualAlloc` с large pages на такой размер отвечает
  `ERROR_INSUFFICIENT_BUFFER` (122). Нужна честная модель физических страниц, а не маска флагов;
* `D3D12ConfigureVirtualMemoryX` (стаб вернул 0) может ожидать ненулевой результат/размер, и
  раскладка арен тогда не совпадёт с ожидаемой игрой.

## 6. Как повторить

```powershell
cd loader
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
.\build\Release\gta6rt.exe "C:\gta6\EXE\game_scarlett_master.exe"
```

Полезные режимы: `--map-only`, `--no-run`, `--trace-iat`, `--no-protect`, `--probe <rva>`.
