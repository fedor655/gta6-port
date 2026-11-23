# gta6-port — независимый параллельный порт GTA VI (Xbox 1.0.2.1)

Отдельный проект портирования **GTA VI, Xbox Series build 1.0.2.1 (Cyberleek, ноябрь 2026)** на
Windows. Ведётся параллельно с [Leonida](https://github.com/ItsNotRexed/Leonida) и не зависит от его
кода: своя архитектура, свои артефакты, свой рантайм.

Подход — **exe-first**: начинаем с исполняемого файла (он появился 23.11.2026), а не с ассетов и
шейдеров. Цель — как можно раньше получить живой процесс игры: образ PE отображается в память,
587 импортов закрываются шимами, дальше boot-трейс ведёт по первым кадрам.

## Что уже известно (факты, снятые с exe)

| | |
|---|---|
| Файл | `game_scarlett_master.exe` |
| Размер | 120 181 760 байт |
| SHA-256 | `e95020b2fa4a721db3df59fdecf75621730ac559d8835252f6c3b658d5a08993` |
| PE | x86-64, PE32+, 10 секций, Windows GUI |
| Собран | 2026-11-13 21:40:36 UTC, GRDK October 2025 (build `0x65F41807`), MSVC 19.29.30159 |
| PDB | `X:/americas/src/sub_story/game/vs_project/Gaming.Xbox.Scarlett.x64/Build/master/game_scarlett_master.pdb` |
| Image | 184 995 840 байт, база `0x140000000`, entry `0x56a1ec8` |
| Функций | **299 257** записей в `.pdata` (все — настоящие функции с unwind-инфо) |
| Импорты | **68 DLL, 587 функций** (полный список — [docs/imports.md](docs/imports.md)) |
| Экспорт | один: `__XMemAllocationHooks__` |
| Релокации | 2 763 блока, 599 676 записей, из них 598 282 `DIR64` |
| TLS | `0x14af3d000`–`0x14af3e480`, callbacks: 0 |
| `.data` | virtual 71 222 168 Б, raw 6 434 304 Б (BSS-образ, живёт в памяти) |

Ключевые системные DLL: `d3d12_xs.dll` (3), `xmem.dll` (12), `xapu.dll` (5), `xg_xs.dll` (2),
`AcpHal.dll` (9), `XCRDAPI.dll` (1), `chad.dll` (5), `GameInput.dll` (1), `Bink2Scarlett.dll` (23),
`amd_fidelityfx_loader_xbox.dll` (4), `libHttpClient.GDK.dll` (38), `XboxBvhBuilder.dll` (7).
Остальное — UCRT/STL/Win32: значит, значительная часть ОС уже обычная Windows.

## Данные игры на этой машине

| Копия | Файлов | Размер | exe |
|---|---|---|---|
| `C:\gta6\GTA6.Xbox.v1.0.2.1-CYBERLEEK` | 42 | 122,0 ГиБ | да, `C:\gta6\EXE\` |
| `D:\gta6\GTA6.Xbox.v1.0.2.1-CYBERLEEK` | 41 | 121,9 ГиБ | нет |

`make_game.py --check` (Leonida) на копии C: сообщал «all files present. Executable found.»

## Статус

- [x] M0. Факты по exe: заголовки, секции, импорты, `.pdata`, релокации, TLS, PDB — [reports/exe-facts.json](reports/exe-facts.json)
- [x] M1 (частично). Загрузчик `loader/`: маппинг по базе `0x140000000`, 598 282 релокации, 587 импортов, TLS, entry point; игра дошла до CRT-инициализации и первых арен `xmem` — [docs/boot-log.md](docs/boot-log.md)
- [ ] M1. Починить per-thread data (падает `rva 0x55DC838`), дойти до первых стабов D3D12
- [ ] M2. Шимы GDK-минимума: `xmem` (полностью), потоки/синхронизация, файловая система
- [ ] M3. `d3d12_xs` → Vulkan: swapchain, первый кадр
- [ ] M4. Boot до логотипа/меню

## Инструменты

```powershell
python -I tools\pe_report.py "C:\gta6\EXE\game_scarlett_master.exe" --json reports\exe-facts.json --imports
```

Только стандартная библиотека Python; из образа ничего не копируется — отчёт содержит производные
факты (размеры, счётчики, имена импортов, путь к PDB).

## Правовая оговорка

Репозиторий не содержит и не будет содержать файлов игры. Всё строится на вашей собственной копии.
