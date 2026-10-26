# pgr

![logo](assets/logo.png)

Захват и воспроизведение нагрузки на postgres

## Содержание

- [Расширение](#расширение)
  - [Установка](#установка)
  - [Команды](#команды)
  - [Сборка](#сборка)
- [Утилита](#утилита-1)
  - [Команды](#команды-1)
  - [Сборка](#сборка-1)
- [Пример](#пример)
- [Тесты](#тесты)

## Расширение

Сохраняет нагрузку и сессии клиентов

### Установка

Расширение нужно подключить через `shared_preload_libraries` и перезапустить сервер:

```
shared_preload_libraries = 'pgr'
```

```sql
CREATE EXTENSION pgr;
```

### Команды

- `pgr.cstart() -> id`

Начинает запись.
Файл с дампом будет в (data directory)/captures/{id}.pr

- `pgr.cstop()`

Останавливает запись

- `pgr.tstart() -> id`

Начинает запись trace выполнения запросов

- `pgr.tstop()`

Останавливает запись trace

- `pgr.getstats() -> (commits, rollbacks, failed_commits)`

Счётчики транзакций: коммиты, откаты, неудавшиеся коммиты

- `pgr.resetstats()`

Сбрасывает счётчики

- `pgr.sdump(name) -> int`

Сохраняет состояние сессии в (data directory)/sessions/{name}.pgs:
изменённые GUC, подготовленные запросы и временные таблицы с данными.
Возвращает 1 при успехе, 0 при ошибке

- `pgr.srestore(name) -> int`

Восстанавливает состояние сессии из файла. При воспроизведении
утилита вызывает её сама для каждого подключения с сохранённой сессией

### Сборка

Нужен [meson](https://mesonbuild.com/)

```bash
meson setup build
meson install -C build
```

## Утилита

Воспроизводит нагрузку и там еще умеет кое что

### Команды

- `replay <capture>`

Воспроизводит захват на другой базе

| Опция          | По умолчанию | Описание      |
| -------------- | ------------ | ------------- |
| `-h, --host`   | 127.0.0.1    | Адрес сервера |
| `-p, --port`   | 5432         | Порт          |
| `-d, --dbname` | postgres     | База данных   |
| `-u, --user`   | $USER        | Пользователь  |
| `-P, --pass`   | -            | Пароль        |

- `dump <capture> [-o capture.csv]`

Выгружает захват в CSV

- `lsn <capture>`

Показывает точку синхронизации WAL и время начала захвата

- `analyze -c <capture> -t <trace> [-o analysis] [--chunk 0.05] [-a 127.0.0.1] [-p 3232]`

Сопоставляет trace с захватом, сохраняет результат в папку и запускает веб-сервер

- `view [folder] [-a 127.0.0.1] [-p 3232]`

Запускает сервер для готового анализа

### Сборка

Нужен [rust](https://rust-lang.org/tools/install/)

```bash
cargo build --release
```

## Пример

```sql
SELECT pgr.cstart();
-- нагрузка
SELECT pgr.cstop();
```

```bash
pgr lsn captures/1.pr
pgr replay captures/1.pr -h 127.0.0.1 -p 5432 -d test -u postgres
```

## Тесты

Перед запуском поменять пути к data и к исполняемым файлам в `tests/base.py`

В `tests/miniroznica.py` указать путь к jar

```bash
python3 -m tests.pgbench
python3 -m tests.miniroznica
```
