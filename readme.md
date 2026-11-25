# pgr

Захват и воспроизведение нагрузки на postgres

## Содержание

- [Сборка и установка](#сборка-и-установка)
- [Пример](#пример)
- [Функции расширения](#функции-расширения)
- [Функции программы](#функции-программы)
- [Тесты](#тесты)

## Сборка и установка

Нужен [meson](https://mesonbuild.com/) и [rust](https://rust-lang.org/tools/install/)

Расширение

```bash
meson setup extension/build
meson install -C extension/build
```

Программа (соберется в ./target/release/pgr)

```bash
cargo build --release
```

Прописываем и создаем расширение:

```
shared_preload_libraries = 'pgr'
```

```sql
CREATE EXTENSION pgr;
```

## Пример

```sql
SELECT pgr.cstart();
-- нагрузка
SELECT pgr.cstop();
```

```bash
pgr lsn captures/1.pr # читает lsn, базу откатываем сами
pgr replay captures/1.pr -h 127.0.0.1 -p 5432 -d test -u postgres
```

## Функции расширения

- `pgr.cstart() -> id`

Начать запись запросов в {data}/captures/{id}.pr

- `pgr.cstop()`

Останавливает запись

- `pgr.timestart() -> id`

Начинает запись таймингов в {data}/timings/{id}.pr

- `pgr.timestop()`

Останавливает запись

- `pgr.getstats() -> (commits, rollbacks, failed_commits)`

Счётчики транзакций: коммиты, откаты, неудавшиеся коммиты

- `pgr.resetstats()`

Сбрасывает счётчики

- `pgr.sdump(name) -> int`

Сохраняет состояние в {data}/sessions/{name}.pgs:
Возвращает 1 при успехе, 0 при ошибке

- `pgr.srestore(name) -> int`

Восстанавливает сосстояние из файла
Возвращает 1 при успехе, 0 при ошибке

## Функции программы

- `replay <capture>`

Собственно воспроизведение

| Опция           | По умолчанию | Описание                             |
| --------------- | ------------ | ------------------------------------ |
| `-h, --host`    | 127.0.0.1    | Адрес сервера                        |
| `-p, --port`    | 5432         | Порт                                 |
| `-d, --dbname`  | postgres     | База данных                          |
| `-u, --user`    | $USER        | Пользователь                         |
| `-P, --pass`    | -            | Пароль                               |
| `-s, --speed`   | 1.0          | делит время ожидания клиента         |
| `-l, --latency` | 3            | вычитается из времени ожидания (мс)  |
| `-t, --threads` | 4            | Число потоков, управляющих клиентами |

- `lsn <capture>`

Читает точку синхронизации WAL

- `ts <capture>`

Читает время начала захвата

- `dump <capture/session/timings/traces> [-o file.csv]`

Преобразует бинарный файл от расширения в читаемый вид

## Тесты

Перед запуском поменять пути к data и к исполняемым файлам в `tests/base.py`

В `tests/miniroznica.py` указать путь к jar

```bash
python3 -m tests.pgbench
python3 -m tests.roz_1c2s
python3 -m tests.roz_5c20s
python3 -m tests.roz_10c6s
```
