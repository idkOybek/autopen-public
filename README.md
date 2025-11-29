# autopen (public version)

Краткое описание, что делает проект.

## Установка

```bash
git clone <url>
cd autopen
# установка зависимостей (пример)
pip install -r requirements.txt

###Конфигурация
#Скопировать пример конфигов:
```bash
cp .env.example .env
cp config.example.yml config.yml
Заполнить .env и config.yml своими значениями.

###Запуск
```bash
# пример
python main.py
# или
docker compose up --build

Ограничения публичной версии

Секретные ключи и реальные адреса сервисов не входят в репозиторий.

Некоторые пути/конфиги нужно настроить вручную.
