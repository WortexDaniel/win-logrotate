# PowerShell Logrotate

Полнофункциональный аналог утилиты logrotate из Linux для управления ротацией и архивацией лог-файлов в среде Windows.

[![GitHub stars](https://img.shields.io/github/stars/yourusername/logrotate.svg)](https://github.com/yourusername/logrotate/stargazers)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

![PowerShell Logrotate Logo](https://example.com/logrotate-logo.png)

## 🚀 Обзор

PowerShell Logrotate предоставляет мощный и гибкий инструмент управления файлами журналов в Windows, позволяя настраивать автоматическую ротацию, сжатие и очистку логов согласно заданным правилам. Скрипт разработан с учетом совместимости с синтаксисом оригинальной утилиты logrotate из Linux, что делает его интуитивно понятным для системных администраторов.

## ✨ Возможности

- **Гибкие правила ротации**: по размеру, времени (ежедневно, еженедельно, ежемесячно, ежегодно)
- **Интеллектуальное сжатие**: автоматическое архивирование ротированных файлов
- **Контроль хранения**: настраиваемое количество сохраняемых копий
- **Выполнение скриптов**: поддержка prerotate и postrotate хуков
- **Планировщик задач**: простая установка в качестве запланированной задачи
- **Модульная конфигурация**: поддержка включения дополнительных конфигурационных файлов
- **Безопасный режим**: тестирование конфигурации без внесения изменений
- **Отчетность**: отправка уведомлений на email

## 💻 Системные требования

- Windows 7/10/11 или Windows Server 2012 R2 и выше
- PowerShell 3.0 или выше
- **Права администратора** для работы с системными каталогами и установки задач

## 🔧 Установка

### Быстрый старт

```powershell
# Клонирование репозитория
git clone https://github.com/yourusername/logrotate.git
cd logrotate

# Запуск PowerShell с правами администратора и установка задачи планировщика
.\Logrotate.ps1 -Install
```

### Ручная установка

1. Скопируйте файлы `Logrotate.ps1`, `logrotate.conf` и папку `conf.d` в выбранную директорию
2. Настройте конфигурационный файл под свои потребности
3. Добавьте задачу в планировщик задач Windows для автоматического запуска

## 📋 Использование

### Базовый запуск

```powershell
.\Logrotate.ps1 -ConfigFile "C:\logrotate\logrotate.conf"
```

### Принудительная ротация всех логов

```powershell
.\Logrotate.ps1 -ConfigFile "C:\logrotate\logrotate.conf" -Force
# или используя короткий параметр
.\Logrotate.ps1 -ConfigFile "C:\logrotate\logrotate.conf" -f
```

### Тестовый режим (без внесения изменений)

```powershell
.\Logrotate.ps1 -ConfigFile "C:\logrotate\logrotate.conf" -Test
```

### Использование нестандартного файла состояния

```powershell
.\Logrotate.ps1 -ConfigFile "C:\logrotate\logrotate.conf" -State "C:\logrotate\custom-state.json"
```

### Отправка отчета на email

```powershell
.\Logrotate.ps1 -ConfigFile "C:\logrotate\logrotate.conf" -Mail "admin@example.com"
```

## 📝 Синтаксис конфигурационного файла

Конфигурация logrotate полностью совместима с синтаксисом Linux-версии:

```
# Глобальные настройки
weekly               # Ротация каждую неделю
rotate 4             # Хранить 4 копии старых файлов
compress             # Сжимать файлы после ротации

# Включение дополнительных конфигураций
include conf.d/*.conf

# Пример конфигурации для конкретных файлов
C:\logs\app\*.log {
    daily            # Ротация ежедневно
    rotate 7         # Хранить 7 копий
    compress         # Сжимать
    missingok        # Не выдавать ошибку, если файла нет
    notifempty       # Не обрабатывать пустые файлы
    
    # Скрипт перед ротацией
    prerotate
        # PowerShell код
    endscript
    
    # Скрипт после ротации
    postrotate
        # PowerShell код
    endscript
}
```

## 📚 Справочник директив

| Директива | Описание |
|-----------|----------|
| `daily`, `weekly`, `monthly`, `yearly` | Периодичность ротации |
| `rotate N` | Количество хранимых архивов (целое число) |
| `size N[kMG]` | Ротация по достижении указанного размера (k - килобайты, M - мегабайты, G - гигабайты) |
| `compress` | Сжимать ротированные файлы |
| `compresscmd COMMAND` | Команда для сжатия файлов |
| `compressext .EXT` | Расширение для сжатых файлов |
| `copytruncate` | Копировать и обнулять оригинальный файл вместо его удаления |
| `create [mode]` | Создавать новый пустой файл после ротации |
| `dateext` | Добавлять дату к имени ротированного файла |
| `dateformat .FORMAT` | Формат даты для имен файлов |
| `include PATH` | Включение дополнительных конфигурационных файлов |
| `maxage N` | Удалять ротированные логи старше N дней |
| `missingok` | Не выдавать ошибку, если файл отсутствует |
| `notifempty` | Не ротировать пустые файлы |
| `olddir DIRECTORY` | Каталог для хранения ротированных логов |
| `prerotate/endscript` | Скрипт, выполняемый перед ротацией |
| `postrotate/endscript` | Скрипт, выполняемый после ротации |

## 📖 Примеры конфигураций

### Ротация логов IIS

```
C:\inetpub\logs\LogFiles\*\*.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
    dateext
    dateformat -%Y%m%d
    olddir C:\log-archive\iis
    
    postrotate
        # Перезапуск службы только если это необходимо
        # Restart-Service W3SVC -Force
    endscript
}
```

### Ротация логов SQL Server

```
C:\Program Files\Microsoft SQL Server\*\MSSQL\LOG\ERRORLOG* {
    daily
    rotate 30
    missingok
    notifempty
    copytruncate
    
    postrotate
        # Уведомление о ротации
        Send-MailMessage -From "sql@example.com" -To "dba@example.com" -Subject "SQL Server logs rotated" -Body "SQL Server logs have been rotated" -SmtpServer "smtp.example.com"
    endscript
}
```

### Ротация логов приложений с индивидуальными настройками

```
# Логи с низкой активностью
C:\apps\lowtraffic\*.log {
    monthly
    rotate 3
    compress
}

# Логи с высокой активностью
C:\apps\hightraffic\*.log {
    size 10M
    daily
    rotate 7
    compress
    delaycompress
}
```

## 🔍 Диагностика проблем

### Основные проблемы и решения

| Проблема | Решение |
|----------|---------|
| Скрипт не ротирует файлы | Проверьте права доступа к файлам и убедитесь, что скрипт запущен с правами администратора |
| Файл заблокирован другим процессом | Используйте `copytruncate` для работы с файлами, которые не могут быть закрыты |
| Ошибки при сжатии | Убедитесь, что указанная команда сжатия доступна в системе |
| Задача планировщика не запускается | Проверьте настройки планировщика и права доступа к файлам скрипта |

### Расширенная отладка

Для получения подробной информации о процессе ротации используйте параметр `-Verbose`:

```powershell
.\Logrotate.ps1 -ConfigFile "C:\logrotate\logrotate.conf" -Verbose
```

## 🤝 Содействие и поддержка

Проект открыт для контрибуций! Если вы обнаружили ошибку или хотите добавить новую функциональность, пожалуйста:

1. Создайте форк репозитория
2. Создайте ветку для вашей функциональности (`git checkout -b feature/amazing-feature`)
3. Зафиксируйте изменения (`git commit -m 'Add some amazing feature'`)
4. Отправьте ветку (`git push origin feature/amazing-feature`)
5. Откройте Pull Request

## 📜 Лицензия

Распространяется под лицензией MIT. См. файл `LICENSE` для получения дополнительной информации.

## ⭐ Благодарности

- Оригинальному проекту logrotate для Linux, который вдохновил на создание данного скрипта
- Сообществу PowerShell за неоценимую помощь и поддержку
- Всем контрибьюторам, помогающим улучшать проект 