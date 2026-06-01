# === ЭТАП СБОРКИ (BUILD STAGE) ===
FROM golang:1.26-alpine AS builder

# Установка рабочей директории в контейнере сборщика
WORKDIR /workspace

# Копирование файлов зависимостей Go
COPY build/go.mod build/go.sum ./
RUN go mod download

# Копирование исходного кода приложения
COPY build/app/ ./app/

# Сборка статического бинарного файла Go (отключаем CGO для переносимости)
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o vigilum ./app

# === ЭТАП ВЫПОЛНЕНИЯ (RUN STAGE) ===
FROM alpine:latest

# Установка корневых сертификатов (для HTTPS проверок), утилиты ping и базы данных часовых поясов
RUN apk --no-cache add ca-certificates iputils tzdata

# Создаем папку для хранения конфигурации
WORKDIR /app

# Копируем скомпилированный бинарный файл из этапа сборки
COPY --from=builder /workspace/vigilum /usr/local/bin/vigilum

# Установка переменных окружения по умолчанию
ENV CONFIG_PATH=/app/config.yaml
ENV HEALTH_PORT=8080
ENV POLL_INTERVAL=10s
ENV LOG_LEVEL=INFO

# Открываем порт для встроенного healthcheck
EXPOSE 8080

# Инструкция Docker для проверки работоспособности контейнера
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Команда запуска приложения
ENTRYPOINT ["/usr/local/bin/vigilum"]
