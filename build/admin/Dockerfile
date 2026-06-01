# === ЭТАП СБОРКИ (BUILD STAGE) ===
FROM golang:1.26-alpine AS builder

# Установка рабочей директории в контейнере сборщика
WORKDIR /workspace

# Копирование файлов зависимостей Go
COPY build/go.mod build/go.sum ./
RUN go mod download

# Копирование исходного кода приложения и веб-интерфейса
COPY build/admin/ ./admin/

# Сборка статического бинарного файла Go (отключаем CGO для переносимости)
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o vigilum-admin ./admin

# === ЭТАП ВЫПОЛНЕНИЯ (RUN STAGE) ===
FROM alpine:latest

# Установка корневых сертификатов и базы данных часовых поясов
RUN apk --no-cache add ca-certificates tzdata

# Создаем папку для хранения конфигурации
WORKDIR /app

# Копируем скомпилированный бинарный файл из этапа сборки
COPY --from=builder /workspace/vigilum-admin /usr/local/bin/vigilum-admin

# Установка переменных окружения по умолчанию
ENV CONFIG_PATH=/app/config.yaml
ENV PORT=8080
ENV ADMIN_USERNAME=admin
ENV ADMIN_PASSWORD=admin

# Открываем порт для панели управления
EXPOSE 8080

# Команда запуска панели управления
ENTRYPOINT ["/usr/local/bin/vigilum-admin"]
