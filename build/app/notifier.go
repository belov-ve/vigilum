package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Определение типов событий для подбора шаблона уведомления.
type AlertType int

const (
	AlertDown AlertType = iota // Аварийная ситуация (сервис упал)
	AlertUp                    // Возобновление работы (сервис поднялся)
	AlertEnabled               // Включение мониторинга сервиса
	AlertDisabled              // Отключение мониторинга сервиса
	AlertWebadminEnabled       // Включение автозапуска службы в Webadmin
	AlertWebadminDisabled      // Отключение автозапуска службы в Webadmin
)

// Тело JSON-запроса, отправляемого в notify-bot согласно постановке.
type BotPayload struct {
	Text string `json:"text"`
}

// Отправляет оповещение о событии изменения статуса сервиса в notify-bot.
func SendAlert(safeConfig *SafeConfig, alertType AlertType, serviceName string, errMsg string) error {
	cfg := safeConfig.Get()
	if cfg.Global.NotifyBotURL == "" {
		slog.Warn("NOTIFY_BOT_URL пуст, отправка уведомления пропущена", "service", serviceName)
		return nil
	}

	// Выбираем соответствующий шаблон сообщения.
	var template string
	switch alertType {
	case AlertDown:
		template = cfg.Templates.Down
	case AlertUp:
		template = cfg.Templates.Up
	case AlertEnabled:
		template = cfg.Templates.Enabled
	case AlertDisabled:
		template = cfg.Templates.Disabled
	case AlertWebadminEnabled:
		template = cfg.Templates.WebadminEnabled
	case AlertWebadminDisabled:
		template = cfg.Templates.WebadminDisabled
	default:
		template = "Событие для сервиса {name}"
	}

	// Заменяем плейсхолдеры {name} и {error} на реальные значения.
	text := strings.ReplaceAll(template, "{name}", serviceName)
	text = strings.ReplaceAll(text, "{error}", errMsg)
	// Превращаем строковые литералы "\n" (введенные в файле конфигурации или веб-панели) в реальные переносы строк.
	text = strings.ReplaceAll(text, "\\n", "\n")

	// Формируем payload запроса.
	payload := BotPayload{Text: text}
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("ошибка сериализации JSON для notify-bot: %w", err)
	}

	// Создаем HTTP POST запрос с таймаутом 5 секунд.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Global.NotifyBotURL, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return fmt.Errorf("не удалось создать HTTP-запрос для notify-bot: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Date", time.Now().Format(time.RFC1123))

	// Логируем факт попытки отправки уведомления в режиме DEBUG.
	slog.Debug("Отправка запроса в notify-bot...", "url", cfg.Global.NotifyBotURL, "payload", text)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		wrapErr := fmt.Errorf("ошибка при выполнении сетевого запроса к notify-bot: %w", err)
		slog.Error("Не удалось отправить уведомление в notify-bot", "service", serviceName, "type", alertType, "error", wrapErr.Error())
		return wrapErr
	}
	defer resp.Body.Close()

	// Проверяем код ответа. Ожидаем 200 OK или 202 Accepted.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		wrapErr := fmt.Errorf("notify-bot вернул некорректный статус ответа: %s", resp.Status)
		slog.Error("Не удалось отправить уведомление в notify-bot", "service", serviceName, "type", alertType, "error", wrapErr.Error())
		return wrapErr
	}

	slog.Info("Уведомление успешно доставлено в notify-bot", "service", serviceName, "type", alertType)
	return nil
}

// Проверяет доступность healthcheck-сервиса notify-bot при старте
func CheckNotifyBotHealth(safeConfig *SafeConfig) error {
	cfg := safeConfig.Get()
	if cfg.Global.NotifyBotHealthURL == "" {
		slog.Debug("Адрес проверки здоровья notify-bot не настроен, проверка пропущена")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.Global.NotifyBotHealthURL, nil)
	if err != nil {
		return err
	}

	slog.Debug("Выполняется проверка здоровья службы notify-bot...", "url", cfg.Global.NotifyBotHealthURL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Возвращаем ошибку с описанием статуса (resp.Status уже содержит код ответа, например, "404 Not Found")
		return fmt.Errorf("код ответа сервера: %s", resp.Status)
	}

	return nil
}
