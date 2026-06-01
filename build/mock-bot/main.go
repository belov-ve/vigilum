package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"
)

// Описание структуры входящего запроса от vigilum к notify-bot.
type Notification struct {
	Text string `json:"text"`
}

func main() {
	// Инициализация структурированного логирования для наглядного вывода в консоль.
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	// Получение порта из переменной окружения или использование значения по умолчанию 18043.
	port := os.Getenv("PORT")
	if port == "" {
		port = "18043"
	}

	// Обработчик эндпоинта /notify, куда vigilum отправляет оповещения.
	http.HandleFunc("/notify", func(w http.ResponseWriter, r *http.Request) {
		// Допускается только метод POST.
		if r.Method != http.MethodPost {
			slog.Warn("Неверный HTTP-метод запроса", "method", r.Method)
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		// Чтение тела запроса.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			slog.Error("Не удалось прочитать тело запроса", "error", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// Разбор JSON-содержимого.
		var notif Notification
		if err := json.Unmarshal(body, &notif); err != nil {
			slog.Error("Не удалось распарсить JSON уведомления", "error", err, "raw_body", string(body))
			http.Error(w, "Unprocessable Entity", http.StatusUnprocessableEntity)
			return
		}

		// Вывод полученного уведомления в терминал.
		timeStr := r.Header.Get("Date")
		if timeStr == "" {
			timeStr = time.Now().Format("2006-01-02 15:04:05 MST")
		}

		// Вывод полученных данных с заголовком text (как в JSON-теле запроса) и time на английском языке.
		fmt.Printf("=== [Mock Bot] RECEIVED NEW NOTIFICATION ===\n")
		fmt.Printf("text:  %s\n", notif.Text)
		fmt.Printf("time:  %s\n", timeStr)
		fmt.Printf("=============================================\n\n")

		// Успешный ответ.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	})

	// Обработчик эндпоинта /health для проверки здоровья бота (эмуляция реального notify-bot).
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Запуск HTTP-сервера.
	slog.Info("Запуск mock-bot сервера для локального тестирования", "port", port)
	address := fmt.Sprintf(":%s", port)
	if err := http.ListenAndServe(address, nil); err != nil {
		slog.Error("Не удалось запустить HTTP-сервер mock-bot", "error", err)
		os.Exit(1)
	}
}
