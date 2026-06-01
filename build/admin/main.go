package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata"

	"gopkg.in/yaml.v3"
)

// Вшиваем HTML-код фронтенда прямо в бинарник с помощью директивы go:embed.
// Это делает утилиту полностью автономной и переносимой.
//
//go:embed index.html
var indexHTML []byte

// Структура конфигурации шаблонов уведомлений (совпадает с основным приложением).
type TemplatesConfig struct {
	Down             string `yaml:"down" json:"down"`
	Up               string `yaml:"up" json:"up"`
	Enabled          string `yaml:"enabled" json:"enabled"`
	Disabled         string `yaml:"disabled" json:"disabled"`
	WebadminEnabled  string `yaml:"webadmin_enabled" json:"webadmin_enabled"`
	WebadminDisabled string `yaml:"webadmin_disabled" json:"webadmin_disabled"`
}

// Структура конфигурации отдельного сервиса.
type ServiceConfig struct {
	ID            string `yaml:"id" json:"id"`
	Name          string `yaml:"name" json:"name"`
	Type          string `yaml:"type" json:"type"`
	Target        string `yaml:"target" json:"target"`
	Enabled       bool   `yaml:"enabled" json:"enabled"`
	Retries       *int   `yaml:"retries,omitempty" json:"retries"`
	RetryInterval string `yaml:"retry_interval,omitempty" json:"retry_interval,omitempty"`
	Username      string `yaml:"username,omitempty" json:"username,omitempty"`
	Password      string `yaml:"password,omitempty" json:"password,omitempty"`
}

// Глобальная структура YAML-файла конфигурации.
type Config struct {
	Templates TemplatesConfig `yaml:"templates" json:"templates"`
	Services  []ServiceConfig `yaml:"services" json:"services"`
}

// Структура для быстрого включения/отключения сервиса через API.
type ToggleRequest struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
}

const sessionDuration = 12 * time.Hour

var (
	// Мьютекс для предотвращения состояния гонки при одновременном чтении/записи config.yaml.
	configMu sync.Mutex
	// Путь к файлу конфигурации, считываемый при запуске.
	configPath string
	// Учетные данные администратора для авторизации.
	adminUser string
	adminPass string

	// Хранилище активных сессий (токен -> время истечения)
	sessions   = make(map[string]time.Time)
	sessionsMu sync.Mutex

	// URL-адрес API демона Vigilum для получения текущих статусов здоровья.
	vigilumAPIURL string
)

func main() {
	// Инициализируем глобальный логгер с учетом уровня логирования из переменной окружения LOG_LEVEL.
	initLogger()

	slog.Info("Запуск административной панели vigilum-admin...")

	// Получаем порт для HTTP-сервера.
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Получаем путь к конфигурационному файлу.
	configPath = os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "config.yaml"
	}

	// Считываем адрес API демона Vigilum.
	vigilumAPIURL = os.Getenv("VIGILUM_API_URL")
	if vigilumAPIURL == "" {
		vigilumAPIURL = "http://vigilum:8080"
	}

	// Считываем логин и пароль администратора.
	adminUser = os.Getenv("ADMIN_USERNAME")
	adminPass = os.Getenv("ADMIN_PASSWORD")

	if adminUser == "" || adminPass == "" {
		slog.Warn("Переменные окружения ADMIN_USERNAME или ADMIN_PASSWORD не заданы!")
		slog.Warn("Используются стандартные учетные данные: логин 'admin', пароль 'admin'")
		adminUser = "admin"
		adminPass = "admin"
	}

	// Создаем роутер.
	mux := http.NewServeMux()

	// Главная страница — отдает встроенный HTML.
	mux.HandleFunc("GET /", handleIndex)

	// Авторизация и выход.
	mux.HandleFunc("POST /api/auth/login", handleLogin)
	mux.HandleFunc("POST /api/auth/logout", handleLogout)

	// REST API эндпоинты.
	mux.HandleFunc("GET /api/config", handleGetConfig)
	mux.HandleFunc("POST /api/config", handleSaveConfig)
	mux.HandleFunc("POST /api/services/toggle", handleToggleService)
	mux.HandleFunc("GET /api/statuses", handleGetStatuses)
	// Бэкап и восстановление конфигурации.
	mux.HandleFunc("GET /api/config/export", handleExportConfig)
	mux.HandleFunc("POST /api/config/import", handleImportConfig)

	// Оборачиваем роутер в Middleware для авторизации по сессионным Cookies.
	handlerWithAuth := sessionAuthMiddleware(mux)

	// Настройка HTTP-сервера.
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      handlerWithAuth,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Канал для отслеживания сигналов завершения процесса (graceful shutdown).
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("Панель управления запущена", "address", "http://localhost:"+port, "config", configPath)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Критическая ошибка HTTP-сервера", "error", err)
			os.Exit(1)
		}
	}()

	// Ожидаем сигнал прерывания.
	<-stop
	slog.Info("Завершение работы vigilum-admin...")

	// Даем серверу 5 секунд на завершение активных запросов.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("Ошибка при graceful shutdown сервера", "error", err)
	}

	slog.Info("Панель управления успешно остановлена")
}

// Структура для параметров входа
type LoginCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Генерация случайного безопасного сессионного токена
func generateSessionToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Резервный вариант на случай непредвиденных ошибок с энтропией
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// POST /api/auth/login: Проверяет учетные данные и устанавливает сессионную куку.
func handleLogin(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var creds LoginCredentials
	if err := json.Unmarshal(bodyBytes, &creds); err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	// Сравнение учетных данных с защитой от атак по времени (Timing Attacks)
	if subtle.ConstantTimeCompare([]byte(creds.Username), []byte(adminUser)) != 1 ||
		subtle.ConstantTimeCompare([]byte(creds.Password), []byte(adminPass)) != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Неверное имя пользователя или пароль"}`))
		return
	}

	// Создаем сессионный токен
	token := generateSessionToken()

	sessionsMu.Lock()
	sessions[token] = time.Now().Add(sessionDuration)
	sessionsMu.Unlock()

	// Устанавливаем HTTP-only куку
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(sessionDuration),
		HttpOnly: true,
		Secure:   false, // false для возможности локального тестирования по HTTP
		SameSite: http.SameSiteStrictMode,
	})

	slog.Info("Администратор успешно вошел в систему", "username", creds.Username)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// POST /api/auth/logout: Сбрасывает текущую сессию и удаляет куку.
func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err == nil {
		sessionsMu.Lock()
		delete(sessions, cookie.Value)
		sessionsMu.Unlock()
	}

	// Удаляем куку на клиенте (сдвигая время назад)
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
	})

	slog.Info("Администратор вышел из системы")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// Middleware для авторизации на основе сессионных Cookies.
func sessionAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Разрешаем свободный доступ к главной странице и эндпоинту входа
		if r.URL.Path == "/" || r.URL.Path == "/api/auth/login" {
			next.ServeHTTP(w, r)
			return
		}

		// Для остальных эндпоинтов проверяем куку сессии
		cookie, err := r.Cookie("session_token")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("401 Unauthorized\n"))
			return
		}

		token := cookie.Value
		sessionsMu.Lock()
		expireTime, exists := sessions[token]
		if !exists || time.Now().After(expireTime) {
			if exists {
				delete(sessions, token)
			}
			sessionsMu.Unlock()
			
			// Сбрасываем невалидную куку
			http.SetCookie(w, &http.Cookie{
				Name:     "session_token",
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
				Secure:   false,
				SameSite: http.SameSiteStrictMode,
			})
			
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("401 Unauthorized\n"))
			return
		}

		// Продлеваем сессию при активности (sliding window)
		sessions[token] = time.Now().Add(sessionDuration)
		sessionsMu.Unlock()

		next.ServeHTTP(w, r)
	})
}

// Отдает встроенный index.html с запретом кэширования, чтобы изменения версий вступали в силу сразу.
func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(indexHTML)
}

// GET /api/config: Читает config.yaml и отдает его в JSON-формате.
func handleGetConfig(w http.ResponseWriter, r *http.Request) {
	configMu.Lock()
	defer configMu.Unlock()

	cfg, err := readConfigFile()
	if err != nil {
		slog.Error("Не удалось прочитать файл конфигурации", "path", configPath, "error", err)
		http.Error(w, "Failed to read configuration file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Добавляем заголовок с меткой времени изменения файла для синхронизации
	setConfigLastModifiedHeader(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(cfg)
}

// POST /api/config: Принимает обновленный JSON, валидирует и записывает в config.yaml.
func handleSaveConfig(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var newCfg Config
	if err := json.Unmarshal(bodyBytes, &newCfg); err != nil {
		http.Error(w, "Invalid JSON format: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Валидация конфигурации.
	if err := validateConfig(newCfg); err != nil {
		slog.Warn("Ошибка валидации конфигурации при сохранении", "error", err)
		http.Error(w, "Validation error: "+err.Error(), http.StatusBadRequest)
		return
	}

	configMu.Lock()
	defer configMu.Unlock()

	// Записываем обновленные данные в файл.
	if err := writeConfigFile(newCfg); err != nil {
		slog.Error("Не удалось записать конфигурацию в файл", "path", configPath, "error", err)
		http.Error(w, "Failed to write configuration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("Конфигурация успешно обновлена администратором")
	// Добавляем заголовок с меткой времени изменения файла для синхронизации
	setConfigLastModifiedHeader(w)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"saved"}`))
}

// POST /api/services/toggle: Быстро переключает флаг enabled у сервиса по его ID.
func handleToggleService(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req ToggleRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.ID == "" {
		http.Error(w, "Service ID is required", http.StatusBadRequest)
		return
	}

	configMu.Lock()
	defer configMu.Unlock()

	// Читаем текущий файл.
	cfg, err := readConfigFile()
	if err != nil {
		http.Error(w, "Failed to read configuration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Ищем сервис по ID и меняем его флаг enabled.
	found := false
	for i := range cfg.Services {
		if cfg.Services[i].ID == req.ID {
			cfg.Services[i].Enabled = req.Enabled
			found = true
			break
		}
	}

	if !found {
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}

	// Перезаписываем файл.
	if err := writeConfigFile(*cfg); err != nil {
		http.Error(w, "Failed to write configuration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("Статус мониторинга сервиса изменен", "id", req.ID, "enabled", req.Enabled)
	// Добавляем заголовок с меткой времени изменения файла для синхронизации
	setConfigLastModifiedHeader(w)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// GET /api/config/export: Отдает рав файл config.yaml для скачивания на компьютер администратора.
func handleExportConfig(w http.ResponseWriter, r *http.Request) {
	configMu.Lock()
	defer configMu.Unlock()

	// Читаем файл как есть, чтобы сохранить оригинальное форматирование YAML.
	fileBytes, err := os.ReadFile(configPath)
	if err != nil {
		slog.Error("Не удалось прочитать конфигурацию для экспорта", "error", err)
		http.Error(w, "Failed to read configuration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Заголовки для скачивания: браузер откроет диалог сохранения файла.
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="config.yaml"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(fileBytes)
}

// POST /api/config/import: Принимает загруженный YAML-файл, валидирует и применяет его как новую конфигурацию.
func handleImportConfig(w http.ResponseWriter, r *http.Request) {
	// Ограничиваем размер загрузки до 1 МБ для защиты от злоупотребления.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	if err := r.ParseMultipartForm(1 << 20); err != nil {
		http.Error(w, "Failed to parse upload: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Получаем файл из поля формы "config".
	file, _, err := r.FormFile("config")
	if err != nil {
		http.Error(w, "No file provided (expected field name: 'config'): "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read uploaded file: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Парсим YAML-структуру.
	var cfg Config
	if err := yaml.Unmarshal(fileBytes, &cfg); err != nil {
		http.Error(w, "Invalid YAML format: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Валидируем структуру конфигурации.
	if err := validateConfig(cfg); err != nil {
		slog.Warn("Ошибка валидации при импорте конфигурации", "error", err)
		http.Error(w, "Validation error: "+err.Error(), http.StatusBadRequest)
		return
	}

	configMu.Lock()
	defer configMu.Unlock()

	// Записываем валидированную конфигурацию на диск.
	if err := writeConfigFile(cfg); err != nil {
		slog.Error("Не удалось записать импортируемую конфигурацию", "error", err)
		http.Error(w, "Failed to write configuration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("Конфигурация успешно импортирована из файла администратором")
	// Добавляем заголовок с меткой времени изменения файла для синхронизации
	setConfigLastModifiedHeader(w)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"imported"}`))
}

// Вспомогательная функция чтения файла конфигурации.
func readConfigFile() (*Config, error) {
	fileBytes, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Если файл не существует, возвращаем пустую конфигурацию.
			return &Config{Services: []ServiceConfig{}}, nil
		}
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(fileBytes, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Добавляет заголовок X-Config-Last-Modified со временем последнего изменения файла конфигурации.
// Это необходимо фронтенду для автоматического отслеживания внешних изменений.
func setConfigLastModifiedHeader(w http.ResponseWriter) {
	info, err := os.Stat(configPath)
	if err == nil {
		w.Header().Set("X-Config-Last-Modified", fmt.Sprintf("%d", info.ModTime().Unix()))
	}
}

// Вспомогательная функция записи файла конфигурации.
func writeConfigFile(cfg Config) error {
	yamlBytes, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	// Записываем с правами 0644.
	return os.WriteFile(configPath, yamlBytes, 0644)
}

// Валидирует параметры конфигурации на корректность.
func validateConfig(cfg Config) error {
	seenIDs := make(map[string]bool)

	for _, svc := range cfg.Services {
		if svc.ID == "" {
			return errors.New("each service must have an 'id'")
		}
		if seenIDs[svc.ID] {
			return fmt.Errorf("duplicate service 'id' found: %s", svc.ID)
		}
		seenIDs[svc.ID] = true

		if svc.Name == "" {
			return fmt.Errorf("service '%s' must have a 'name'", svc.ID)
		}

		if svc.Target == "" {
			return fmt.Errorf("service '%s' must have a 'target'", svc.ID)
		}

		// Валидируем тип.
		switch svc.Type {
		case "ping", "http", "https", "tcp", "udp", "webadmin":
			// Валидный тип.
		default:
			return fmt.Errorf("service '%s' has unsupported type '%s'", svc.ID, svc.Type)
		}

		// Для http/https/webadmin проверяем корректность URL.
		if svc.Type == "http" || svc.Type == "https" || svc.Type == "webadmin" {
			if _, err := url.ParseRequestURI(svc.Target); err != nil {
				return fmt.Errorf("target for '%s' must be a valid URL: %w", svc.ID, err)
			}
		}

		// Для webadmin обязательны username и password.
		if svc.Type == "webadmin" {
			if svc.Username == "" || svc.Password == "" {
				return fmt.Errorf("service Webadmin '%s' requires both 'username' and 'password'", svc.ID)
			}
		}

		// Проверяем формат retry_interval, если задан.
		if svc.RetryInterval != "" {
			if _, err := time.ParseDuration(svc.RetryInterval); err != nil {
				return fmt.Errorf("service '%s' has invalid retry_interval format: %w", svc.ID, err)
			}
		}
	}

	return nil
}

// GET /api/statuses: Запрашивает текущие статусы у демона Vigilum и проксирует их клиенту.
func handleGetStatuses(w http.ResponseWriter, r *http.Request) {
	client := http.Client{
		Timeout: 2 * time.Second,
	}

	resp, err := client.Get(vigilumAPIURL + "/api/statuses")
	if err != nil {
		slog.Warn("Не удалось связаться с демоном Vigilum для получения статусов", "url", vigilumAPIURL, "error", err)
		// Возвращаем пустой объект, чтобы фронтенд перешел в режим ожидания (Unknown / Checking)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("Демон Vigilum вернул некорректный статус-код", "code", resp.StatusCode)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
		return
	}

	// Добавляем заголовок с меткой времени изменения файла для синхронизации
	setConfigLastModifiedHeader(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, resp.Body)
}

// Инициализирует глобальный логгер slog в зависимости от переменной окружения LOG_LEVEL.
// По умолчанию используется уровень логирования INFO для обеспечения сбалансированного вывода.
func initLogger() {
	logLevelStr := os.Getenv("LOG_LEVEL")
	var level slog.Level

	// Определяем уровень логирования на основе полученного из окружения значения
	switch logLevelStr {
	case "DEBUG":
		level = slog.LevelDebug
	case "WARN", "WARNING":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}
	// Создаем текстовый обработчик логов с выводом в стандартный поток вывода
	handler := slog.NewTextHandler(os.Stdout, opts)
	slog.SetDefault(slog.New(handler))
}


