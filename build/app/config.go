package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Содержит шаблоны уведомлений для различных типов событий.
type TemplatesConfig struct {
	Down             string `yaml:"down"`
	Up               string `yaml:"up"`
	Enabled          string `yaml:"enabled"`
	Disabled         string `yaml:"disabled"`
	WebadminEnabled  string `yaml:"webadmin_enabled"`
	WebadminDisabled string `yaml:"webadmin_disabled"`
}

// Описывает параметры мониторинга одного ресурса/сервиса.
type ServiceConfig struct {
	ID            string `yaml:"id"`
	Name          string `yaml:"name"`
	Type          string `yaml:"type"`            // ping, http, https, tcp, udp, webadmin
	Target        string `yaml:"target"`          // хост, IP, URL или адрес порта
	Enabled       bool   `yaml:"enabled"`         // флаг включения/выключения мониторинга
	Retries       *int   `yaml:"retries"`         // индивидуальное кол-во повторов при ошибках (опционально)
	RetryInterval string `yaml:"retry_interval"`  // индивидуальная пауза между повторами (опционально, например "2s")
	Username      string `yaml:"username"`        // имя пользователя (только для типа webadmin)
	Password      string `yaml:"password"`        // пароль (только для типа webadmin)
}

// Глобальная структура настроек приложения, собираемая из файла и переменных окружения.
type Config struct {
	Templates TemplatesConfig `yaml:"templates"`
	Services  []ServiceConfig `yaml:"services"`

	// Внутренние глобальные настройки, задаваемые через переменные окружения.
	Global struct {
		ConfigPath           string
		PollInterval         time.Duration
		DefaultRetries       int
		DefaultRetryInterval time.Duration
		NotifyBotURL         string
		NotifyBotHealthURL   string
	}
}

// Потокобезопасный контейнер для хранения активной конфигурации.
type SafeConfig struct {
	mu     sync.RWMutex
	config *Config
}

func NewSafeConfig(cfg *Config) *SafeConfig {
	return &SafeConfig{config: cfg}
}

// Возвращает копию текущей конфигурации для безопасного чтения.
func (sc *SafeConfig) Get() *Config {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.config
}

// Обновляет конфигурацию.
func (sc *SafeConfig) Set(cfg *Config) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.config = cfg
}

// Загружает конфигурацию из переменных окружения и файла YAML.
func LoadConfig() (*Config, error) {
	cfg := &Config{}

	// Установка значений по умолчанию из переменных окружения.
	cfg.Global.ConfigPath = getEnv("CONFIG_PATH", "config.yaml")

	pollStr := getEnv("POLL_INTERVAL", "10s")
	pollDuration, err := time.ParseDuration(pollStr)
	if err != nil {
		return nil, fmt.Errorf("неверный формат POLL_INTERVAL (%s): %w", pollStr, err)
	}
	cfg.Global.PollInterval = pollDuration

	retriesVal := 3
	retriesStr := getEnv("DEFAULT_RETRIES", "3")
	if _, err := fmt.Sscanf(retriesStr, "%d", &retriesVal); err != nil || retriesVal < 0 {
		return nil, fmt.Errorf("неверный формат DEFAULT_RETRIES (%s), должно быть целое неотрицательное число", retriesStr)
	}
	cfg.Global.DefaultRetries = retriesVal

	retryIntStr := getEnv("DEFAULT_RETRY_INTERVAL", "2s")
	retryIntDuration, err := time.ParseDuration(retryIntStr)
	if err != nil {
		return nil, fmt.Errorf("неверный формат DEFAULT_RETRY_INTERVAL (%s): %w", retryIntStr, err)
	}
	cfg.Global.DefaultRetryInterval = retryIntDuration

	notifyBotURL := getEnv("NOTIFY_BOT_URL", "")
	if notifyBotURL != "" {
		if _, err := url.ParseRequestURI(notifyBotURL); err != nil {
			return nil, fmt.Errorf("неверный формат NOTIFY_BOT_URL (%s): %w", notifyBotURL, err)
		}
	}
	cfg.Global.NotifyBotURL = notifyBotURL

	// Загружаем NOTIFY_BOT_HEALTH_URL. Если она пустая, пробуем автоматически построить на базе NOTIFY_BOT_URL
	notifyBotHealthURL := getEnv("NOTIFY_BOT_HEALTH_URL", "")
	if notifyBotHealthURL == "" && notifyBotURL != "" {
		if u, err := url.Parse(notifyBotURL); err == nil {
			u.Path = "/health"
			notifyBotHealthURL = u.String()
		}
	}
	if notifyBotHealthURL != "" {
		if _, err := url.ParseRequestURI(notifyBotHealthURL); err != nil {
			return nil, fmt.Errorf("неверный формат NOTIFY_BOT_HEALTH_URL (%s): %w", notifyBotHealthURL, err)
		}
	}
	cfg.Global.NotifyBotHealthURL = notifyBotHealthURL

	// Загрузка данных из файла конфигурации YAML, если он существует.
	fileBytes, err := os.ReadFile(cfg.Global.ConfigPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			slog.Warn("Файл конфигурации не найден, используются только переменные окружения", "path", cfg.Global.ConfigPath)
		} else {
			return nil, fmt.Errorf("не удалось прочитать файл конфигурации %s: %w", cfg.Global.ConfigPath, err)
		}
	} else {
		// Парсинг YAML структуры.
		if err := yaml.Unmarshal(fileBytes, cfg); err != nil {
			return nil, fmt.Errorf("ошибка парсинга YAML файла конфигурации: %w", err)
		}
	}

	// Заполнение дефолтных шаблонов на английском языке, если они не были переопределены в файле.
	// В шаблоне аварии (down) ошибка выводится с новой строки.
	if cfg.Templates.Down == "" {
		cfg.Templates.Down = "🔴 Service {name} is down!\nError: {error}"
	}
	if cfg.Templates.Up == "" {
		cfg.Templates.Up = "🟢 Service {name} is available / recovered"
	}
	if cfg.Templates.Enabled == "" {
		cfg.Templates.Enabled = "🔵 Monitoring enabled for service {name}"
	}
	if cfg.Templates.Disabled == "" {
		cfg.Templates.Disabled = "🟡 Monitoring disabled for service {name}"
	}
	if cfg.Templates.WebadminEnabled == "" {
		cfg.Templates.WebadminEnabled = "🔵 Autostart enabled for Webadmin service {name}"
	}
	if cfg.Templates.WebadminDisabled == "" {
		cfg.Templates.WebadminDisabled = "🟡 Autostart disabled for Webadmin service {name}"
	}

	// Валидация загруженной конфигурации.
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Валидирует все параметры конфигурации на корректность и непротиворечивость.
func validateConfig(cfg *Config) error {
	// NOTIFY_BOT_URL обязателен.
	if cfg.Global.NotifyBotURL == "" {
		return errors.New("не задан обязательный URL-адрес для отправки оповещений (NOTIFY_BOT_URL)")
	}

	seenIDs := make(map[string]bool)

	for i, svc := range cfg.Services {
		// Проверка ID на уникальность и заполненность.
		if svc.ID == "" {
			return fmt.Errorf("у сервиса под индексом %d отсутствует обязательное поле 'id'", i)
		}
		if seenIDs[svc.ID] {
			return fmt.Errorf("обнаружен дубликат 'id' в конфигурации сервисов: %s", svc.ID)
		}
		seenIDs[svc.ID] = true

		// Название сервиса обязательно.
		if svc.Name == "" {
			return fmt.Errorf("у сервиса '%s' отсутствует обязательное поле 'name'", svc.ID)
		}

		// Валидация типа сервиса.
		switch svc.Type {
		case "ping", "http", "https", "tcp", "udp", "webadmin":
			// Корректный тип.
		case "":
			return fmt.Errorf("у сервиса '%s' не указан тип ('type')", svc.ID)
		default:
			return fmt.Errorf("у сервиса '%s' указан неизвестный тип проверки '%s'", svc.ID, svc.Type)
		}

		// Target обязателен.
		if svc.Target == "" {
			return fmt.Errorf("у сервиса '%s' не указана цель проверки ('target')", svc.ID)
		}

		// Проверка формата индивидуальной паузы перепроверки, если она задана.
		if svc.RetryInterval != "" {
			if _, err := time.ParseDuration(svc.RetryInterval); err != nil {
				return fmt.Errorf("у сервиса '%s' некорректный формат retry_interval '%s': %w", svc.ID, svc.RetryInterval, err)
			}
		}

		// Валидация параметров Webadmin.
		if svc.Type == "webadmin" {
			if svc.Username == "" || svc.Password == "" {
				return fmt.Errorf("для сервиса Webadmin '%s' необходимо заполнить имя пользователя ('username') и пароль ('password')", svc.ID)
			}
			// Проверка URL.
			if _, err := url.ParseRequestURI(svc.Target); err != nil {
				return fmt.Errorf("целевой адрес Webadmin '%s' (%s) должен быть валидным URL-адресом: %w", svc.ID, svc.Target, err)
			}
		}

		// Для http/https также проверяем корректность URL.
		if svc.Type == "http" || svc.Type == "https" {
			if _, err := url.ParseRequestURI(svc.Target); err != nil {
				return fmt.Errorf("адрес target для HTTP/HTTPS проверки '%s' (%s) должен быть валидным URL-адресом: %w", svc.ID, svc.Target, err)
			}
		}
	}

	return nil
}

// Запускает фоновый цикл отслеживания изменений файла конфигурации.
func WatchConfig(configPath string, onChange func(*Config)) {
	// Запоминаем время последнего изменения файла при запуске.
	lastModTime := getFileModTime(configPath)

	// Опрос файла конфигурации каждые 3 секунды (ModTime polling).
	ticker := time.NewTicker(3 * time.Second)
	go func() {
		// Перехват аварийных ситуаций (паник) для исключения падения всего приложения при отслеживании конфига.
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Критическая аварийная ситуация (паника) при отслеживании конфигурации", "panic", r)
			}
		}()
		for range ticker.C {
			currentModTime := getFileModTime(configPath)
			if !currentModTime.IsZero() && !currentModTime.Equal(lastModTime) {
				slog.Info("Обнаружено изменение файла конфигурации, выполняется перезагрузка...", "path", configPath)
				
				// Пытаемся загрузить измененную конфигурацию.
				newCfg, err := LoadConfig()
				if err != nil {
					// При горячей перезагрузке ошибка не прерывает приложение, а логируется с уровнем ERROR.
					slog.Error("Не удалось применить измененную конфигурацию. Сохранена прежняя рабочая конфигурация.", "error", err)
				} else {
					slog.Info("Конфигурация успешно перезагружена на лету")
					lastModTime = currentModTime
					onChange(newCfg)
				}
			}
		}
	}()
}

// Возвращает значение переменной окружения или дефолтное значение, если она пуста.
func getEnv(key, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultVal
}

// Безопасно возвращает ModTime файла, возвращая нулевое время при ошибке доступа.
func getFileModTime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}
