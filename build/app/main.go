package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata"
)

// Состояние запущенного воркера мониторинга сервиса.
type RunningWorker struct {
	cancel context.CancelFunc
	config ServiceConfig
}

var (
	// Карта активных воркеров для горячей перезагрузки конфигурации.
	activeWorkers = make(map[string]*RunningWorker)
	workersMu     sync.Mutex
	wg            sync.WaitGroup
)

func main() {
	// 1. Инициализация структурированного логирования со строгими уровнями.
	initLogger()
	slog.Info("Запуск сервиса Vigilum v1.0.0")

	// 2. Первоначальная загрузка конфигурации.
	cfg, err := LoadConfig()
	if err != nil {
		slog.Error("Критическая ошибка при запуске: не удалось загрузить конфигурацию", "error", err)
		os.Exit(1)
	}

	safeConfig := NewSafeConfig(cfg)

	// 2.1. Проверка доступности службы notify-bot при старте.
	if err := CheckNotifyBotHealth(safeConfig); err != nil {
		slog.Warn("Служба notify-bot недоступна по адресу проверки здоровья. Уведомления могут не доставляться.", "url", cfg.Global.NotifyBotHealthURL, "error", err)
	} else {
		slog.Info("Служба notify-bot доступна и здорова (healthcheck OK)", "url", cfg.Global.NotifyBotHealthURL)
	}

	// 2.2. Синхронизация реестра Webadmin-клиентов при первоначальном запуске.
	SyncWebadminClients(cfg.Services)

	// Создаем корневой контекст для отмены всех фоновых задач при завершении.
	mainCtx, mainCancel := context.WithCancel(context.Background())
	defer mainCancel()

	// 3. Запуск HTTP-сервера для docker healthcheck.
	startHealthCheckServer(mainCtx)

	// 4. Запуск планировщика воркеров на основе текущей конфигурации.
	applyConfiguration(mainCtx, safeConfig, true)

	// 5. Запуск фонового отслеживания изменений файла конфигурации.
	WatchConfig(cfg.Global.ConfigPath, func(newCfg *Config) {
		// Обновляем потокобезопасный контейнер конфигурации.
		safeConfig.Set(newCfg)

		// Синхронизируем Webadmin-клиентов с новой конфигурацией (удаляем неиспользуемые,
		// но сохраняем состояние сессий и подсервисов для продолжающих работу).
		SyncWebadminClients(newCfg.Services)

		// Применяем изменения к работающим воркерам.
		applyConfiguration(mainCtx, safeConfig, false)
	})

	// 6. Ожидание сигналов завершения работы (SIGINT, SIGTERM) для graceful shutdown.
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-signalChan
	slog.Info("Получен сигнал завершения работы, инициирован Graceful Shutdown...", "signal", sig.String())

	// Останавливаем все воркеры.
	mainCancel()

	// Ожидаем завершения всех горутин мониторинга.
	doneChan := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneChan)
	}()

	select {
	case <-doneChan:
		slog.Info("Все задачи мониторинга успешно завершены. Выход.")
	case <-time.After(5 * time.Second):
		slog.Warn("Истек таймаут ожидания завершения задач. Принудительный выход.")
	}
}

// Настраивает глобальный логгер slog в зависимости от переменной окружения LOG_LEVEL.
func initLogger() {
	logLevelStr := os.Getenv("LOG_LEVEL")
	var level slog.Level

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
	handler := slog.NewTextHandler(os.Stdout, opts)
	slog.SetDefault(slog.New(handler))
}

// Применяет изменения конфигурации: запускает новые воркеры, останавливает отключенные или измененные.
func applyConfiguration(ctx context.Context, safeConfig *SafeConfig, isInitialStart bool) {
	workersMu.Lock()
	defer workersMu.Unlock()

	cfg := safeConfig.Get()
	newServicesMap := make(map[string]ServiceConfig)

	for _, svc := range cfg.Services {
		newServicesMap[svc.ID] = svc
	}

	// 1. Останавливаем воркеры для сервисов, которые были удалены или выключены.
	for id, worker := range activeWorkers {
		newSvc, exists := newServicesMap[id]
		
		// Проверяем, изменились ли retries (учитывая nil-указатели)
		var oldRetries, newRetries int
		if worker.config.Retries != nil {
			oldRetries = *worker.config.Retries
		} else {
			oldRetries = -1
		}
		if newSvc.Retries != nil {
			newRetries = *newSvc.Retries
		} else {
			newRetries = -1
		}

		// Условия для остановки: сервис удален или отключен (enabled: false), или изменились параметры.
		shouldStop := !exists || !newSvc.Enabled || 
			worker.config.Name != newSvc.Name ||
			worker.config.Target != newSvc.Target || 
			worker.config.Type != newSvc.Type ||
			worker.config.Username != newSvc.Username ||
			worker.config.Password != newSvc.Password ||
			worker.config.RetryInterval != newSvc.RetryInterval ||
			oldRetries != newRetries

		if shouldStop {
			slog.Info("Остановка воркера мониторинга для сервиса", "id", id)
			worker.cancel()
			delete(activeWorkers, id)

			// Отправляем уведомление, что мониторинг сервиса отключен.
			_ = SendAlert(safeConfig, AlertDisabled, worker.config.Name, "")
		}
	}

	// 2. Запускаем воркеры для новых или вновь включенных сервисов.
	for id, newSvc := range newServicesMap {
		if !newSvc.Enabled {
			continue
		}

		// Если воркера нет в активных, значит запускаем.
		if _, exists := activeWorkers[id]; !exists {
			slog.Info("Запуск воркера мониторинга для сервиса", "id", id, "type", newSvc.Type)

			workerCtx, workerCancel := context.WithCancel(ctx)
			activeWorkers[id] = &RunningWorker{
				cancel: workerCancel,
				config: newSvc,
			}

			// Отправляем уведомление о начале мониторинга только при горячей перезагрузке,
			// но не при первоначальном запуске всего приложения.
			if !isInitialStart {
				_ = SendAlert(safeConfig, AlertEnabled, newSvc.Name, "")
			}

			// Запуск горутины опроса.
			wg.Add(1)
			go runServiceMonitorLoop(workerCtx, safeConfig, newSvc)
		}
	}
}

// Фоновый цикл периодического опроса состояния конкретного сервиса.
func runServiceMonitorLoop(ctx context.Context, safeConfig *SafeConfig, svc ServiceConfig) {
	defer wg.Done()

	// Перехват аварийных ситуаций (паник) для исключения падения всего приложения при сбое отдельной проверки.
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Критическая аварийная ситуация (паника) в воркере мониторинга", "service", svc.ID, "panic", r)
		}
	}()

	// Переменная для отслеживания предыдущего статуса (true = здоров, false = авария).
	// Инициализируем nil-подобным состоянием (используем вспомогательный флаг первого запуска).
	isFirstRun := true
	isPreviousHealthy := true

	// Запуск первого шага проверки немедленно.
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Debug("Фоновый цикл опроса завершен по контексту", "service", svc.ID)
			return
		case <-timer.C:
			// Выполняем проверку с учетом повторов при ошибках.
			err := RunCheckWithRetries(ctx, safeConfig, svc)
			isCurrentHealthy := (err == nil)

			if isFirstRun {
				// Запоминаем начальное состояние службы без отправки уведомлений.
				isPreviousHealthy = isCurrentHealthy
				isFirstRun = false
				if isCurrentHealthy {
					slog.Info("Начальное состояние сервиса определено: ДОСТУПЕН", "service", svc.ID)
				} else {
					slog.Warn("Начальное состояние сервиса определено: КРИТИЧЕСКОЕ", "service", svc.ID, "error", err)
				}
			} else {
				// Фиксируем изменение состояния.
				if isPreviousHealthy && !isCurrentHealthy {
					// Сервис упал.
					slog.Error("Сервис перешел в КРИТИЧЕСКОЕ состояние", "service", svc.ID, "error", err)
					_ = SendAlert(safeConfig, AlertDown, svc.Name, err.Error())
					isPreviousHealthy = false
				} else if !isPreviousHealthy && isCurrentHealthy {
					// Сервис восстановился.
					slog.Info("Сервис восстановил работу (ДОСТУПЕН)", "service", svc.ID)
					_ = SendAlert(safeConfig, AlertUp, svc.Name, "")
					isPreviousHealthy = true
				}
			}

			// Планируем следующий опрос, читая его интервал динамически на случай hot-reload.
			timer.Reset(safeConfig.Get().Global.PollInterval)
		}
	}
}

// Запускает встроенный HTTP-сервер для docker healthcheck.
func startHealthCheckServer(ctx context.Context) {
	port := os.Getenv("HEALTH_PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "healthy", "time": time.Now().Format(time.RFC3339)})
	})

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	// Запускаем HTTP-сервер в фоновом режиме.
	go func() {
		// Перехват аварийных ситуаций (паник) для исключения падения всего приложения при сбое сервера.
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Критическая аварийная ситуация (паника) HTTP healthcheck сервера", "panic", r)
			}
		}()
		slog.Info("Запуск встроенного HTTP-сервера для healthcheck", "port", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Не удалось запустить healthcheck сервер", "error", err)
		}
	}()

	// Ожидаем готовности HTTP-сервера (когда порт начнет отвечать),
	// чтобы избежать ложных срабатываний проверок self-tcp при старте.
	for i := 0; i < 20; i++ {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 25*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Горутина корректной остановки сервера при отмене общего контекста.
	go func() {
		// Перехват аварийных ситуаций (паник) при graceful shutdown сервера.
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Критическая аварийная ситуация (паника) при остановке HTTP-сервера", "panic", r)
			}
		}()
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		slog.Debug("Healthcheck HTTP-сервер остановлен")
	}()
}
