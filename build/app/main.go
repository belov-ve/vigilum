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

// Состояние отдельного подсервиса (systemd службы) панели Webadmin.
type SubServiceStatus struct {
	Name        string `json:"name"`
	ServiceName string `json:"service_name"`
	Enabled     bool   `json:"enabled"`
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
	Healthy     bool   `json:"healthy"`
}

// Текущий статус работоспособности конкретного сервиса.
type ServiceStatus struct {
	Healthy     bool               `json:"healthy"`
	LastCheck   time.Time          `json:"last_check"`
	LastError   string             `json:"last_error,omitempty"`
	SubServices []SubServiceStatus `json:"sub_services,omitempty"` // Список подсервисов (только для типа webadmin)
}

var (
	// Карта активных воркеров для горячей перезагрузки конфигурации.
	activeWorkers = make(map[string]*RunningWorker)
	workersMu     sync.Mutex
	wg            sync.WaitGroup

	// Хранилище текущих статусов здоровья сервисов в оперативной памяти.
	serviceStatuses = make(map[string]ServiceStatus)
	statusesMu      sync.RWMutex
)

func main() {
	// 1. Инициализация структурированного логирования со строгими уровнями.
	initLogger()
	slog.Info("Запуск сервиса Vigilum v1.3.1")

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

	// Запоминаем, какие воркеры были активны до обновления конфигурации.
	wasActive := make(map[string]bool)
	for id := range activeWorkers {
		wasActive[id] = true
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

			// Удаляем статус здоровья из глобальной карты только при полном удалении сервиса из конфигурации.
			// Если сервис просто изменен или временно отключен, сохраняем его последний статус здоровья для
			// корректного определения восстановления работы (AlertUp) при его повторном запуске.
			if !exists {
				statusesMu.Lock()
				delete(serviceStatuses, id)
				statusesMu.Unlock()
			}

			// Отправляем уведомление об отключении мониторинга только если сервис был удален или выключен тумблером.
			// Если воркер перезапускается из-за изменения параметров, уведомление не посылаем.
			if !exists || !newSvc.Enabled {
				_ = SendAlert(safeConfig, AlertDisabled, worker.config.Name, "")
			}
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

			// Вывод предупреждения в лог при использовании кастомных UDP портов
			if newSvc.Type == "udp" {
				_, port, err := net.SplitHostPort(newSvc.Target)
				if err == nil {
					if port != "53" && port != "123" && port != "3478" && port != "161" && port != "5060" {
						slog.Warn("Сервис использует кастомный UDP-порт. Проверка выполняется пустым пакетом; ее достоверность зависит от доступности ICMP-ответов на целевом хосте.", "service", id, "port", port)
					}
				} else {
					slog.Warn("Сервис использует UDP-проверку без явного указания стандартного порта. Проверка выполняется пустым пакетом.", "service", id, "target", newSvc.Target)
				}
			}

			workerCtx, workerCancel := context.WithCancel(ctx)
			// Передаем флаг первоначального старта через контекст воркера
			workerCtx = context.WithValue(workerCtx, "isInitialStart", isInitialStart)
			// Передаем флаг повторного запуска (рестарта из-за изменения параметров) через контекст воркера
			workerCtx = context.WithValue(workerCtx, "isRestart", wasActive[id])

			activeWorkers[id] = &RunningWorker{
				cancel: workerCancel,
				config: newSvc,
			}

			// Отправляем уведомление о начале мониторинга только при горячей перезагрузке
			// и только если сервис не был активен до этого (т.е. это не перезапуск из-за изменения параметров).
			if !isInitialStart && !wasActive[id] {
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

			// Проверяем наличие предыдущего статуса в глобальной карте ДО ее обновления.
			var wasUnhealthy bool
			statusesMu.Lock()
			if prevStatus, ok := serviceStatuses[svc.ID]; ok {
				wasUnhealthy = !prevStatus.Healthy
			}
			statusesMu.Unlock()

			updateServiceStatus(svc.ID, isCurrentHealthy, err)

			if isFirstRun {

				// Запоминаем начальное состояние службы. Если сервис сразу недоступен,
				// отправляем уведомление об аварии (DOWN), чтобы не пропустить неисправность.
				isPreviousHealthy = isCurrentHealthy
				isFirstRun = false

				// Извлекаем флаги из контекста.
				isInitStart := false
				if val, ok := ctx.Value("isInitialStart").(bool); ok {
					isInitStart = val
				}
				isRestart := false
				if val, ok := ctx.Value("isRestart").(bool); ok {
					isRestart = val
				}

				if isCurrentHealthy {
					slog.Info("Начальное состояние сервиса определено: ДОСТУПЕН", "service", svc.ID)
					// Отправляем AlertUp ("🟢") только если:
					// 1. Это не первоначальный старт демона И сервис новый/вновь включенный (не простой рестарт воркера).
					// 2. Или сервис уже существовал, но ранее был неисправен (wasUnhealthy == true).
					shouldAlertUp := (!isInitStart && !isRestart) || wasUnhealthy
					if shouldAlertUp {
						slog.Info("Отправка оповещения о доступности сервиса при запуске воркера", "service", svc.ID)
						_ = SendAlert(safeConfig, AlertUp, svc.Name, "")
					}
				} else {
					slog.Warn("Начальное состояние сервиса определено: КРИТИЧЕСКОЕ", "service", svc.ID, "error", err)
					_ = SendAlert(safeConfig, AlertDown, svc.Name, err.Error())
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

	// Возвращает актуальный статус здоровья всех контролируемых сервисов в RAM.
	mux.HandleFunc("/api/statuses", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		
		// Чтение глобальной карты под RLock
		statusesMu.RLock()
		defer statusesMu.RUnlock()
		
		// Создаем копию карты статусов с добавлением подсервисов для webadmin-панелей
		responseMap := make(map[string]ServiceStatus)
		for id, status := range serviceStatuses {
			// Проверяем наличие клиента Webadmin в реестре
			registryMu.Lock()
			client, ok := clientsRegistry[id]
			registryMu.Unlock()
			
			if ok && client != nil {
				client.mu.Lock()
				var subs []SubServiceStatus
				for _, item := range client.subStates {
					subs = append(subs, SubServiceStatus{
						Name:        item.Name,
						ServiceName: item.ServiceName,
						Enabled:     item.Enabled,
						ActiveState: item.Status.ActiveState,
						SubState:    item.Status.SubState,
						Healthy:     item.Status.ActiveState == "active" && item.Status.SubState == "running",
					})
				}
				client.mu.Unlock()
				status.SubServices = subs
			}
			responseMap[id] = status
		}
		
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(responseMap)
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

// Обновляет состояние сервиса в глобальной карте.
func updateServiceStatus(id string, healthy bool, err error) {
	statusesMu.Lock()
	defer statusesMu.Unlock()

	var errMsg string
	if err != nil {
		errMsg = err.Error()
	}

	serviceStatuses[id] = ServiceStatus{
		Healthy:   healthy,
		LastCheck: time.Now(),
		LastError: errMsg,
	}
}

