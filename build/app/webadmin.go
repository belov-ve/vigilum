package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"time"
)

// Описание структуры запроса авторизации.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Описание структуры ответа по состоянию отдельного подсервиса.
type WebadminStatus struct {
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
}

type WebadminConfigItem struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Type        string         `json:"type"`
	ServiceName string         `json:"service_name"`
	Enabled     bool           `json:"enabled"`
	Status      WebadminStatus `json:"status"`
}

type WebadminConfigsResponse struct {
	Items []WebadminConfigItem `json:"items"`
}

// Описание структуры ответа общего статуса Webadmin.
type SystemStatusResponse struct {
	Service string `json:"service"`
	Status  struct {
		ActiveState string `json:"active_state"`
		SubState    string `json:"sub_state"`
	} `json:"status"`
}

// Вспомогательная структура для отслеживания истории переходов состояний подсервисов.
type SubServiceHistory struct {
	LastPendingState string // "running", "stopped", "failed"
	ConsecutiveCount int
}

// Внутреннее состояние конкретного клиента Webadmin.
type WebadminClient struct {
	mu           sync.Mutex
	id           string
	targetURL    string
	username     string
	password     string
	httpClient   *http.Client
	subStates    map[string]WebadminConfigItem
	subHistories map[string]SubServiceHistory // История стабилизации физических состояний подсервисов
	initialized  bool
}

var (
	// Глобальный реестр клиентов для исключения пересоздания соединений и сессий при каждом опросе.
	clientsRegistry = make(map[string]*WebadminClient)
	registryMu      sync.Mutex
)

// Возвращает существующий или инициализирует новый клиент Webadmin для переданной конфигурации.
func getWebadminClient(svc ServiceConfig) *WebadminClient {
	registryMu.Lock()
	defer registryMu.Unlock()

	client, exists := clientsRegistry[svc.ID]
	if !exists {
		// Инициализация cookie jar для автоматического управления куками сессии.
		jar, _ := cookiejar.New(nil)
		httpClient := &http.Client{
			Timeout: 5 * time.Second,
			Jar:     jar,
			// Запрещаем автоматическое следование по редиректам, так как X-UI панели
			// при протухании сессии могут редиректить (302) на форму авторизации.
			// Вместо этого мы вернем исходный ответ 302 и обработаем его для повторного входа.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		client = &WebadminClient{
			id:           svc.ID,
			targetURL:    svc.Target,
			username:     svc.Username,
			password:     svc.Password,
			httpClient:   httpClient,
			subStates:    make(map[string]WebadminConfigItem),
			subHistories: make(map[string]SubServiceHistory),
		}
		clientsRegistry[svc.ID] = client
		slog.Debug("Инициализирован новый клиент Webadmin", "id", svc.ID, "target", svc.Target)
	} else {
		// Если клиент уже существует, проверяем, не изменились ли настройки подключения/авторизации.
		client.mu.Lock()
		if client.targetURL != svc.Target || client.username != svc.Username || client.password != svc.Password {
			slog.Info("Обнаружено изменение настроек авторизации/URL для Webadmin. Сброс сессионных кук.", "id", svc.ID)
			// При изменении реквизитов подключения сбрасываем только сессию (cookie jar),
			// но сохраняем историю состояний подсервисов и флаг инициализации.
			jar, _ := cookiejar.New(nil)
			client.httpClient.Jar = jar
			client.targetURL = svc.Target
			client.username = svc.Username
			client.password = svc.Password
		}
		client.mu.Unlock()
	}

	return client
}

// Главная функция проверки работоспособности Webadmin, вызываемая из checker.go.
func checkWebadmin(ctx context.Context, safeConfig *SafeConfig, svc ServiceConfig) error {
	client := getWebadminClient(svc)

	// Блокируем мьютекс клиента на время проведения транзакции проверки.
	client.mu.Lock()
	defer client.mu.Unlock()

	// 1. Проверяем работоспособность самой службы Webadmin (healthcheck /api/system/status).
	if err := client.checkSystemStatus(ctx); err != nil {
		// Возвращаем ошибку о недоступности службы Webadmin на английском языке.
		return fmt.Errorf("Webadmin service is unavailable: %w", err)
	}

	// 2. Выполняем запрос к списку конфигураций подсервисов.
	items, err := client.fetchConfigs(ctx)
	if err != nil {
		// Возвращаем ошибку получения конфигураций на английском языке.
		return fmt.Errorf("failed to get Webadmin configurations: %w", err)
	}

	// 3. Анализируем состояние подсервисов и отправляем оповещения при их изменении.
	client.processSubServices(safeConfig, svc, items)

	return nil
}

// Выполняет проверку общего статуса системы Webadmin (без авторизации).
func (c *WebadminClient) checkSystemStatus(ctx context.Context) error {
	reqURL := fmt.Sprintf("%s/api/system/status", c.targetURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Возвращаем ошибку с кодом ответа на английском языке (избегаем дублирования кода из resp.Status).
		return fmt.Errorf("server response: %s", resp.Status)
	}

	// Читаем и декодируем ответ для проверки корректности JSON.
	var sysStatus SystemStatusResponse
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		// Возвращаем ошибку чтения ответа на английском языке.
		return fmt.Errorf("failed to read system status response: %w", err)
	}

	if err := json.Unmarshal(body, &sysStatus); err != nil {
		// Возвращаем ошибку некорректного JSON на английском языке.
		return fmt.Errorf("invalid system status response JSON: %w (body:\n%s)", err, prettyPrintJSON(body))
	}

	// Проверяем, что служба находится в активном рабочем состоянии.
	if sysStatus.Status.ActiveState != "active" || sysStatus.Status.SubState != "running" {
		// Возвращаем ошибку неактивной службы на английском языке.
		return fmt.Errorf("Webadmin service is inactive: active_state=%s, sub_state=%s", 
			sysStatus.Status.ActiveState, sysStatus.Status.SubState)
	}

	return nil
}

// Выполняет авторизацию в Webadmin для получения сессионной куки.
func (c *WebadminClient) login(ctx context.Context) error {
	reqURL := fmt.Sprintf("%s/api/auth/login", c.targetURL)
	loginData := LoginRequest{
		Username: c.username,
		Password: c.password,
	}

	jsonBytes, err := json.Marshal(loginData)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	slog.Debug("Попытка авторизации в Webadmin...", "id", c.id, "url", reqURL)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Успешным кодом авторизации считаем 200 OK или любые перенаправления (302/303/307),
	// которые X-UI панели могут возвращать для перенаправления на Dashboard после успешного входа.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound &&
		resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusTemporaryRedirect {
		body, _ := io.ReadAll(resp.Body)
		// Возвращаем ошибку авторизации на английском языке.
		return fmt.Errorf("authorization error (code %d):\n%s", resp.StatusCode, prettyPrintJSON(body))
	}

	slog.Info("Успешная авторизация в Webadmin, сессия обновлена", "id", c.id)
	return nil
}

// Запрашивает статус конфигураций подсервисов. Автоматически выполняет повторную авторизацию при 401 ошибке.
func (c *WebadminClient) fetchConfigs(ctx context.Context) ([]WebadminConfigItem, error) {
	reqURL := fmt.Sprintf("%s/api/configs", c.targetURL)

	// Вспомогательная функция для выполнения запроса.
	doRequest := func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, err
		}
		return c.httpClient.Do(req)
	}

	resp, err := doRequest()
	if err != nil {
		return nil, err
	}

	// Если сессия неактивна (401) или происходит перенаправление (302/303/307) на форму логина,
	// пробуем авторизоваться заново и повторить запрос.
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusFound ||
		resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusTemporaryRedirect {
		resp.Body.Close()
		slog.Warn("Webadmin session expired or requires login, performing re-authorization...", "id", c.id, "status", resp.StatusCode)
		
		if err := c.login(ctx); err != nil {
			// Возвращаем ошибку повторной авторизации на английском языке.
			return nil, fmt.Errorf("re-authorization failed: %w", err)
		}

		// Повторяем запрос с обновленной сессией.
		resp, err = doRequest()
		if err != nil {
			return nil, err
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		// Возвращаем ошибку с кодом ответа при запросе конфигураций на английском языке (избегаем дублирования статус-кода).
		return nil, fmt.Errorf("error when fetching configurations: %s (body:\n%s)", resp.Status, prettyPrintJSON(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var res WebadminConfigsResponse
	if err := json.Unmarshal(body, &res); err != nil {
		// Возвращаем ошибку парсинга конфигураций на английском языке.
		return nil, fmt.Errorf("failed to parse configurations JSON: %w (body:\n%s)", err, prettyPrintJSON(body))
	}

	return res.Items, nil
}

// Сравнивает текущие состояния внутренних подсервисов с предыдущими и отправляет уведомления с учетом стабилизации.
func (c *WebadminClient) processSubServices(safeConfig *SafeConfig, svc ServiceConfig, items []WebadminConfigItem) {
	parentName := svc.Name
	// Логируем количество полученных подсервисов с уровнем DEBUG для предотвращения спама в INFO.
	slog.Debug("Retrieved subservices list from Webadmin API", "parent", parentName, "count", len(items))

	// Определяем порог стабилизации (количество проверок).
	// Порог берется из индивидуальных настроек retries сервиса, либо из глобального DEFAULT_RETRIES.
	stabilizationThreshold := 3 // значение по умолчанию
	if svc.Retries != nil {
		stabilizationThreshold = *svc.Retries
	} else {
		stabilizationThreshold = safeConfig.Get().Global.DefaultRetries
	}
	if stabilizationThreshold < 1 {
		stabilizationThreshold = 1
	}

	currentMap := make(map[string]WebadminConfigItem)
	for _, item := range items {
		// Защита: если service_name пуст, используем ID для генерации ключа, чтобы не сгруппировать все пустые элементы в один
		sName := item.ServiceName
		if sName == "" {
			sName = "id-" + item.ID
			item.ServiceName = sName
			slog.Warn("Подсервис Webadmin имеет пустой service_name. Сгенерирован временный ключ.", "name", item.Name, "generated_key", sName)
		}
		currentMap[sName] = item
	}

	// Если это первый запуск проверки, просто инициализируем состояние без отправки уведомлений.
	if !c.initialized {
		for sName, item := range currentMap {
			c.subStates[sName] = item
			slog.Info("Начальное состояние подсервиса Webadmin", 
				"parent", parentName, 
				"name", item.Name, 
				"service_name", sName, 
				"enabled", item.Enabled, 
				"active_state", item.Status.ActiveState, 
				"sub_state", item.Status.SubState)
		}
		c.initialized = true
		slog.Info("Инициализация начальных состояний подсервисов Webadmin успешно завершена", "id", c.id, "count", len(currentMap))
		return
	}

	// 1. Проверяем изменения состояния и удаленные сервисы.
	for sName, oldItem := range c.subStates {
		fullName := fmt.Sprintf("%s / %s (%s)", parentName, oldItem.Name, oldItem.ServiceName)

		newItem, exists := currentMap[sName]
		if !exists {
			// Сервис был полностью удален из Webadmin.
			slog.Info("Внутренний сервис Webadmin удален", "parent", parentName, "service", oldItem.Name, "service_name", sName)
			// Присылаем оповещение об удалении подсервиса из панели независимо от его статуса автозапуска.
			_ = SendAlert(safeConfig, AlertDisabled, fullName, "Removed from Webadmin panel")
			delete(c.subStates, sName)
			delete(c.subHistories, sName) // Чистим историю для удаленного подсервиса
			continue
		}

		slog.Debug("Сравнение подсервиса Webadmin", 
			"name", newItem.Name, 
			"service_name", sName, 
			"old_enabled", oldItem.Enabled, 
			"new_enabled", newItem.Enabled, 
			"old_active", oldItem.Status.ActiveState, 
			"new_active", newItem.Status.ActiveState)

		// Определяем физические состояния запуска службы для старого (oldItem) и нового (newItem) состояний.
		// Физическое состояние определяется строго по полям ActiveState и SubState в JSON-ответе.
		
		// Состояние Running (служба успешно запущена и работает)
		oldRunning := oldItem.Status.ActiveState == "active" && oldItem.Status.SubState == "running"
		newRunning := newItem.Status.ActiveState == "active" && newItem.Status.SubState == "running"

		// Состояние Stopped (служба штатно остановлена / выключена)
		oldStopped := oldItem.Status.ActiveState == "inactive" || oldItem.Status.SubState == "dead"
		newStopped := newItem.Status.ActiveState == "inactive" || newItem.Status.SubState == "dead"


		// Классифицируем старое и новое состояние для стабилизации.
		var lastFixedState string
		if oldRunning {
			lastFixedState = "running"
		} else if oldStopped {
			lastFixedState = "stopped"
		} else {
			lastFixedState = "failed"
		}

		var currentState string
		if newRunning {
			currentState = "running"
		} else if newStopped {
			currentState = "stopped"
		} else {
			currentState = "failed"
		}

		// Выполняем проверку стабилизации.
		if currentState == lastFixedState {
			// Состояние совпадает с последним зафиксированным, сбрасываем историю ожидания перехода.
			delete(c.subHistories, sName)

			// Отслеживаем включение автозапуска для уже лежащей службы (если изменился только флаг Enabled).
			if !oldItem.Enabled && newItem.Enabled && !newRunning {
				errDesc := fmt.Sprintf("active_state=%s, sub_state=%s (detected on autostart enable)", newItem.Status.ActiveState, newItem.Status.SubState)
				slog.Warn("Внутренний сервис Webadmin лежит при включении автозапуска", "parent", parentName, "service", newItem.Name, "details", errDesc)
				_ = SendAlert(safeConfig, AlertDown, fullName, errDesc)
			}

			// Обновляем метаданные в локальном кэше (например, Enabled)
			c.subStates[sName] = newItem
		} else {
			// Состояние изменилось, ведем учет последовательных совпадений нового состояния.
			history, hasHistory := c.subHistories[sName]
			if !hasHistory || history.LastPendingState != currentState {
				history = SubServiceHistory{
					LastPendingState: currentState,
					ConsecutiveCount: 1,
				}
			} else {
				history.ConsecutiveCount++
			}

			slog.Debug("Физическое состояние подсервиса Webadmin изменилось, ожидает стабилизации",
				"service", newItem.Name,
				"from", lastFixedState,
				"to", currentState,
				"count", history.ConsecutiveCount,
				"threshold", stabilizationThreshold)

			if history.ConsecutiveCount >= stabilizationThreshold {
				// Состояние стабилизировалось! Отправляем соответствующие алерты.
				
				// 1. Отслеживаем физические переходы состояния службы и отправляем алерты
				if lastFixedState != "running" && currentState == "running" {
					// Переход в Running (служба успешно запустилась из любого другого состояния)
					if newItem.Enabled {
						// Если автозапуск включен, это штатное восстановление службы (UP)
						slog.Info("Внутренний сервис Webadmin восстановил работу (запущен)", "parent", parentName, "service", newItem.Name)
						_ = SendAlert(safeConfig, AlertUp, fullName, "")
					} else {
						// Если автозапуск выключен, это запуск администратором вручную (ENABLED)
						slog.Info("Внутренний сервис Webadmin запущен вручную", "parent", parentName, "service", newItem.Name)
						_ = SendAlert(safeConfig, AlertWebadminEnabled, fullName, "Service started (manual)")
					}
				} else if (lastFixedState == "running" || lastFixedState == "failed") && currentState == "stopped" {
					// Переход в Stopped (служба была выключена или переведена в inactive/dead)
					if newItem.Enabled {
						// Если автозапуск включен, но служба физически остановилась — это сбой (DOWN)
						errDesc := fmt.Sprintf("active_state=%s, sub_state=%s", newItem.Status.ActiveState, newItem.Status.SubState)
						slog.Warn("Внутренний сервис Webadmin остановлен при включенном автозапуске", "parent", parentName, "service", newItem.Name, "details", errDesc)
						_ = SendAlert(safeConfig, AlertDown, fullName, errDesc)
					} else {
						// Если автозапуск выключен, это штатное отключение/остановка администратором (DISABLED)
						slog.Info("Внутренний сервис Webadmin штатно остановлен/выключен", "parent", parentName, "service", newItem.Name)
						_ = SendAlert(safeConfig, AlertWebadminDisabled, fullName, "Service stopped (disabled)")
					}
				} else if (lastFixedState == "running" || lastFixedState == "stopped") && currentState == "failed" {
					// Переход в Failed (служба упала в сбой или ушла в цикл автоперезапуска из рабочего/остановленного состояния)
					if newItem.Enabled {
						// Если автозапуск включен, сбой считается критической аварией (DOWN)
						errDesc := fmt.Sprintf("active_state=%s, sub_state=%s", newItem.Status.ActiveState, newItem.Status.SubState)
						slog.Warn("Внутренний сервис Webadmin перешел в аварийное состояние (сбой)", "parent", parentName, "service", newItem.Name, "details", errDesc)
						_ = SendAlert(safeConfig, AlertDown, fullName, errDesc)
					} else {
						// Если автозапуск выключен, сбой не логируется как критический аварийный DOWN.
						// Однако, если служба до этого физически работала (oldRunning), мы отправляем предупреждение об остановке (DISABLED)
						if lastFixedState == "running" {
							slog.Info("Внутренний сервис Webadmin отключен (ушел в сбой при выключенном автозапуске)", "parent", parentName, "service", newItem.Name)
							_ = SendAlert(safeConfig, AlertWebadminDisabled, fullName, "Service stopped (disabled/failed)")
						}
					}
				}

				// 2. Дополнительно отслеживаем включение автозапуска для уже лежащей службы
				if !oldItem.Enabled && newItem.Enabled && currentState != "running" {
					errDesc := fmt.Sprintf("active_state=%s, sub_state=%s (detected on autostart enable)", newItem.Status.ActiveState, newItem.Status.SubState)
					slog.Warn("Внутренний сервис Webadmin лежит при включении автозапуска", "parent", parentName, "service", newItem.Name, "details", errDesc)
					_ = SendAlert(safeConfig, AlertDown, fullName, errDesc)
				}

				// Обновляем зафиксированное состояние и чистим историю.
				c.subStates[sName] = newItem
				delete(c.subHistories, sName)
			} else {
				// Состояние изменилось, но еще не стабилизировалось. Сохраняем историю ожидания.
				c.subHistories[sName] = history
			}
		}
	}

	// 2. Проверяем новые добавленные службы и отправляем оповещения по их текущему состоянию.
	// При первом обнаружении новой службы её статус фиксируется мгновенно во избежание задержки.
	for sName, newItem := range currentMap {
		if _, exists := c.subStates[sName]; !exists {
			fullName := fmt.Sprintf("%s / %s (%s)", parentName, newItem.Name, newItem.ServiceName)
			slog.Info("Добавлен новый внутренний сервис Webadmin", "parent", parentName, "service", newItem.Name, "service_name", sName)
			
			newRunning := newItem.Status.ActiveState == "active" && newItem.Status.SubState == "running"
			if newRunning {
				if newItem.Enabled {
					_ = SendAlert(safeConfig, AlertUp, fullName, "New service running")
				} else {
					_ = SendAlert(safeConfig, AlertWebadminEnabled, fullName, "New service running (manual)")
				}
			} else {
				if newItem.Enabled {
					_ = SendAlert(safeConfig, AlertDown, fullName, "New service not running")
				} else {
					_ = SendAlert(safeConfig, AlertWebadminDisabled, fullName, "New service stopped")
				}
			}
			c.subStates[sName] = newItem
		}
	}
}

// Вспомогательный метод для определения работоспособности подсервиса.
// Сервис считается здоровым, если active_state равен "active" и sub_state равен "running".
func isHealthy(status WebadminStatus) bool {
	return status.ActiveState == "active" && status.SubState == "running"
}

// Синхронизирует реестр клиентов Webadmin с текущим списком сервисов.
// Удаляет из реестра только те клиенты, которые были полностью удалены из файла конфигурации.
// Это сохраняет кэшированные состояния внутренних подсервисов и флаг инициализации.
func SyncWebadminClients(services []ServiceConfig) {
	registryMu.Lock()
	defer registryMu.Unlock()
	
	activeIDs := make(map[string]bool)
	for _, svc := range services {
		if svc.Type == "webadmin" {
			activeIDs[svc.ID] = true
		}
	}

	// Удаляем из кэша неиспользуемых клиентов во избежание утечки памяти.
	for id := range clientsRegistry {
		if !activeIDs[id] {
			delete(clientsRegistry, id)
			slog.Debug("Удален неиспользуемый клиент Webadmin из реестра", "id", id)
		}
	}
	slog.Debug("Синхронизация реестра клиентов Webadmin завершена", "total_active", len(clientsRegistry))
}

// Вспомогательная функция для красивого иерархического вывода JSON-тела в логах.
func prettyPrintJSON(body []byte) string {
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, body, "", "  "); err == nil {
		return prettyJSON.String()
	}
	return string(body)
}

