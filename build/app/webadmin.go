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

// Внутреннее состояние конкретного клиента Webadmin.
type WebadminClient struct {
	mu           sync.Mutex
	id           string
	targetURL    string
	username     string
	password     string
	httpClient   *http.Client
	subStates    map[string]WebadminConfigItem
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
			id:         svc.ID,
			targetURL:  svc.Target,
			username:   svc.Username,
			password:   svc.Password,
			httpClient: httpClient,
			subStates:  make(map[string]WebadminConfigItem),
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
	client.processSubServices(safeConfig, svc.Name, items)

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
		// Возвращаем ошибку с кодом ответа на английском языке.
		return fmt.Errorf("server response code: %d %s", resp.StatusCode, resp.Status)
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
		// Возвращаем ошибку с кодом ответа при запросе конфигураций на английском языке.
		return nil, fmt.Errorf("response code when fetching configurations: %d %s (body:\n%s)", resp.StatusCode, resp.Status, prettyPrintJSON(body))
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

// Сравнивает текущие состояния внутренних подсервисов с предыдущими и отправляет уведомления.
func (c *WebadminClient) processSubServices(safeConfig *SafeConfig, parentName string, items []WebadminConfigItem) {
	// Логируем количество полученных подсервисов с уровнем DEBUG для предотвращения спама в INFO.
	slog.Debug("Retrieved subservices list from Webadmin API", "parent", parentName, "count", len(items))

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
			continue
		}

		slog.Debug("Сравнение подсервиса Webadmin", 
			"name", newItem.Name, 
			"service_name", sName, 
			"old_enabled", oldItem.Enabled, 
			"new_enabled", newItem.Enabled, 
			"old_active", oldItem.Status.ActiveState, 
			"new_active", newItem.Status.ActiveState)

		// 1. Обрабатываем изменение флага Enabled (включение/отключение автозапуска в Webadmin).
		if oldItem.Enabled && !newItem.Enabled {
			// Автозапуск сервиса был отключен администратором.
			slog.Info("Автозапуск внутреннего сервиса Webadmin отключен (enabled=false)", "parent", parentName, "service", newItem.Name)
			// Оповещение об отключении автозапуска.
			_ = SendAlert(safeConfig, AlertWebadminDisabled, fullName, "Autostart disabled in Webadmin")
		} else if !oldItem.Enabled && newItem.Enabled {
			// Автозапуск сервиса был включен администратором.
			slog.Info("Автозапуск внутреннего сервиса Webadmin включен (enabled=true)", "parent", parentName, "service", newItem.Name)
			_ = SendAlert(safeConfig, AlertWebadminEnabled, fullName, "")
		}

		// 2. Всегда проверяем изменения его работоспособности (здоровья), независимо от флага Enabled (автозапуска).
		oldHealthy := isHealthy(oldItem.Status)
		newHealthy := isHealthy(newItem.Status)

		if oldHealthy && !newHealthy {
			// Сервис перешел в состояние аварии.
			errDesc := fmt.Sprintf("active_state=%s, sub_state=%s", newItem.Status.ActiveState, newItem.Status.SubState)
			slog.Warn("Внутренний сервис Webadmin перешел в аварийное состояние", "parent", parentName, "service", newItem.Name, "details", errDesc)
			_ = SendAlert(safeConfig, AlertDown, fullName, errDesc)
		} else if !oldHealthy && newHealthy {
			// Сервис восстановился (или запустился).
			slog.Info("Внутренний сервис Webadmin восстановил работу", "parent", parentName, "service", newItem.Name)
			_ = SendAlert(safeConfig, AlertUp, fullName, "")
		} else if oldItem.Status.ActiveState != newItem.Status.ActiveState || oldItem.Status.SubState != newItem.Status.SubState {
			// Изменение внутренних статусов systemd без смены критического состояния здоровья.
			slog.Debug("Изменение статуса подсервиса Webadmin", "service", newItem.Name, "old_active", oldItem.Status.ActiveState, "new_active", newItem.Status.ActiveState, "old_sub", oldItem.Status.SubState, "new_sub", newItem.Status.SubState)
		}

		// Обновляем сохраненный статус в кэше.
		c.subStates[sName] = newItem
	}

	// 2. Проверяем новые добавленные сервисы.
	for sName, newItem := range currentMap {
		if _, exists := c.subStates[sName]; !exists {
			fullName := fmt.Sprintf("%s / %s (%s)", parentName, newItem.Name, newItem.ServiceName)
			slog.Info("Добавлен новый внутренний сервис Webadmin", "parent", parentName, "service", newItem.Name, "service_name", sName)
			
			// Отправляем оповещение о начале мониторинга нового сервиса.
			// Если автозапуск выключен, посылаем AlertWebadminDisabled, если включен - AlertWebadminEnabled.
			if newItem.Enabled {
				_ = SendAlert(safeConfig, AlertWebadminEnabled, fullName, "")
			} else {
				_ = SendAlert(safeConfig, AlertWebadminDisabled, fullName, "Added in disabled state")
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

