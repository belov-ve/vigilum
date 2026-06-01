package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// Выполняет проверку целевого ресурса в зависимости от его типа с учетом заданного количества повторов.
func RunCheckWithRetries(ctx context.Context, safeConfig *SafeConfig, svc ServiceConfig) error {
	cfg := safeConfig.Get()

	// Определение числа попыток. Если в конфиге сервиса не задано, берем глобальный дефолт.
	retries := cfg.Global.DefaultRetries
	if svc.Retries != nil {
		retries = *svc.Retries
	}

	// Определение интервала перепроверки.
	retryInterval := cfg.Global.DefaultRetryInterval
	if svc.RetryInterval != "" {
		if d, err := time.ParseDuration(svc.RetryInterval); err == nil {
			retryInterval = d
		}
	}

	var lastErr error

	// Выполняем проверку в цикле до первой успешной попытки или до исчерпания лимита попыток.
	for attempt := 1; attempt <= (retries + 1); attempt++ {
		// Проверка отмены контекста (например, при graceful shutdown или перезагрузке конфига).
		if err := ctx.Err(); err != nil {
			return err
		}

		slog.Debug("Попытка проверки сервиса", "service", svc.ID, "attempt", attempt, "type", svc.Type, "target", svc.Target)
		lastErr = performCheck(ctx, safeConfig, svc)
		if lastErr == nil {
			if attempt > 1 {
				slog.Info("Сервис восстановился в процессе повторных попыток", "service", svc.ID, "attempts", attempt)
			}
			return nil
		}

		slog.Debug("Неуспешная попытка проверки сервиса", "service", svc.ID, "attempt", attempt, "error", lastErr)

		// Если попытки не исчерпаны, делаем паузу перед следующей проверкой.
		if attempt <= retries {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(retryInterval):
			}
		}
	}

	return lastErr
}

// Выполняет единичную проверку соответствующего типа.
func performCheck(ctx context.Context, safeConfig *SafeConfig, svc ServiceConfig) error {
	// Ограничиваем таймаут единичной проверки в 5 секунд.
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	switch svc.Type {
	case "http", "https":
		return checkHTTP(checkCtx, svc.Target)
	case "tcp":
		return checkTCP(checkCtx, svc.Target)
	case "udp":
		return checkUDP(checkCtx, svc.Target)
	case "ping":
		return checkPing(checkCtx, svc.Target)
	case "webadmin":
		// Проверка webadmin обрабатывается отдельно в файле webadmin.go.
		return checkWebadmin(checkCtx, safeConfig, svc)
	default:
		// Возвращаем ошибку о неподдерживаемом типе проверки на английском языке.
		return fmt.Errorf("unsupported check type: %s", svc.Type)
	}
}

// Проверка по протоколу HTTP/HTTPS.
func checkHTTP(ctx context.Context, target string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		// Возвращаем ошибку создания HTTP-запроса на английском языке.
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Отправляем запрос, используя стандартный HTTP-клиент.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Статусы ответов 4xx и 5xx считаются ошибкой.
	if resp.StatusCode >= 400 {
		// Возвращаем ошибку с кодом статуса на английском языке.
		return fmt.Errorf("server returned error code: %d %s", resp.StatusCode, resp.Status)
	}

	return nil
}

// Проверка установлением TCP соединения.
func checkTCP(ctx context.Context, target string) error {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

// Проверка UDP доступности путем отправки пустого пакета (или DNS-запроса для порта 53) и анализа ICMP ошибок.
// Если ответ не получен в течение таймаута, для обычных портов выполняется резервная проверка (Ping-fallback) доступности хоста.
func checkUDP(ctx context.Context, target string) error {
	// Разделяем целевой адрес на хост и порт.
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		// Если не удалось разделить, используем target как хост.
		host = target
		port = ""
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", target)
	if err != nil {
		return err
	}
	defer conn.Close()

	var payload []byte
	isDNS := (port == "53")

	// Если проверяется DNS-сервис (порт 53), формируем простейший валидный DNS-запрос
	// для домена google.com (тип A, класс IN), чтобы сервер прислал нам осмысленный ответ.
	if isDNS {
		payload = []byte{
			0x12, 0x34, // Transaction ID
			0x01, 0x00, // Flags: Standard query
			0x00, 0x01, // Questions: 1
			0x00, 0x00, // Answer RRs: 0
			0x00, 0x00, // Authority RRs: 0
			0x00, 0x00, // Additional RRs: 0
			// Запрос имени: google.com
			0x06, 'g', 'o', 'o', 'g', 'l', 'e',
			0x03, 'c', 'o', 'm',
			0x00,       // Терминатор имени
			0x00, 0x01, // Тип A
			0x00, 0x01, // Класс IN
		}
	} else {
		// Для остальных UDP-сервисов отправляем пустой пакет для провокации ICMP ошибок
		payload = []byte("")
	}

	// Отправляем сформированный UDP-пакет.
	_, err = conn.Write(payload)
	if err != nil {
		return err
	}

	// Для DNS даем чуть больше времени на ответ (до 1.5 секунд), для остальных портов достаточно 100мс
	readTimeout := 100 * time.Millisecond
	if isDNS {
		readTimeout = 1500 * time.Millisecond
	}

	err = conn.SetReadDeadline(time.Now().Add(readTimeout))
	if err != nil {
		return err
	}

	// Для DNS-ответа выделяем буфер побольше (512 байт), для пустого ответа - 1 байт
	bufSize := 1
	if isDNS {
		bufSize = 512
	}
	buf := make([]byte, bufSize)
	
	_, err = conn.Read(buf)
	if err != nil {
		// Если это DNS-сервер и на запрос ответа не последовало вообще (таймаут),
		// значит DNS-служба не функционирует. Возвращаем ошибку без Ping-fallback.
		if isDNS {
			// Возвращаем ошибку таймаута DNS-запроса на английском языке.
			return fmt.Errorf("DNS server did not respond to request due to timeout: %w", err)
		}

		// Для остальных UDP-портов: таймаут чтения - стандартная ситуация, если служба просто съела пакет.
		// Выполняем резервную проверку доступности хоста по пингу.
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// Выполняем Ping-fallback для проверки, что хост не отключен.
			if pingErr := checkPing(ctx, host); pingErr != nil {
				// Возвращаем ошибку недоступности хоста по пингу на английском языке.
				return fmt.Errorf("host is unreachable (ping failed): %w", pingErr)
			}
			return nil
		}
		// Если получили явную сетевую ошибку "refused" или "reset", значит порт закрыт.
		if strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "reset") {
			// Возвращаем ошибку закрытого порта на английском языке.
			return fmt.Errorf("port is closed (ICMP unreachable): %w", err)
		}
		return err
	}

	return nil
}

// Проверка доступности хоста системным вызовом утилиты ping.
func checkPing(ctx context.Context, target string) error {
	// -c 1 — отправить 1 пакет
	// -W 2 — ждать ответа не более 2 секунд
	cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "2", target)
	
	// Выполняем команду и анализируем код возврата.
	if err := cmd.Run(); err != nil {
		// Возвращаем ошибку недоступности по пингу на английском языке.
		return fmt.Errorf("host is unreachable by ICMP ping: %w", err)
	}
	return nil
}
