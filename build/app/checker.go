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

// Проверка UDP доступности путем отправки валидного запроса для известных протоколов
// (DNS, NTP, STUN, SNMP, SIP) или пустого пакета для кастомных портов и анализа ответа/ICMP ошибок.
func checkUDP(ctx context.Context, target string) error {
	// Разделяем целевой адрес на хост и порт.
	_, port, err := net.SplitHostPort(target)
	if err != nil {
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
	isNTP := (port == "123")
	isSTUN := (port == "3478")
	isSNMP := (port == "161")
	isSIP := (port == "5060")

	// Формируем полезную нагрузку в зависимости от порта.
	if isDNS {
		// Стандартный DNS-запрос для домена google.com (тип A)
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
	} else if isNTP {
		// NTP клиентский запрос (48 байт)
		payload = make([]byte, 48)
		payload[0] = 0x1B // LI = 0, VN = 3, Mode = 3 (client request)
	} else if isSTUN {
		// STUN Binding Request (20 байт)
		payload = []byte{
			0x00, 0x01, // Message Type: Binding Request
			0x00, 0x00, // Message Length: 0
			0x21, 0x12, 0xA4, 0x42, // Magic Cookie
			// Transaction ID (12 байт)
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
		}
	} else if isSNMP {
		// SNMP v1 GetRequest для OID 1.3.6.1.2.1.1.1.0 (sysDescr) с community "public"
		payload = []byte{
			0x30, 0x29,             // Sequence, length 41
			0x02, 0x01, 0x00,       // Version: v1 (0)
			0x04, 0x06,             // Community, length 6
			0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // "public"
			0xa0, 0x1c,             // GetRequest PDU, length 28
			0x02, 0x04, 0x00, 0x00, 0x00, 0x01, // Request ID
			0x02, 0x01, 0x00,       // Error Status: noError
			0x02, 0x01, 0x00,       // Error Index
			0x30, 0x0e,             // Varbind List
			0x30, 0x0c,             // Varbind
			0x06, 0x08,             // Object Identifier
			0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID: 1.3.6.1.2.1.1.1.0
			0x05, 0x00,             // Null value
		}
	} else if isSIP {
		// SIP OPTIONS запрос
		req := fmt.Sprintf(
			"OPTIONS sip:%s SIP/2.0\r\n"+
				"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-%d\r\n"+
				"Max-Forwards: 70\r\n"+
				"To: <sip:%s>\r\n"+
				"From: <sip:vigilum@127.0.0.1>;tag=vigilum\r\n"+
				"Call-ID: %d@127.0.0.1\r\n"+
				"CSeq: 1 OPTIONS\r\n"+
				"Contact: <sip:vigilum@127.0.0.1>\r\n"+
				"Accept: application/sdp\r\n"+
				"Content-Length: 0\r\n\r\n",
			target, time.Now().UnixNano(), target, time.Now().UnixNano(),
		)
		payload = []byte(req)
	} else {
		// Для остальных кастомных UDP-сервисов отправляем пустой пакет для провокации ICMP ошибок
		payload = []byte("")
	}

	// Отправляем сформированный UDP-пакет.
	_, err = conn.Write(payload)
	if err != nil {
		return err
	}

	// Устанавливаем таймаут чтения 1.5 секунды для ожидания ответа или прихода ICMP ошибки
	readTimeout := 1500 * time.Millisecond
	err = conn.SetReadDeadline(time.Now().Add(readTimeout))
	if err != nil {
		return err
	}

	// Выделяем буфер для чтения ответа
	bufSize := 1
	if isDNS || isNTP || isSTUN || isSNMP || isSIP {
		bufSize = 512
	}
	buf := make([]byte, bufSize)
	
	_, err = conn.Read(buf)
	if err != nil {
		// Если получили таймаут ожидания ответа
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			if isDNS {
				return fmt.Errorf("DNS server did not respond to request due to timeout: %w", err)
			}
			if isNTP {
				return fmt.Errorf("NTP server did not respond to request due to timeout: %w", err)
			}
			if isSTUN {
				return fmt.Errorf("STUN server did not respond to request due to timeout: %w", err)
			}
			if isSNMP {
				return fmt.Errorf("SNMP agent did not respond to request due to timeout: %w", err)
			}
			if isSIP {
				return fmt.Errorf("SIP server did not respond to request due to timeout: %w", err)
			}
			// Для кастомных портов Ping-fallback исключен, трактуем таймаут как недоступность
			return fmt.Errorf("UDP service did not respond to request (timeout): %w", err)
		}
		
		// Если получили явную ICMP-ошибку "connection refused" или "reset", значит порт закрыт.
		if strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "reset") {
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
