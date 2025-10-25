package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

type Config struct {
	BaseFailureRate        float64       `json:"base_failure_rate"`
	MaxRetries             int           `json:"max_retries"`
	GatewayTimeout         time.Duration `json:"gateway_timeout"`
	FraudThreshold         float64       `json:"fraud_threshold"`
	CircuitBreakerFailures int           `json:"circuit_breaker_failures"`
	CircuitBreakerReset    time.Duration `json:"circuit_breaker_reset"`
}

func LoadConfig() *Config {
	return &Config{
		BaseFailureRate:      0.05,
		MaxRetries:          2,
		GatewayTimeout:      30 * time.Second,
		FraudThreshold:      0.7,
		CircuitBreakerFailures: 5,
		CircuitBreakerReset:    60 * time.Second,
	}
}

type PaymentError struct {
	Code      string    `json:"code"`
	Message   string    `json:"message"`
	PaymentID string    `json:"payment_id"`
	Retryable bool      `json:"retryable"`
	Timestamp time.Time `json:"timestamp"`
}

func (e *PaymentError) Error() string {
	return fmt.Sprintf("[%s] %s (payment: %s)", e.Code, e.Message, e.PaymentID)
}

var (
	ErrFraudDetected   = &PaymentError{Code: "FRAUD", Message: "Transaction flagged as fraudulent", Retryable: false}
	ErrGatewayTimeout  = &PaymentError{Code: "GATEWAY_TIMEOUT", Message: "Payment gateway timeout", Retryable: true}
	ErrInvalidAmount   = &PaymentError{Code: "INVALID_AMOUNT", Message: "Amount must be positive", Retryable: false}
	ErrInvalidCurrency = &PaymentError{Code: "INVALID_CURRENCY", Message: "Invalid currency", Retryable: false}
	ErrCircuitOpen     = &PaymentError{Code: "CIRCUIT_OPEN", Message: "Circuit breaker is open", Retryable: true}
)

type Payment struct {
	ID             string    `json:"id"`
	Amount         float64   `json:"amount"`
	Currency       string    `json:"currency"`
	MerchantID     string    `json:"merchant_id"`
	CustomerID     string    `json:"customer_id"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
	ProcessedAt    time.Time `json:"processed_at"`
	ErrorReason    string    `json:"error_reason,omitempty"`
	RetryCount     int       `json:"retry_count"`
	IdempotencyKey string    `json:"idempotency_key,omitempty"`
	GatewayUsed    string    `json:"gateway_used,omitempty"`
}

func (p *Payment) Validate() error {
	if p.Amount <= 0 {
		return ErrInvalidAmount
	}
	
	validCurrencies := map[string]bool{"USD": true, "EUR": true, "GBP": true, "CAD": true}
	if !validCurrencies[p.Currency] {
		return ErrInvalidCurrency
	}
	
	if p.MerchantID == "" {
		return &PaymentError{Code: "INVALID_MERCHANT", Message: "Merchant ID is required", Retryable: false}
	}
	
	if p.CustomerID == "" {
		return &PaymentError{Code: "INVALID_CUSTOMER", Message: "Customer ID is required", Retryable: false}
	}
	
	return nil
}

type PaymentGateway struct {
	Name        string        `json:"name"`
	SuccessRate float64       `json:"success_rate"`
	Latency     time.Duration `json:"latency"`
	IsActive    bool          `json:"is_active"`
}

type FraudDetectionResult struct {
	IsFraudulent bool     `json:"is_fraudulent"`
	RiskScore    float64  `json:"risk_score"`
	Reasons      []string `json:"reasons"`
}

type CircuitBreaker struct {
	failures     int
	maxFailures  int
	resetTimeout time.Duration
	lastFailure  time.Time
	mu           sync.RWMutex
}

func NewCircuitBreaker(maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		maxFailures:  maxFailures,
		resetTimeout: resetTimeout,
	}
}

func (cb *CircuitBreaker) Allow() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	
	if cb.failures >= cb.maxFailures {
		if time.Since(cb.lastFailure) > cb.resetTimeout {
			cb.mu.RUnlock()
			cb.mu.Lock()
			cb.failures = 0
			cb.mu.Unlock()
			cb.mu.RLock()
			return true
		}
		return false
	}
	return true
}

func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
}

func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	cb.lastFailure = time.Now()
}

func (cb *CircuitBreaker) State() string {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	
	if cb.failures >= cb.maxFailures {
		if time.Since(cb.lastFailure) > cb.resetTimeout {
			return "half-open"
		}
		return "open"
	}
	return "closed"
}

type PaymentProcessor struct {
	config             *Config
	gateways           []PaymentGateway
	fraudService       *FraudDetectionService
	chaosInjector      *ChaosInjector
	circuitBreakers    map[string]*CircuitBreaker
	transactionHistory map[string]*Payment
	idempotencyStore   map[string]*Payment
	mu                 sync.RWMutex
	metrics            *PaymentMetrics
	gatewayStats       map[string]*GatewayStats
}

type GatewayStats struct {
	Attempts   int `json:"attempts"`
	Successes  int `json:"successes"`
	Failures   int `json:"failures"`
	Timeouts   int `json:"timeouts"`
}

type PaymentMetrics struct {
	TotalProcessed        int64         `json:"total_processed"`
	Successful            int64         `json:"successful"`
	Failed                int64         `json:"failed"`
	FraudDetected         int64         `json:"fraud_detected"`
	TotalAmount           float64       `json:"total_amount"`
	AverageProcessingTime time.Duration `json:"average_processing_time"`
	SuccessRate           float64       `json:"success_rate"`
	CircuitBreakerTrips   int64         `json:"circuit_breaker_trips"`
}

func NewPaymentProcessor(config *Config) *PaymentProcessor {
	if config == nil {
		config = LoadConfig()
	}

	gateways := []PaymentGateway{
		{Name: "Stripe", SuccessRate: 0.98, Latency: 200 * time.Millisecond, IsActive: true},
		{Name: "PayPal", SuccessRate: 0.96, Latency: 300 * time.Millisecond, IsActive: true},
		{Name: "Square", SuccessRate: 0.97, Latency: 250 * time.Millisecond, IsActive: true},
		{Name: "Adyen", SuccessRate: 0.99, Latency: 150 * time.Millisecond, IsActive: true},
	}

	processor := &PaymentProcessor{
		config:             config,
		gateways:           gateways,
		fraudService:       NewFraudDetectionService(config),
		chaosInjector:      NewChaosInjector(config),
		circuitBreakers:    make(map[string]*CircuitBreaker),
		transactionHistory: make(map[string]*Payment),
		idempotencyStore:   make(map[string]*Payment),
		metrics:            &PaymentMetrics{},
		gatewayStats:       make(map[string]*GatewayStats),
	}

	for _, gateway := range gateways {
		processor.circuitBreakers[gateway.Name] = NewCircuitBreaker(
			config.CircuitBreakerFailures,
			config.CircuitBreakerReset,
		)
		processor.gatewayStats[gateway.Name] = &GatewayStats{}
	}

	return processor
}

func (p *PaymentProcessor) ProcessPayment(amount float64, currency, merchantID, customerID string) (*Payment, error) {
	return p.ProcessPaymentWithContext(context.Background(), amount, currency, merchantID, customerID, "")
}

func (p *PaymentProcessor) ProcessPaymentWithContext(
	ctx context.Context,
	amount float64, 
	currency, merchantID, customerID string,
	idempotencyKey string,
) (*Payment, error) {
	
	if idempotencyKey != "" {
		if existing, found := p.getIdempotentPayment(idempotencyKey); found {
			return existing, nil
		}
	}

	startTime := time.Now()

	payment := &Payment{
		ID:             generatePaymentID(),
		Amount:         amount,
		Currency:       currency,
		MerchantID:     merchantID,
		CustomerID:     customerID,
		Status:         "pending",
		CreatedAt:      time.Now(),
		IdempotencyKey: idempotencyKey,
	}

	if err := payment.Validate(); err != nil {
		return p.handlePaymentFailure(payment, err, startTime)
	}

	p.mu.Lock()
	p.transactionHistory[payment.ID] = payment
	if idempotencyKey != "" {
		p.idempotencyStore[idempotencyKey] = payment
	}
	p.mu.Unlock()

	fmt.Printf("Processing payment %s: $%.2f from %s to %s\n",
		payment.ID, amount, customerID, merchantID)

	fraudResult, err := p.fraudService.CheckPayment(payment)
	if err != nil {
		return p.handlePaymentFailure(payment, err, startTime)
	}

	if fraudResult.IsFraudulent {
		p.mu.Lock()
		p.metrics.FraudDetected++
		p.mu.Unlock()
		fraudErr := &PaymentError{
			Code:      "FRAUD_DETECTED",
			Message:   fmt.Sprintf("Fraud detected: %v", fraudResult.Reasons),
			PaymentID: payment.ID,
			Retryable: false,
			Timestamp: time.Now(),
		}
		return p.handlePaymentFailure(payment, fraudErr, startTime)
	}

	if err := p.chaosInjector.InjectPaymentChaos(payment); err != nil {
		fmt.Printf("Chaos injection affected payment %s: %v\n", payment.ID, err)
	}

	gateway := p.selectPaymentGateway()
	
	circuitBreaker := p.circuitBreakers[gateway.Name]
	if !circuitBreaker.Allow() {
		circuitErr := &PaymentError{
			Code:      "CIRCUIT_BREAKER_OPEN",
			Message:   fmt.Sprintf("Gateway %s circuit breaker is open", gateway.Name),
			PaymentID: payment.ID,
			Retryable: true,
			Timestamp: time.Now(),
		}
		return p.handlePaymentFailure(payment, circuitErr, startTime)
	}

	p.mu.Lock()
	payment.Status = "processing"
	p.mu.Unlock()

	success, processErr := p.processWithGateway(ctx, payment, gateway)
	if processErr != nil {
		p.recordGatewayStat(gateway.Name, false, processErr)
		circuitBreaker.RecordFailure()
		p.mu.Lock()
		p.metrics.CircuitBreakerTrips++
		p.mu.Unlock()
		return p.handlePaymentFailure(payment, processErr, startTime)
	}

	if !success {
		if payment.RetryCount < p.config.MaxRetries {
			p.mu.Lock()
			payment.RetryCount++
			fmt.Printf("Retrying payment %s (attempt %d)\n", payment.ID, payment.RetryCount)
			p.mu.Unlock()
			
			success, _ = p.processWithGateway(ctx, payment, gateway)
		}
	}

	if success {
		p.recordGatewayStat(gateway.Name, true, nil)
		circuitBreaker.RecordSuccess()
		payment.GatewayUsed = gateway.Name
		return p.handlePaymentSuccess(payment, gateway.Name, startTime)
	} else {
		p.recordGatewayStat(gateway.Name, false, nil)
		circuitBreaker.RecordFailure()
		p.mu.Lock()
		p.metrics.CircuitBreakerTrips++
		p.mu.Unlock()
		return p.handlePaymentFailure(payment, 
			&PaymentError{
				Code: "GATEWAY_FAILURE", 
				Message: "All payment attempts failed",
				PaymentID: payment.ID,
				Retryable: true,
				Timestamp: time.Now(),
			}, startTime)
	}
}

func (p *PaymentProcessor) processWithGateway(ctx context.Context, payment *Payment, gateway PaymentGateway) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}

	processingTime := gateway.Latency + time.Duration(secureRandIntn(100))*time.Millisecond
	
	gatewayCtx, cancel := context.WithTimeout(ctx, p.config.GatewayTimeout)
	defer cancel()

	resultChan := make(chan struct {
		success bool
		err     error
	}, 1)

	go func() {
		time.Sleep(processingTime)
		
		successThreshold := gateway.SuccessRate * p.chaosInjector.GetSuccessRateModifier()
		success := secureRandFloat64() <= successThreshold
		
		select {
		case resultChan <- struct {
			success bool
			err     error
		}{success: success, err: nil}:
		case <-gatewayCtx.Done():
		}
	}()

	select {
	case <-gatewayCtx.Done():
		return false, gatewayCtx.Err()
	case result := <-resultChan:
		return result.success, result.err
	}
}

func (p *PaymentProcessor) recordGatewayStat(gateway string, success bool, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	stats := p.gatewayStats[gateway]
	if stats == nil {
		stats = &GatewayStats{}
		p.gatewayStats[gateway] = stats
	}
	
	stats.Attempts++
	if success {
		stats.Successes++
	} else {
		stats.Failures++
		if err == context.DeadlineExceeded {
			stats.Timeouts++
		}
	}
}

func (p *PaymentProcessor) selectPaymentGateway() PaymentGateway {
	p.mu.RLock()
	defer p.mu.RUnlock()

	activeGateways := make([]PaymentGateway, 0)
	for _, gw := range p.gateways {
		if gw.IsActive && p.circuitBreakers[gw.Name].State() != "open" {
			activeGateways = append(activeGateways, gw)
		}
	}

	if len(activeGateways) == 0 {
		return p.gateways[0]
	}

	return activeGateways[secureRandIntn(len(activeGateways))]
}

func (p *PaymentProcessor) handlePaymentSuccess(payment *Payment, gateway string, startTime time.Time) (*Payment, error) {
	processingTime := time.Since(startTime)

	p.mu.Lock()
	defer p.mu.Unlock()
	
	payment.Status = "completed"
	payment.ProcessedAt = time.Now()

	p.metrics.Successful++
	p.metrics.TotalProcessed++
	p.metrics.TotalAmount += payment.Amount

	if p.metrics.Successful == 1 {
		p.metrics.AverageProcessingTime = processingTime
	} else {
		p.metrics.AverageProcessingTime = time.Duration(
			(float64(p.metrics.AverageProcessingTime)*float64(p.metrics.Successful-1)+float64(processingTime))/float64(p.metrics.Successful),
		)
	}
	
	if p.metrics.TotalProcessed > 0 {
		p.metrics.SuccessRate = float64(p.metrics.Successful) / float64(p.metrics.TotalProcessed)
	}

	fmt.Printf("Payment %s completed successfully via %s (took %v)\n",
		payment.ID, gateway, processingTime)

	return payment, nil
}

func (p *PaymentProcessor) handlePaymentFailure(payment *Payment, err error, startTime time.Time) (*Payment, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	payment.Status = "failed"
	payment.ErrorReason = err.Error()
	payment.ProcessedAt = time.Now()

	p.metrics.Failed++
	p.metrics.TotalProcessed++
	if p.metrics.TotalProcessed > 0 {
		p.metrics.SuccessRate = float64(p.metrics.Successful) / float64(p.metrics.TotalProcessed)
	}

	fmt.Printf("Payment %s failed: %v\n", payment.ID, err)

	return payment, err
}

func (p *PaymentProcessor) getIdempotentPayment(key string) (*Payment, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	if payment, exists := p.idempotencyStore[key]; exists {
		return payment, true
	}
	return nil, false
}

func (p *PaymentProcessor) CleanupOldData(maxAge time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	cutoff := time.Now().Add(-maxAge)
	
	for key, payment := range p.idempotencyStore {
		if payment.CreatedAt.Before(cutoff) {
			delete(p.idempotencyStore, key)
		}
	}
}

type FraudDetectionService struct {
	config       *Config
	riskPatterns []string
	mu           sync.RWMutex
}

func NewFraudDetectionService(config *Config) *FraudDetectionService {
	return &FraudDetectionService{
		config: config,
		riskPatterns: []string{
			"high_amount_velocity",
			"unusual_geolocation",
			"suspicious_device",
			"risky_merchant_category",
			"card_testing_pattern",
		},
	}
}

func (f *FraudDetectionService) CheckPayment(payment *Payment) (*FraudDetectionResult, error) {
	time.Sleep(50 * time.Millisecond)

	result := &FraudDetectionResult{
		RiskScore: secureRandFloat64(),
	}

	if payment.Amount > 1000 {
		result.RiskScore += 0.3
		result.Reasons = append(result.Reasons, "high_amount")
	}

	if secureRandFloat64() < 0.1 {
		f.mu.RLock()
		pattern := f.riskPatterns[secureRandIntn(len(f.riskPatterns))]
		f.mu.RUnlock()
		result.Reasons = append(result.Reasons, pattern)
		result.RiskScore += 0.4
	}

	result.IsFraudulent = result.RiskScore > f.config.FraudThreshold

	return result, nil
}

type ChaosInjector struct {
	config         *Config
	mu             sync.RWMutex
	failureRate    float64
	latencyRange   time.Duration
	gatewayOutages map[string]time.Time
}

func NewChaosInjector(config *Config) *ChaosInjector {
	return &ChaosInjector{
		config:         config,
		failureRate:    config.BaseFailureRate,
		latencyRange:   2 * time.Second,
		gatewayOutages: make(map[string]time.Time),
	}
}

func (c *ChaosInjector) InjectPaymentChaos(payment *Payment) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	now := time.Now()
	
	for gateway, outageEnd := range c.gatewayOutages {
		if now.After(outageEnd) {
			delete(c.gatewayOutages, gateway)
		}
	}

	if secureRandFloat64() < 0.02 {
		gateway := "unknown"
		if secureRandFloat64() < 0.5 {
			gateway = "Stripe"
		} else {
			gateway = "PayPal"
		}
		c.gatewayOutages[gateway] = now.Add(30 * time.Second)
		fmt.Printf("Simulating gateway outage: %s\n", gateway)
	}

	if secureRandFloat64() < 0.03 {
		latency := time.Duration(secureRandIntn(int(c.latencyRange)))
		time.Sleep(latency)
		fmt.Printf("Injected latency: %v\n", latency)
	}

	if secureRandFloat64() < 0.01 {
		return ErrGatewayTimeout
	}

	return nil
}

func (c *ChaosInjector) GetSuccessRateModifier() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	modifier := 1.0
	outages := len(c.gatewayOutages)
	if outages > 0 {
		modifier -= 0.1 * float64(outages)
	}
	if modifier < 0 {
		modifier = 0
	}
	return modifier
}

func (p *PaymentProcessor) GenerateBusinessReport() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	revenueByMerchant := make(map[string]float64)
	gatewayStats := make(map[string]interface{})
	
	for _, payment := range p.transactionHistory {
		if payment.Status == "completed" {
			revenueByMerchant[payment.MerchantID] += payment.Amount
		}
	}

	for gateway, stats := range p.gatewayStats {
		if stats != nil && stats.Attempts > 0 {
			gatewayStats[gateway] = map[string]interface{}{
				"attempts":  stats.Attempts,
				"successes": stats.Successes,
				"failures":  stats.Failures,
				"timeouts":  stats.Timeouts,
				"success_rate": float64(stats.Successes) / float64(stats.Attempts) * 100,
			}
		}
	}

	circuitStates := make(map[string]string)
	for gateway, cb := range p.circuitBreakers {
		circuitStates[gateway] = cb.State()
	}

	return map[string]interface{}{
		"metrics":               p.metrics,
		"revenue_by_merchant":   revenueByMerchant,
		"gateway_stats":         gatewayStats,
		"circuit_breaker_states": circuitStates,
		"total_transactions":    len(p.transactionHistory),
		"timestamp":             time.Now().Format(time.RFC3339),
	}
}

func (p *PaymentProcessor) SaveReportToFile(filename string) error {
	report := p.GenerateBusinessReport()

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func generatePaymentID() string {
	return fmt.Sprintf("pay_%d_%d", time.Now().UnixNano(), secureRandIntn(10000))
}

func secureRandIntn(n int) int {
	if n <= 0 {
		return 0
	}
	num, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err == nil {
		return int(num.Int64())
	}
	return int(time.Now().UnixNano() % int64(n))
}

func secureRandFloat64() float64 {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return float64(time.Now().UnixNano()&(1<<53-1)) / float64(1<<53)
	}
	u := binary.LittleEndian.Uint64(buf[:]) & ((uint64(1) << 53) - 1)
	return float64(u) / float64(uint64(1)<<53)
}

func main() {
	fmt.Println("Enhanced Payment Processing System with Chaos Engineering")
	fmt.Println("=======================================================")

	config := LoadConfig()
	processor := NewPaymentProcessor(config)

	merchants := []string{"amazon", "netflix", "spotify", "uber", "starbucks"}
	customers := []string{"cust_001", "cust_002", "cust_003", "cust_004", "cust_005"}

	fmt.Println("\nProcessing payments...")

	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func(transactionNum int) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			amount := float64(10 + secureRandIntn(500))
			merchant := merchants[secureRandIntn(len(merchants))]
			customer := customers[secureRandIntn(len(customers))]
			idempotencyKey := fmt.Sprintf("txn_%d_%d", transactionNum, time.Now().Unix())

			payment, err := processor.ProcessPaymentWithContext(ctx, amount, "USD", merchant, customer, idempotencyKey)
			if err != nil {
				fmt.Printf("Transaction %d failed: %v\n", transactionNum, err)
			} else {
				fmt.Printf("Transaction %d successful: %s $%.2f\n",
					transactionNum, payment.ID, payment.Amount)
			}

			time.Sleep(100 * time.Millisecond)
		}(i)
	}

	wg.Wait()

	processor.CleanupOldData(1 * time.Hour)

	fmt.Println("\nEnhanced Business Report:")
	fmt.Println("========================")

	report := processor.GenerateBusinessReport()
	metrics := report["metrics"].(*PaymentMetrics)
	circuitStates := report["circuit_breaker_states"].(map[string]string)
	gatewayStats := report["gateway_stats"].(map[string]interface{})

	fmt.Printf("Total Processed: %d\n", metrics.TotalProcessed)
	fmt.Printf("Successful: %d\n", metrics.Successful)
	fmt.Printf("Failed: %d\n", metrics.Failed)
	fmt.Printf("Fraud Detected: %d\n", metrics.FraudDetected)
	fmt.Printf("Circuit Breaker Trips: %d\n", metrics.CircuitBreakerTrips)
	fmt.Printf("Success Rate: %.2f%%\n", metrics.SuccessRate*100)
	fmt.Printf("Total Amount Processed: $%.2f\n", metrics.TotalAmount)
	fmt.Printf("Average Processing Time: %v\n", metrics.AverageProcessingTime)

	fmt.Println("\nGateway Statistics:")
	for gateway, stats := range gatewayStats {
		statMap := stats.(map[string]interface{})
		fmt.Printf("  %s: %.1f%% success (%d/%d attempts)\n", 
			gateway, statMap["success_rate"], statMap["successes"], statMap["attempts"])
	}

	fmt.Println("\nCircuit Breaker States:")
	for gateway, state := range circuitStates {
		fmt.Printf("  %s: %s\n", gateway, state)
	}

	if err := processor.SaveReportToFile("enhanced_payment_report.json"); err != nil {
		fmt.Printf("Error saving report: %v\n", err)
	} else {
		fmt.Println("\nDetailed report saved to enhanced_payment_report.json")
	}

	fmt.Println("\nEnhanced Chaos Resilience Analysis:")
	fmt.Println("==================================")
	fmt.Printf("System handled %.1f%% success rate under chaos conditions\n", metrics.SuccessRate*100)
	fmt.Printf("Detected and prevented %d fraudulent transactions\n", metrics.FraudDetected)
	fmt.Printf("Circuit breakers prevented %d potential cascade failures\n", metrics.CircuitBreakerTrips)
	fmt.Printf("Processed $%.2f in total transaction volume\n", metrics.TotalAmount)
	fmt.Printf("Average processing time: %v\n", metrics.AverageProcessingTime)
	
	fmt.Println("\nSystem Configuration:")
	fmt.Printf("Max Retries: %d\n", config.MaxRetries)
	fmt.Printf("Fraud Threshold: %.2f\n", config.FraudThreshold)
	fmt.Printf("Circuit Breaker: %d failures / %v reset\n", 
		config.CircuitBreakerFailures, config.CircuitBreakerReset)
}
