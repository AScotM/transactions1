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

// Configuration management
type Config struct {
	BaseFailureRate    float64       `json:"base_failure_rate"`
	MaxRetries         int           `json:"max_retries"`
	GatewayTimeout     time.Duration `json:"gateway_timeout"`
	FraudThreshold     float64       `json:"fraud_threshold"`
	CircuitBreakerFailures int       `json:"circuit_breaker_failures"`
	CircuitBreakerReset    time.Duration `json:"circuit_breaker_reset"`
}

func LoadConfig() *Config {
	// In real implementation, load from file/env with validation
	return &Config{
		BaseFailureRate:      0.05,
		MaxRetries:          2,
		GatewayTimeout:      30 * time.Second,
		FraudThreshold:      0.7,
		CircuitBreakerFailures: 5,
		CircuitBreakerReset:    60 * time.Second,
	}
}

// Enhanced error handling
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

// Pre-defined error types
var (
	ErrFraudDetected   = &PaymentError{Code: "FRAUD", Message: "Transaction flagged as fraudulent", Retryable: false}
	ErrGatewayTimeout  = &PaymentError{Code: "GATEWAY_TIMEOUT", Message: "Payment gateway timeout", Retryable: true}
	ErrInvalidAmount   = &PaymentError{Code: "INVALID_AMOUNT", Message: "Amount must be positive", Retryable: false}
	ErrInvalidCurrency = &PaymentError{Code: "INVALID_CURRENCY", Message: "Invalid currency", Retryable: false}
	ErrCircuitOpen     = &PaymentError{Code: "CIRCUIT_OPEN", Message: "Circuit breaker is open", Retryable: true}
)

// Business domain models
type Payment struct {
	ID           string    `json:"id"`
	Amount       float64   `json:"amount"`
	Currency     string    `json:"currency"`
	MerchantID   string    `json:"merchant_id"`
	CustomerID   string    `json:"customer_id"`
	Status       string    `json:"status"` // pending, processing, completed, failed
	CreatedAt    time.Time `json:"created_at"`
	ProcessedAt  time.Time `json:"processed_at"`
	ErrorReason  string    `json:"error_reason,omitempty"`
	RetryCount   int       `json:"retry_count"`
	IdempotencyKey string  `json:"idempotency_key,omitempty"`
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

// Circuit Breaker pattern
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
			// Auto-reset after timeout
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

// Core business service
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
}

type PaymentMetrics struct {
	TotalProcessed        int           `json:"total_processed"`
	Successful            int           `json:"successful"`
	Failed                int           `json:"failed"`
	FraudDetected         int           `json:"fraud_detected"`
	TotalAmount           float64       `json:"total_amount"`
	AverageProcessingTime time.Duration `json:"average_processing_time"`
	SuccessRate           float64       `json:"success_rate"`
	CircuitBreakerTrips   int           `json:"circuit_breaker_trips"`
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
	}

	// Initialize circuit breakers for each gateway
	for _, gateway := range gateways {
		processor.circuitBreakers[gateway.Name] = NewCircuitBreaker(
			config.CircuitBreakerFailures,
			config.CircuitBreakerReset,
		)
	}

	return processor
}

// ProcessPayment handles the complete payment flow with chaos injection
func (p *PaymentProcessor) ProcessPayment(amount float64, currency, merchantID, customerID string) (*Payment, error) {
	return p.ProcessPaymentWithContext(context.Background(), amount, currency, merchantID, customerID, "")
}

// ProcessPaymentWithContext handles payment with context support for timeouts
func (p *PaymentProcessor) ProcessPaymentWithContext(
	ctx context.Context,
	amount float64, 
	currency, merchantID, customerID string,
	idempotencyKey string,
) (*Payment, error) {
	
	// Check idempotency first
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

	// Validate payment
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

	// Step 1: Fraud detection
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

	// Step 2: Inject chaos (simulate real-world failures)
	if err := p.chaosInjector.InjectPaymentChaos(payment); err != nil {
		fmt.Printf("Chaos injection affected payment %s: %v\n", payment.ID, err)
	}

	// Step 3: Process with selected gateway
	gateway := p.selectPaymentGateway()
	
	// Check circuit breaker for selected gateway
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

	// Process with gateway (with context support)
	success, processErr := p.processWithGateway(ctx, payment, gateway)
	if processErr != nil {
		circuitBreaker.RecordFailure()
		p.mu.Lock()
		p.metrics.CircuitBreakerTrips++
		p.mu.Unlock()
		return p.handlePaymentFailure(payment, processErr, startTime)
	}

	if !success {
		// Retry logic with circuit breaker awareness
		if payment.RetryCount < p.config.MaxRetries {
			p.mu.Lock()
			payment.RetryCount++
			fmt.Printf("Retrying payment %s (attempt %d)\n", payment.ID, payment.RetryCount)
			p.mu.Unlock()
			
			success, _ = p.processWithGateway(ctx, payment, gateway)
		}
	}

	if success {
		circuitBreaker.RecordSuccess()
		return p.handlePaymentSuccess(payment, gateway.Name, startTime)
	} else {
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
	// Check context cancellation
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}

	// Simulate gateway latency with context timeout
	processingTime := gateway.Latency + time.Duration(secureRandIntn(100))*time.Millisecond
	
	// Use context with timeout for gateway processing
	gatewayCtx, cancel := context.WithTimeout(ctx, p.config.GatewayTimeout)
	defer cancel()

	// Simulate processing with potential cancellation
	done := make(chan bool, 1)
	go func() {
		time.Sleep(processingTime)
		
		// Determine success based on gateway success rate and chaos
		successThreshold := gateway.SuccessRate * p.chaosInjector.GetSuccessRateModifier()
		success := secureRandFloat64() <= successThreshold
		done <- success
	}()

	select {
	case <-gatewayCtx.Done():
		return false, gatewayCtx.Err()
	case success := <-done:
		return success, nil
	}
}

func (p *PaymentProcessor) selectPaymentGateway() PaymentGateway {
	p.mu.Lock()
	defer p.mu.Unlock()

	activeGateways := make([]PaymentGateway, 0)
	for _, gw := range p.gateways {
		if gw.IsActive && p.circuitBreakers[gw.Name].State() != "open" {
			activeGateways = append(activeGateways, gw)
		}
	}

	if len(activeGateways) == 0 {
		// Fallback to first gateway if none active (bypass circuit breaker in emergency)
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

	// Update average processing time
	if p.metrics.Successful == 1 {
		p.metrics.AverageProcessingTime = processingTime
	} else {
		p.metrics.AverageProcessingTime = time.Duration(
			(float64(p.metrics.AverageProcessingTime)*float64(p.metrics.Successful-1)+float64(processingTime))/float64(p.metrics.Successful),
		)
	}
	
	if p.metrics.TotalProcessed > 0 {
		p.metrics.SuccessRate = float64(p.metrics.Successful) / float64(p.metrics.TotalProcessed)
	} else {
		p.metrics.SuccessRate = 0
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
	} else {
		p.metrics.SuccessRate = 0
	}

	fmt.Printf("Payment %s failed: %v\n", payment.ID, err)

	return payment, err
}

// Idempotency support
func (p *PaymentProcessor) getIdempotentPayment(key string) (*Payment, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	if payment, exists := p.idempotencyStore[key]; exists {
		return payment, true
	}
	return nil, false
}

// FraudDetectionService simulates fraud detection logic
type FraudDetectionService struct {
	config       *Config
	riskPatterns []string
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
	// Simulate fraud detection processing
	time.Sleep(50 * time.Millisecond)

	result := &FraudDetectionResult{
		RiskScore: secureRandFloat64(),
	}

	// High amount transactions have higher risk
	if payment.Amount > 1000 {
		result.RiskScore += 0.3
		result.Reasons = append(result.Reasons, "high_amount")
	}

	// Random risk patterns
	if secureRandFloat64() < 0.1 {
		pattern := f.riskPatterns[secureRandIntn(len(f.riskPatterns))]
		result.Reasons = append(result.Reasons, pattern)
		result.RiskScore += 0.4
	}

	result.IsFraudulent = result.RiskScore > f.config.FraudThreshold

	return result, nil
}

// ChaosInjector for payment-specific failures
type ChaosInjector struct {
	config         *Config
	mu             sync.RWMutex
	failureRate    float64
	latencyRange   time.Duration
	gatewayOutages map[string]bool
}

func NewChaosInjector(config *Config) *ChaosInjector {
	return &ChaosInjector{
		config:         config,
		failureRate:    config.BaseFailureRate,
		latencyRange:   2 * time.Second,
		gatewayOutages: make(map[string]bool),
	}
}

func (c *ChaosInjector) InjectPaymentChaos(payment *Payment) error {
	// Random gateway outages
	if secureRandFloat64() < 0.02 { // 2% chance of gateway outage
		gateway := "unknown"
		if secureRandFloat64() < 0.5 {
			gateway = "Stripe"
		} else {
			gateway = "PayPal"
		}
		c.mu.Lock()
		c.gatewayOutages[gateway] = true
		c.mu.Unlock()
		fmt.Printf("Simulating gateway outage: %s\n", gateway)
	}

	// Random latency spikes
	if secureRandFloat64() < 0.03 { // 3% chance of high latency
		latency := time.Duration(secureRandIntn(int(c.latencyRange)))
		time.Sleep(latency)
		fmt.Printf("Injected latency: %v\n", latency)
	}

	// Simulate network timeouts
	if secureRandFloat64() < 0.01 { // 1% chance of timeout
		return ErrGatewayTimeout
	}

	return nil
}

func (c *ChaosInjector) GetSuccessRateModifier() float64 {
	// Reduce success rate based on chaos conditions
	modifier := 1.0
	c.mu.RLock()
	outages := len(c.gatewayOutages)
	c.mu.RUnlock()
	if outages > 0 {
		modifier -= 0.1 * float64(outages)
	}
	if modifier < 0 {
		modifier = 0
	}
	return modifier
}

// Business analytics and reporting
func (p *PaymentProcessor) GenerateBusinessReport() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	revenueByMerchant := make(map[string]float64)
	gatewayStats := make(map[string]int)
	
	for _, payment := range p.transactionHistory {
		if payment.Status == "completed" {
			revenueByMerchant[payment.MerchantID] += payment.Amount
		}
	}

	// Circuit breaker states
	circuitStates := make(map[string]string)
	for gateway, cb := range p.circuitBreakers {
		circuitStates[gateway] = cb.State()
	}

	return map[string]interface{}{
		"metrics":             p.metrics,
		"revenue_by_merchant": revenueByMerchant,
		"gateway_stats":       gatewayStats,
		"circuit_breaker_states": circuitStates,
		"total_transactions":  len(p.transactionHistory),
		"timestamp":           time.Now().Format(time.RFC3339),
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

// Utility functions
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

// Demo execution
func main() {
	fmt.Println("Enhanced Payment Processing System with Chaos Engineering")
	fmt.Println("=======================================================")

	config := LoadConfig()
	processor := NewPaymentProcessor(config)

	// Simulate business transactions
	merchants := []string{"amazon", "netflix", "spotify", "uber", "starbucks"}
	customers := []string{"cust_001", "cust_002", "cust_003", "cust_004", "cust_005"}

	fmt.Println("\nProcessing payments...")

	// Process multiple payments with context and idempotency
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

			// Small delay between transactions
			time.Sleep(100 * time.Millisecond)
		}(i)
	}

	wg.Wait()

	// Generate business report
	fmt.Println("\nEnhanced Business Report:")
	fmt.Println("========================")

	report := processor.GenerateBusinessReport()
	metrics := report["metrics"].(*PaymentMetrics)
	circuitStates := report["circuit_breaker_states"].(map[string]string)

	fmt.Printf("Total Processed: %d\n", metrics.TotalProcessed)
	fmt.Printf("Successful: %d\n", metrics.Successful)
	fmt.Printf("Failed: %d\n", metrics.Failed)
	fmt.Printf("Fraud Detected: %d\n", metrics.FraudDetected)
	fmt.Printf("Circuit Breaker Trips: %d\n", metrics.CircuitBreakerTrips)
	fmt.Printf("Success Rate: %.2f%%\n", metrics.SuccessRate*100)
	fmt.Printf("Total Amount Processed: $%.2f\n", metrics.TotalAmount)
	fmt.Printf("Average Processing Time: %v\n", metrics.AverageProcessingTime)

	fmt.Println("\nCircuit Breaker States:")
	for gateway, state := range circuitStates {
		fmt.Printf("  %s: %s\n", gateway, state)
	}

	// Save detailed report
	if err := processor.SaveReportToFile("enhanced_payment_report.json"); err != nil {
		fmt.Printf("Error saving report: %v\n", err)
	} else {
		fmt.Println("\nDetailed report saved to enhanced_payment_report.json")
	}

	// Demonstrate system resilience
	fmt.Println("\nEnhanced Chaos Resilience Analysis:")
	fmt.Println("==================================")
	fmt.Printf("System handled %.1f%% success rate under chaos conditions\n", metrics.SuccessRate*100)
	fmt.Printf("Detected and prevented %d fraudulent transactions\n", metrics.FraudDetected)
	fmt.Printf("Circuit breakers prevented %d potential cascade failures\n", metrics.CircuitBreakerTrips)
	fmt.Printf("Processed $%.2f in total transaction volume\n", metrics.TotalAmount)
	fmt.Printf("Average processing time: %v\n", metrics.AverageProcessingTime)
	
	// Show configuration
	fmt.Println("\nSystem Configuration:")
	fmt.Printf("Max Retries: %d\n", config.MaxRetries)
	fmt.Printf("Fraud Threshold: %.2f\n", config.FraudThreshold)
	fmt.Printf("Circuit Breaker: %d failures / %v reset\n", 
		config.CircuitBreakerFailures, config.CircuitBreakerReset)
}
