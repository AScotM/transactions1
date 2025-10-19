package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
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
}

type PaymentGateway struct {
	Name       string        `json:"name"`
	SuccessRate float64      `json:"success_rate"`
	Latency    time.Duration `json:"latency"`
	IsActive   bool          `json:"is_active"`
}

type FraudDetectionResult struct {
	IsFraudulent bool     `json:"is_fraudulent"`
	RiskScore    float64  `json:"risk_score"`
	Reasons      []string `json:"reasons"`
}

// Core business service
type PaymentProcessor struct {
	gateways           []PaymentGateway
	fraudService       *FraudDetectionService
	chaosInjector      *ChaosInjector
	transactionHistory map[string]*Payment
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
}

func NewPaymentProcessor() *PaymentProcessor {
	gateways := []PaymentGateway{
		{Name: "Stripe", SuccessRate: 0.98, Latency: 200 * time.Millisecond, IsActive: true},
		{Name: "PayPal", SuccessRate: 0.96, Latency: 300 * time.Millisecond, IsActive: true},
		{Name: "Square", SuccessRate: 0.97, Latency: 250 * time.Millisecond, IsActive: true},
		{Name: "Adyen", SuccessRate: 0.99, Latency: 150 * time.Millisecond, IsActive: true},
	}

	return &PaymentProcessor{
		gateways:           gateways,
		fraudService:       NewFraudDetectionService(),
		chaosInjector:      NewChaosInjector(),
		transactionHistory: make(map[string]*Payment),
		metrics:            &PaymentMetrics{},
	}
}

// ProcessPayment handles the complete payment flow with chaos injection
func (p *PaymentProcessor) ProcessPayment(amount float64, currency, merchantID, customerID string) (*Payment, error) {
	startTime := time.Now()

	payment := &Payment{
		ID:         generatePaymentID(),
		Amount:     amount,
		Currency:   currency,
		MerchantID: merchantID,
		CustomerID: customerID,
		Status:     "pending",
		CreatedAt:  time.Now(),
	}

	p.mu.Lock()
	p.transactionHistory[payment.ID] = payment
	p.mu.Unlock()

	fmt.Printf("Processing payment %s: $%.2f from %s to %s\n",
		payment.ID, amount, customerID, merchantID)

	// Step 1: Fraud detection
	fraudResult, err := p.fraudService.CheckPayment(payment)
	if err != nil {
		return p.handlePaymentFailure(payment, "fraud_detection_error", startTime)
	}

	if fraudResult.IsFraudulent {
		p.metrics.FraudDetected++
		return p.handlePaymentFailure(payment, "fraud_detected", startTime)
	}

	// Step 2: Inject chaos (simulate real-world failures)
	if err := p.chaosInjector.InjectPaymentChaos(payment); err != nil {
		fmt.Printf("Chaos injection affected payment %s: %v\n", payment.ID, err)
	}

	// Step 3: Process with selected gateway
	gateway := p.selectPaymentGateway()
	payment.Status = "processing"

	// Simulate gateway processing with potential failure
	success := p.processWithGateway(payment, gateway)
	if !success {
		// Retry logic
		if payment.RetryCount < 2 {
			payment.RetryCount++
			fmt.Printf("Retrying payment %s (attempt %d)\n", payment.ID, payment.RetryCount)
			success = p.processWithGateway(payment, gateway)
		}
	}

	if success {
		return p.handlePaymentSuccess(payment, gateway.Name, startTime)
	} else {
		return p.handlePaymentFailure(payment, "gateway_failure", startTime)
	}
}

func (p *PaymentProcessor) processWithGateway(payment *Payment, gateway PaymentGateway) bool {
	// Simulate gateway latency
	processingTime := gateway.Latency + time.Duration(secureRandIntn(100))*time.Millisecond
	time.Sleep(processingTime)

	// Determine success based on gateway success rate and chaos
	successThreshold := gateway.SuccessRate * p.chaosInjector.GetSuccessRateModifier()
	return secureRandFloat64() <= successThreshold
}

func (p *PaymentProcessor) selectPaymentGateway() PaymentGateway {
	// Simple round-robin selection - in reality, this would be more sophisticated
	p.mu.Lock()
	defer p.mu.Unlock()

	activeGateways := make([]PaymentGateway, 0)
	for _, gw := range p.gateways {
		if gw.IsActive {
			activeGateways = append(activeGateways, gw)
		}
	}

	if len(activeGateways) == 0 {
		// Fallback to first gateway if none active
		return p.gateways[0]
	}

	return activeGateways[secureRandIntn(len(activeGateways))]
}

func (p *PaymentProcessor) handlePaymentSuccess(payment *Payment, gateway string, startTime time.Time) (*Payment, error) {
	processingTime := time.Since(startTime)

	payment.Status = "completed"
	payment.ProcessedAt = time.Now()

	p.mu.Lock()
	p.metrics.Successful++
	p.metrics.TotalProcessed++
	p.metrics.TotalAmount += payment.Amount
	
	// Update average processing time
	if p.metrics.Successful == 1 {
		p.metrics.AverageProcessingTime = processingTime
	} else {
		p.metrics.AverageProcessingTime = time.Duration(
			(float64(p.metrics.AverageProcessingTime)*float64(p.metrics.Successful-1) + float64(processingTime)) / float64(p.metrics.Successful),
		)
	}
	p.metrics.SuccessRate = float64(p.metrics.Successful) / float64(p.metrics.TotalProcessed)
	p.mu.Unlock()

	fmt.Printf("Payment %s completed successfully via %s (took %v)\n",
		payment.ID, gateway, processingTime)

	return payment, nil
}

func (p *PaymentProcessor) handlePaymentFailure(payment *Payment, reason string, startTime time.Time) (*Payment, error) {
	payment.Status = "failed"
	payment.ErrorReason = reason
	payment.ProcessedAt = time.Now()

	p.mu.Lock()
	p.metrics.Failed++
	p.metrics.TotalProcessed++
	p.metrics.SuccessRate = float64(p.metrics.Successful) / float64(p.metrics.TotalProcessed)
	p.mu.Unlock()

	fmt.Printf("Payment %s failed: %s\n", payment.ID, reason)

	return payment, fmt.Errorf("payment failed: %s", reason)
}

// FraudDetectionService simulates fraud detection logic
type FraudDetectionService struct {
	riskPatterns []string
}

func NewFraudDetectionService() *FraudDetectionService {
	return &FraudDetectionService{
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

	result.IsFraudulent = result.RiskScore > 0.7

	return result, nil
}

// ChaosInjector for payment-specific failures
type ChaosInjector struct {
	failureRate    float64
	latencyRange   time.Duration
	gatewayOutages map[string]bool
}

func NewChaosInjector() *ChaosInjector {
	return &ChaosInjector{
		failureRate:    0.05, // 5% base failure rate
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
		c.gatewayOutages[gateway] = true
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
		return errors.New("network_timeout")
	}

	return nil
}

func (c *ChaosInjector) GetSuccessRateModifier() float64 {
	// Reduce success rate based on chaos conditions
	modifier := 1.0
	if len(c.gatewayOutages) > 0 {
		modifier -= 0.1 * float64(len(c.gatewayOutages))
	}
	return modifier
}

// Business analytics and reporting
func (p *PaymentProcessor) GenerateBusinessReport() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	revenueByMerchant := make(map[string]float64)
	for _, payment := range p.transactionHistory {
		if payment.Status == "completed" {
			revenueByMerchant[payment.MerchantID] += payment.Amount
		}
	}

	return map[string]interface{}{
		"metrics":            p.metrics,
		"revenue_by_merchant": revenueByMerchant,
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
	return fmt.Sprintf("pay_%d_%d", time.Now().Unix(), secureRandIntn(10000))
}

func secureRandIntn(n int) int {
	if n <= 0 {
		return 0
	}
	num, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		var fallback int64
		binary.Read(rand.Reader, binary.BigEndian, &fallback)
		if fallback < 0 {
			fallback = -fallback
		}
		return int(fallback % int64(n))
	}
	return int(num.Int64())
}

func secureRandFloat64() float64 {
	var buf [8]byte
	rand.Read(buf[:])
	return float64(binary.LittleEndian.Uint64(buf[:])&((1<<53)-1)) / (1 << 53)
}

// Demo execution
func main() {
	fmt.Println("Payment Processing System with Chaos Engineering")
	fmt.Println("=============================================")

	processor := NewPaymentProcessor()

	// Simulate business transactions
	merchants := []string{"amazon", "netflix", "spotify", "uber", "starbucks"}
	customers := []string{"cust_001", "cust_002", "cust_003", "cust_004", "cust_005"}

	fmt.Println("\nProcessing payments...")

	// Process multiple payments
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(transactionNum int) {
			defer wg.Done()

			amount := float64(10 + secureRandIntn(500))
			merchant := merchants[secureRandIntn(len(merchants))]
			customer := customers[secureRandIntn(len(customers))]

			payment, err := processor.ProcessPayment(amount, "USD", merchant, customer)
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
	fmt.Println("\nBusiness Report:")
	fmt.Println("================")

	report := processor.GenerateBusinessReport()
	metrics := report["metrics"].(*PaymentMetrics)

	fmt.Printf("Total Processed: %d\n", metrics.TotalProcessed)
	fmt.Printf("Successful: %d\n", metrics.Successful)
	fmt.Printf("Failed: %d\n", metrics.Failed)
	fmt.Printf("Fraud Detected: %d\n", metrics.FraudDetected)
	fmt.Printf("Success Rate: %.2f%%\n", metrics.SuccessRate*100)
	fmt.Printf("Total Amount Processed: $%.2f\n", metrics.TotalAmount)
	fmt.Printf("Average Processing Time: %v\n", metrics.AverageProcessingTime)

	// Save detailed report
	if err := processor.SaveReportToFile("payment_processing_report.json"); err != nil {
		fmt.Printf("Error saving report: %v\n", err)
	} else {
		fmt.Println("\nDetailed report saved to payment_processing_report.json")
	}

	// Demonstrate system resilience
	fmt.Println("\nChaos Resilience Analysis:")
	fmt.Println("========================")
	fmt.Printf("System handled %.1f%% success rate under chaos conditions\n", metrics.SuccessRate*100)
	fmt.Printf("Detected and prevented %d fraudulent transactions\n", metrics.FraudDetected)
	fmt.Printf("Processed $%.2f in total transaction volume\n", metrics.TotalAmount)
}
