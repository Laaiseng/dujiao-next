package application

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	productdomain "github.com/dujiao-next/internal/modules/catalog/product/domain"
	fulfillmentdomain "github.com/dujiao-next/internal/modules/fulfillment/domain"
	orderapp "github.com/dujiao-next/internal/modules/order/application"
	ordercontract "github.com/dujiao-next/internal/modules/order/contract"
	paymentcontract "github.com/dujiao-next/internal/modules/payment/contract"
	paymentdomain "github.com/dujiao-next/internal/modules/payment/domain"
	settingsapp "github.com/dujiao-next/internal/modules/settings/application"

	"github.com/dujiao-next/internal/constants"
	"github.com/dujiao-next/internal/logger"
	"github.com/dujiao-next/internal/shared/jsonmap"
)

var (
	ErrPlusIssueNotConfigured  = errors.New("plus issue not configured")
	ErrPlusIssueNotPlusType    = errors.New("fulfillment is not plus_issue")
	ErrPlusIssuePaymentMissing = errors.New("paid payment missing for plus issue")
	ErrPlusIssueProductConfig  = errors.New("plus issue product config invalid")
)

type productReader interface {
	GetByID(id string) (*productdomain.Product, error)
}

// SetPlusIssueDeps wires optional dependencies for zero-inventory plus issuance.
func (s *Service) SetPlusIssueDeps(payments paymentcontract.Store, products productReader, issuer PlusIssuer) {
	s.paymentStore = payments
	s.productReader = products
	if issuer != nil {
		s.plusIssuer = issuer
	} else {
		s.plusIssuer = NewHTTPPlusIssuer()
	}
}

// CreatePlusIssue asks plus to mint cards after payment and writes fulfillment.payload.
// Failures return an error so asynq can retry; after retries the order stays fulfilling for manual handling.
func (s *Service) CreatePlusIssue(orderID uint) (*fulfillmentdomain.Fulfillment, error) {
	if orderID == 0 {
		return nil, ErrFulfillmentInvalid
	}
	order, err := s.orderStore.GetByID(orderID)
	if err != nil {
		return nil, ErrOrderFetchFailed
	}
	if order == nil {
		return nil, ErrOrderNotFound
	}
	if order.ParentID == nil && len(order.Children) > 0 {
		return nil, ErrFulfillmentInvalid
	}
	if order.Status != constants.OrderStatusPaid && order.Status != constants.OrderStatusFulfilling {
		return nil, ErrOrderStatusInvalid
	}
	if len(order.Items) == 0 {
		return nil, ErrFulfillmentInvalid
	}
	for _, item := range order.Items {
		if strings.TrimSpace(item.FulfillmentType) != constants.FulfillmentTypePlusIssue {
			return nil, ErrPlusIssueNotPlusType
		}
	}
	if existing, err := s.fulfillmentRepo.GetByOrderID(orderID); err == nil && existing != nil {
		return existing, ErrFulfillmentExists
	}
	if s.paymentStore == nil || s.productReader == nil || s.plusIssuer == nil {
		return nil, ErrPlusIssueNotConfigured
	}

	cfg, err := loadPlusIssueSiteConfig(s.settingService)
	if err != nil {
		return nil, err
	}

	paymentOrderID := orderID
	paymentOrderNo := order.OrderNo
	if order.ParentID != nil {
		paymentOrderID = *order.ParentID
		if parent, perr := s.orderStore.GetByID(paymentOrderID); perr == nil && parent != nil {
			paymentOrderNo = parent.OrderNo
		}
	}
	payments, err := s.paymentStore.ListByOrderID(paymentOrderID)
	if err != nil {
		return nil, err
	}
	payment := pickSuccessfulPayment(payments)
	if payment == nil || strings.TrimSpace(payment.ProviderRef) == "" {
		return nil, ErrPlusIssuePaymentMissing
	}

	// One bepusdt trade_id can only fund one mall order on plus. Multi-line carts would need
	// separate payments, so plus_issue is limited to a single product line per order.
	if len(order.Items) != 1 {
		return nil, ErrPlusIssueProductConfig
	}
	item := order.Items[0]
	if item.ProductID == 0 || item.Quantity <= 0 {
		return nil, ErrFulfillmentInvalid
	}
	product, err := s.productReader.GetByID(strconv.FormatUint(uint64(item.ProductID), 10))
	if err != nil || product == nil {
		return nil, ErrPlusIssueProductConfig
	}
	channel, serviceType, creditQty, err := parsePlusIssueProductConfig(product.PlusIssueConfigJSON)
	if err != nil {
		return nil, err
	}
	req := PlusIssueRequest{
		ExternalOrderNo:  order.OrderNo,
		PaymentOrderNo:   paymentOrderNo,
		TradeID:          strings.TrimSpace(payment.ProviderRef),
		Channel:          channel,
		ServiceType:      serviceType,
		Quantity:         item.Quantity,
		ExpectedAmount:   payment.Amount.Decimal.String(),
		ExpectedCurrency: strings.ToUpper(strings.TrimSpace(payment.Currency)),
		Note:             "dujiao:" + order.OrderNo,
		CreditQuantity:   creditQty,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	resp, issueErr := s.plusIssuer.IssueCards(ctx, cfg.BaseURL, cfg.APIToken, req)
	cancel()
	if issueErr != nil {
		return nil, fmt.Errorf("plus issue for order %s: %w", order.OrderNo, issueErr)
	}
	lines := resp.Cards

	now := time.Now()
	payload := strings.Join(lines, "\n")
	var fulfillment *fulfillmentdomain.Fulfillment
	err = s.orderStore.WithinTransaction(func(tx ordercontract.Transaction) error {
		if _, found, terr := tx.Fulfillments().FindByOrderIDForUpdate(orderID); terr != nil {
			return terr
		} else if found {
			return ErrFulfillmentExists
		}
		fulfillment = &fulfillmentdomain.Fulfillment{
			OrderID:     orderID,
			Type:        constants.FulfillmentTypePlusIssue,
			Status:      constants.FulfillmentStatusDelivered,
			Payload:     payload,
			DeliveredAt: &now,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if cerr := tx.Fulfillments().Create(fulfillment); cerr != nil {
			return ErrFulfillmentCreateFailed
		}
		if uerr := tx.Orders().UpdateFields(orderID, map[string]interface{}{
			"status":     constants.OrderStatusCompleted,
			"updated_at": now,
		}); uerr != nil {
			return ErrOrderUpdateFailed
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrFulfillmentExists) {
			existing, _ := s.fulfillmentRepo.GetByOrderID(orderID)
			return existing, ErrFulfillmentExists
		}
		return nil, err
	}

	if s.orderQueue != nil {
		targetID := orderID
		status := constants.OrderStatusCompleted
		if order.ParentID != nil {
			targetID = *order.ParentID
			if synced, syncErr := orderapp.SyncParentStatus(s.orderStore, targetID, now); syncErr != nil {
				logger.Warnw("plus_issue_sync_parent_status_failed", "order_id", orderID, "error", syncErr)
			} else if synced != "" {
				status = synced
			}
		}
		if status != constants.OrderStatusCanceled {
			if _, emailErr := orderapp.EnqueueStatusEmailTaskIfEligible(s.orderStore, s.orderQueue, s.settingService, s.defaultEmailConfig, targetID, status); emailErr != nil {
				logger.Warnw("plus_issue_enqueue_status_email_failed", "order_id", orderID, "error", emailErr)
			}
		}
	}
	notifyOrderID := orderID
	if order.ParentID != nil {
		notifyOrderID = *order.ParentID
	}
	go s.NotifyBotOrderFulfilled(order.UserID, notifyOrderID)
	if s.downstreamCallbackSvc != nil {
		s.downstreamCallbackSvc.EnqueueCallback(orderID)
	}
	return fulfillment, nil
}

type plusIssueSiteConfig struct {
	BaseURL  string
	APIToken string
}

func loadPlusIssueSiteConfig(settings *settingsapp.Service) (plusIssueSiteConfig, error) {
	if settings == nil {
		return plusIssueSiteConfig{}, ErrPlusIssueNotConfigured
	}
	runtime, err := settings.GetPlusIssueRuntime()
	if err != nil {
		return plusIssueSiteConfig{}, fmt.Errorf("%w: %v", ErrPlusIssueNotConfigured, err)
	}
	if !runtime.Enabled || runtime.BaseURL == "" || runtime.APIToken == "" {
		return plusIssueSiteConfig{}, ErrPlusIssueNotConfigured
	}
	return plusIssueSiteConfig{BaseURL: runtime.BaseURL, APIToken: runtime.APIToken}, nil
}

func parsePlusIssueProductConfig(raw jsonmap.JSON) (channel, serviceType string, credit *int, err error) {
	if raw == nil {
		return "", "", nil, ErrPlusIssueProductConfig
	}
	channel, _ = raw["channel"].(string)
	serviceType, _ = raw["service_type"].(string)
	channel = strings.TrimSpace(channel)
	serviceType = strings.TrimSpace(serviceType)
	if channel == "" || serviceType == "" {
		return "", "", nil, ErrPlusIssueProductConfig
	}
	if channel != "local_pro" && channel != "mapped_orchestrator" {
		return "", "", nil, ErrPlusIssueProductConfig
	}
	switch v := raw["credit_quantity"].(type) {
	case float64:
		n := int(v)
		credit = &n
	case int:
		n := v
		credit = &n
	}
	return channel, serviceType, credit, nil
}

func pickSuccessfulPayment(payments []paymentdomain.Payment) *paymentdomain.Payment {
	for i := range payments {
		if strings.EqualFold(strings.TrimSpace(payments[i].Status), constants.PaymentStatusSuccess) {
			return &payments[i]
		}
	}
	return nil
}
