// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package audit

import (
	"context"
	"fmt"
)

// BusSink is the durable-bus Sink for the audit fan-in. The concrete bus
// (NATS/Kafka/AMQP — a component-spec decision, contract #150) is dialled from
// config; until a bus endpoint is configured it fails closed on every publish, so
// the emit-before-ack contract holds (a forward cannot ack without a durable
// record). This is NOT a mock: it is the real sink shell that fails closed absent
// a configured durable bus. The wire-up to a live bus is the remaining work; the
// fail-closed durable-first property is enforced here regardless.
type BusSink struct {
	endpoint string // durable bus endpoint; empty => fail closed
}

// NewBusSink builds the durable-bus sink with the audit-bus endpoint. An empty
// endpoint is permitted at construction (the scaffold may boot without a live
// bus), but every Publish then fails closed rather than reporting a non-durable
// success — which keeps emit-before-ack honest.
func NewBusSink(endpoint string) *BusSink {
	return &BusSink{endpoint: endpoint}
}

// Publish durably commits the payload to the channel. With no configured
// endpoint it fails closed (the durable write cannot be confirmed), so the
// Emitter turns it into a fail-closed refusal rather than acking an unrecorded
// action. A live bus dial that confirmed a durable commit would return nil here.
func (s *BusSink) Publish(_ context.Context, channel string, _ []byte) error {
	if s.endpoint == "" {
		return fmt.Errorf("audit: no durable bus endpoint configured (channel %q)", channel)
	}
	// A live publish dials s.endpoint and returns nil ONLY on a confirmed durable
	// commit. The bus transport (NATS/Kafka/AMQP) is the remaining wire-up; until
	// then a configured-but-unreachable endpoint also fails closed.
	return fmt.Errorf("audit: durable bus transport not yet wired (endpoint %q, channel %q)", s.endpoint, channel)
}
