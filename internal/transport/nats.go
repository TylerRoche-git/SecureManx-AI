package transport

import (
	"context"
	"fmt"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// NATSClient wraps a NATS connection and JetStream context.
type NATSClient struct {
	conn      *nats.Conn
	jetstream jetstream.JetStream
}

// NewNATSClient connects to NATS and initialises JetStream.
func NewNATSClient(url string) (*NATSClient, error) {
	conn, err := nats.Connect(url)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}

	js, err := jetstream.New(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("jetstream init: %w", err)
	}

	return &NATSClient{conn: conn, jetstream: js}, nil
}

// Publish sends data to a NATS subject.
func (c *NATSClient) Publish(ctx context.Context, subject string, data []byte) error {
	_, err := c.jetstream.Publish(ctx, subject, data)
	if err != nil {
		return fmt.Errorf("publish %s: %w", subject, err)
	}
	return nil
}

// Subscribe registers a handler for messages on a subject via a durable consumer.
func (c *NATSClient) Subscribe(ctx context.Context, stream, subject, consumer string, handler func(msg jetstream.Msg)) (jetstream.ConsumeContext, error) {
	cons, err := c.jetstream.CreateOrUpdateConsumer(ctx, stream, jetstream.ConsumerConfig{
		Durable:       consumer,
		FilterSubject: subject,
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return nil, fmt.Errorf("create consumer %s: %w", consumer, err)
	}

	cc, err := cons.Consume(handler)
	if err != nil {
		return nil, fmt.Errorf("consume %s: %w", consumer, err)
	}
	return cc, nil
}

// CreateStream creates a JetStream stream if it does not already exist.
func (c *NATSClient) CreateStream(ctx context.Context, name string, subjects []string) error {
	_, err := c.jetstream.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:     name,
		Subjects: subjects,
	})
	if err != nil {
		return fmt.Errorf("create stream %s: %w", name, err)
	}
	return nil
}

// CreateAllStreams creates all standard streams defined in StreamConfig.
func (c *NATSClient) CreateAllStreams(ctx context.Context) error {
	for name, subjects := range StreamConfig {
		if err := c.CreateStream(ctx, name, subjects); err != nil {
			return err
		}
	}
	return nil
}

// JetStream returns the underlying JetStream context for advanced use.
func (c *NATSClient) JetStream() jetstream.JetStream {
	return c.jetstream
}

// Close drains and closes the NATS connection.
func (c *NATSClient) Close() {
	c.conn.Drain()
	c.conn.Close()
}
