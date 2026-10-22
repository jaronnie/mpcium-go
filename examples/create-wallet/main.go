package main

import (
	"context"
	"fmt"
	mpcium "github.com/jaronnie/mpcium-go"
	"github.com/jaronnie/mpcium-go/event"
	"os"
	"os/signal"
	"time"
)

func run() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: create-wallet <credentials.age> <new-wallet-id>; set MPC_CREDENTIALS_PASSWORD")
	}
	password := os.Getenv("MPC_CREDENTIALS_PASSWORD")
	if password == "" {
		return fmt.Errorf("MPC_CREDENTIALS_PASSWORD is required")
	}
	credentials, err := mpcium.UnlockCredentials(os.Args[1], password)
	if err != nil {
		return err
	}
	defer credentials.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	opts, err := mpcium.Connect(ctx, os.Getenv("NATS_URL"), os.Getenv("NATS_TOKEN"), credentials.ProjectID, credentials)
	if err != nil {
		return err
	}
	nc := opts.NatsConn
	defer nc.Close()
	client := mpcium.NewMPCClient(opts)
	result := make(chan event.KeygenResultEvent, 1)
	if err = client.OnWalletCreationResult(func(e event.KeygenResultEvent) {
		if e.WalletID == os.Args[2] {
			select {
			case result <- e:
			default:
			}
		}
	}); err != nil {
		return err
	}
	if err = nc.FlushWithContext(ctx); err != nil {
		return err
	}
	if err = client.CreateWallet(os.Args[2]); err != nil {
		return err
	}
	select {
	case e := <-result:
		if e.ResultType == event.ResultTypeError {
			return fmt.Errorf("wallet creation failed: %s", e.ErrorReason)
		}
		fmt.Printf("Wallet created: %s\n", e.WalletID)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
