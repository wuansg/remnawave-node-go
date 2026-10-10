package accessaudit

import (
	"context"
	"sync"
	"time"
)

type Collector struct {
	Store  *Store
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func Start(store *Store, address, secret string) *Collector {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Collector{Store: store, cancel: cancel}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		pruneTicker := time.NewTicker(time.Hour)
		defer pruneTicker.Stop()
		for {
			if err := store.Prune(time.Now()); err != nil {
				store.Runtime(false, err)
			}
			select {
			case <-ctx.Done():
				return
			case <-pruneTicker.C:
			}
		}
	}()
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			if !store.Enabled(time.Now()) {
				store.Runtime(false, nil)
				continue
			}
			streamCtx, stop := context.WithCancel(ctx)
			done := make(chan struct{})
			go func() {
				defer close(done)
				t := time.NewTicker(time.Second)
				defer t.Stop()
				for {
					select {
					case <-streamCtx.Done():
						return
					case <-t.C:
						if !store.Enabled(time.Now()) {
							stop()
							return
						}
					}
				}
			}()
			err := Subscribe(streamCtx, address, secret, func(events []Event) error { store.Runtime(true, nil); return store.Apply(events, time.Now()) })
			stop()
			<-done
			store.Runtime(false, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
		}
	}()
	return c
}
func (c *Collector) Close() error { c.cancel(); c.wg.Wait(); return c.Store.Close() }
