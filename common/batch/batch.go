package batch

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
)

type Option[T any] func(b *Batch[T])

type Result[T any] struct {
	Value T
	Err   error
}

type Error struct {
	Key string
	Err error
}

func WithConcurrencyNum[T any](n int) Option[T] {
	return func(b *Batch[T]) {
		q := make(chan struct{}, n)
		for i := 0; i < n; i++ {
			q <- struct{}{}
		}
		b.queue = q
	}
}

// Batch similar to errgroup, but can control the maximum number of concurrent
type Batch[T any] struct {
	result map[string]Result[T]
	queue  chan struct{}
	wg     sync.WaitGroup
	mux    sync.Mutex
	err    *Error
	once   sync.Once
	cancel func()
}

func (b *Batch[T]) Go(key string, fn func() (T, error)) {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		var value T
		var err error
		defer func() {
			if recovered := recover(); recovered != nil {
				err = fmt.Errorf("batch task %q panicked: %v\n%s", key, recovered, debug.Stack())
			}
			b.storeResult(key, value, err)
		}()
		if b.queue != nil {
			<-b.queue
			defer func() {
				b.queue <- struct{}{}
			}()
		}

		value, err = fn()
	}()
}

func (b *Batch[T]) storeResult(key string, value T, err error) {
	if err != nil {
		b.once.Do(func() {
			b.err = &Error{key, err}
			if b.cancel != nil {
				b.cancel()
			}
		})
	}

	ret := Result[T]{value, err}
	b.mux.Lock()
	defer b.mux.Unlock()
	b.result[key] = ret
}

func (b *Batch[T]) Wait() *Error {
	b.wg.Wait()
	if b.cancel != nil {
		b.cancel()
	}
	return b.err
}

func (b *Batch[T]) WaitAndGetResult() (map[string]Result[T], *Error) {
	err := b.Wait()
	return b.Result(), err
}

func (b *Batch[T]) Result() map[string]Result[T] {
	b.mux.Lock()
	defer b.mux.Unlock()
	copyM := map[string]Result[T]{}
	for k, v := range b.result {
		copyM[k] = v
	}
	return copyM
}

func New[T any](ctx context.Context, opts ...Option[T]) (*Batch[T], context.Context) {
	ctx, cancel := context.WithCancel(ctx)

	b := &Batch[T]{
		result: map[string]Result[T]{},
	}

	for _, o := range opts {
		o(b)
	}

	b.cancel = cancel
	return b, ctx
}
