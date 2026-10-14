package session

import (
	"sync"
	"testing"
)

func TestStreamCloseConcurrentRead(t *testing.T) {
	for i := 0; i < 100; i++ {
		stream := newStream(1, nil)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = stream.Read(make([]byte, 1))
		}()
		stream.closeLocally()
		wg.Wait()
	}
}
