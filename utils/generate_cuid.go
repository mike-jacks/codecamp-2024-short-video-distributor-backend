package utils

import (
	"math/rand/v2"
	"sync/atomic"
	"time"

	"github.com/nrednav/cuid2"
)

// Generate unique cuid2 ids

var generator func() string

func init() {
	var err error
	startValue := time.Now().UnixNano()
	counter := NewCounter(startValue)

	generator, err = cuid2.Init(
		cuid2.WithRandomFunc(rand.Float64),
		cuid2.WithLength(32),
		cuid2.WithFingerprint("Codecamp Rocks!"),
		cuid2.WithSessionCounter(counter),
	)
	if err != nil {
		panic(err)
	}
}

type Counter struct {
	value int64
}

func NewCounter(initialCount int64) *Counter {
	return &Counter{value: initialCount}
}

func (c *Counter) Increment() int64 {
	return atomic.AddInt64(&c.value, 1)
}

func GenerateId() string {
	return generator()
}
