//go:build !with_naive

package outbound

import "errors"

type Naive struct {
	*Base
}

func NewNaive(NaiveOption) (*Naive, error) {
	return nil, errors.New("naive support is not included in this build; rebuild with -tags with_naive (and with_purego when using a dynamic Cronet library)")
}
