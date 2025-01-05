package managers_test

import "github.com/stretchr/testify/mock"

func fillMock(m *mock.Mock, methods ...mockedMethod) {
	for _, method := range methods {
		m.On(method.name, method.in...).Return(method.out...)
	}
}

type mockedMethod struct {
	name string
	in   []any
	out  []any
}
