package secret

type Secret[T any] struct {
	innerValue T
}

func (s *Secret[T]) String() string {
	return "[Secret ****]"
}

func (s *Secret[T]) DangerouslyRevealSecret() T {
	return s.innerValue
}

func New[T any](value T) Secret[T] {
	return Secret[T]{
		innerValue: value,
	}
}
