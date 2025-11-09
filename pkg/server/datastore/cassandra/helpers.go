package cassandra

// tiny helpers
func ifThen[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}
func ifThenI64(cond bool, a, b int64) int64 {
	if cond {
		return a
	}
	return b
}
func ifThenBool(cond bool, a, b bool) bool {
	if cond {
		return a
	}
	return b
}
