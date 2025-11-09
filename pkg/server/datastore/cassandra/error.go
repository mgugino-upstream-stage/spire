package cassandra

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newError creates a gRPC status error with the provided message format and args
func newError(format string, args ...any) error {
	return status.Errorf(codes.Unknown, format, args...)
}

func newInvalidArgumentErrorf(format string, args ...any) error {
	return status.Errorf(codes.InvalidArgument, format, args...)
}

func newNotFoundError(format string, args ...any) error {
	return status.Errorf(codes.NotFound, format, args...)
}

func newAlreadyExistsError(format string, args ...any) error {
	return status.Errorf(codes.AlreadyExists, format, args...)
}

// newInvalidArgumentError creates a gRPC InvalidArgument status error with the provided message
func newInvalidArgumentError(message string) error {
	return status.Error(codes.InvalidArgument, message)
}
