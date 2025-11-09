package datastore

import (
	"github.com/gogo/status"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc/codes"
)

func ValidateFederationRelationship(fr *FederationRelationship, mask *types.FederationRelationshipMask) error {
	if fr == nil {
		return status.Error(codes.InvalidArgument, "federation relationship is nil")
	}

	if fr.TrustDomain.IsZero() {
		return status.Error(codes.InvalidArgument, "trust domain is required")
	}

	if mask.BundleEndpointUrl && fr.BundleEndpointURL == nil {
		return status.Error(codes.InvalidArgument, "bundle endpoint URL is required")
	}

	if mask.BundleEndpointProfile {
		switch fr.BundleEndpointProfile {
		case BundleEndpointWeb:
		case BundleEndpointSPIFFE:
			if fr.EndpointSPIFFEID.IsZero() {
				return status.Error(codes.InvalidArgument, "bundle endpoint SPIFFE ID is required")
			}
		default:
			return status.Errorf(codes.InvalidArgument, "unknown bundle endpoint profile type: %q", fr.BundleEndpointProfile)
		}
	}

	return nil
}
