package registry

import (
	"fmt"

	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/awslabs/amazon-ecr-credential-helper/ecr-login/api"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type PlatformImageReference struct {
	ImageReference

	Platform v1.Platform
}

type RemoteRepository struct {
	auth remote.Option
}

func NewRemoteRepository() *RemoteRepository {
	factory := api.DefaultClientFactory{}
	ecrHelper := ecr.NewECRHelper(ecr.WithClientFactory(factory))

	authOption := remote.WithAuthFromKeychain(authn.NewKeychainFromHelper(ecrHelper))

	return &RemoteRepository{
		auth: authOption,
	}
}

// ResolveImageReferences takes an image and resolves it to a list of
// platform-specific images. If the image is not a manifest list, the supplied
// image is returned as the only item in the list (but with the platform if it
// is known).
func (r *RemoteRepository) ResolveImageReferences(imageReference ImageReference) ([]PlatformImageReference, error) {
	ref, err := name.ParseReference(imageReference.String())
	if err != nil {
		return nil, fmt.Errorf("image reference format invalid: %w", err)
	}

	img, err := remote.Get(ref, r.auth)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve index: %w", err)
	}

	// standard image, return immediately with the platform if possible
	if img.MediaType.IsImage() {
		platform := img.Platform
		if platform == nil {
			platform = &v1.Platform{
				OS:           "unknown",
				Architecture: "unknown",
			}
		}

		return []PlatformImageReference{
			{
				ImageReference: imageReference,
				Platform:       *platform,
			},
		}, nil
	}

	// only accept either single images or lists
	if !img.MediaType.IsIndex() {
		return nil, fmt.Errorf("image type is not recognized as a manifest index: %s", img.MediaType)
	}

	// yield the set of images for each architecture in the list
	idx, err := img.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("failed to convert to manifest index: %w", err)
	}

	mf, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest index: %w", err)
	}

	images := make([]PlatformImageReference, 0, len(mf.Manifests))

	for _, m := range mf.Manifests {
		if m.Platform == nil {
			continue
		}

		ref := PlatformImageReference{
			ImageReference: imageReference.WithDigest(m.Digest.String()),
			Platform:       *m.Platform,
		}

		images = append(images, ref)
	}

	return images, nil
}
