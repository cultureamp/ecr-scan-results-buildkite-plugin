package registry

import (
	"fmt"

	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/awslabs/amazon-ecr-credential-helper/ecr-login/api"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

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

func (r *RemoteRepository) GetImageForArchitecture(imageReference ImageReference, arch string) (ImageReference, string, error) {
	emptyRef := ImageReference{}

	ref, err := name.ParseReference(imageReference.String())
	if err != nil {
		return emptyRef, "", fmt.Errorf("image reference format invalid: %w", err)
	}

	img, err := remote.Get(ref, r.auth)
	if err != nil {
		return emptyRef, "", fmt.Errorf("failed to retrieve index: %w", err)
	}

	if !img.MediaType.IsIndex() {
		return emptyRef, "", fmt.Errorf("image type is not recognized as a manifest index: %s", img.MediaType)
	}

	idx, err := img.ImageIndex()
	if err != nil {
		return emptyRef, "", fmt.Errorf("failed to convert to manifest index: %w", err)
	}

	mf, err := idx.IndexManifest()
	if err != nil {
		return emptyRef, "", fmt.Errorf("failed to read manifest index: %w", err)
	}

	for _, m := range mf.Manifests {
		if m.Platform.Architecture != arch {
			continue
		}

		archReference := imageReference
		archReference.Tag = ""
		archReference.Digest = m.Digest.String()

		return archReference, m.Platform.String(), nil
	}

	return emptyRef, "", fmt.Errorf("no image found for architecture %s", arch)
}
