package customcat

import (
	"context"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

/*
  This is a contrived cataloger that attempts to capture useful APK files from the image as if it were a package.
  This isn't a real cataloger, but it is a good example of how to use API elements to create a custom cataloger.
*/

type customErlangCataloger struct {
}

func NewCustomCataloger() pkg.Cataloger {
	return customErlangCataloger{}
}

func (m customErlangCataloger) Name() string {
	return "custom-erlang-cataloger"
}

func (m customErlangCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	erlangExecLocations, err := resolver.FilesByPath("/usr/local/bin/erl")

	if err != nil {
		return nil, nil, err
	}

	foundPkgs := []pkg.Package{}

	for _, location := range erlangExecLocations {
		//TODO: resolve ver

		erlPkg := pkg.Package{
			Name:      "erlang",
			Version:   "26.1.2",
			Locations: file.NewLocationSet(location),
			Type:      pkg.BinaryPkg,
		}

		foundPkgs = append(foundPkgs, erlPkg)
	}

	return foundPkgs, nil, nil
}
