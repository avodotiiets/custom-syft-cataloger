package main

import (
	"context"
	"crypto"
	"fmt"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	customcat "github.com/avodotiiets/custom-syft-cataloger"
	"os"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/filecataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// const defaultImage = "erlang:26.1.2"
const defaultImage = "hexpm/elixir:1.15.6-erlang-26.1.2-alpine-3.18.4"

func main() {
	// automagically get a source.Source for arbitrary string input
	src := getSource(imageReference())

	// will catalog the given source and return a SBOM keeping in mind several configurable options
	sbom := getSBOM(src)

	bytes := formatSBOM(sbom)

	sbomJson := string(bytes)
	fmt.Println(sbomJson)
}

func formatSBOM(s sbom.SBOM) []byte {
	bytes, err := format.Encode(s, syftjson.NewFormatEncoder())
	if err != nil {
		panic(err)
	}
	return bytes
}

func imageReference() string {
	// read an image string reference from the command line or use a default
	if len(os.Args) > 1 {
		return os.Args[1]
	}
	return defaultImage
}

func getSource(input string) source.Source {
	fmt.Println("detecting source type for input:", input, "...")

	src, err := syft.GetSource(context.Background(), input, nil)

	if err != nil {
		panic(err)
	}

	return src
}

func getSBOM(src source.Source) sbom.SBOM {
	fmt.Println("creating SBOM...")

	cfg := syft.DefaultCreateSBOMConfig().
		// run the catalogers in parallel (5 at a time concurrently max)
		WithParallelism(5).
		// bake a specific tool name and version into the SBOM
		WithTool("my-tool", "v1.0").
		// catalog all files with 3 digests
		WithFilesConfig(
			filecataloging.DefaultConfig().
				WithSelection(file.AllFilesSelection).
				WithHashers(
					crypto.MD5,
					crypto.SHA1,
					crypto.SHA256,
				),
		).
		// only use OS related catalogers that would have been used with the kind of
		// source type (container image or directory), but also add a specific python cataloger
		WithCatalogerSelection(
			cataloging.NewSelectionRequest().
				WithSubSelections("os").
				WithAdditions("python-package-cataloger", "binary-classifier-cataloger"),
		).
		// which relationships to include
		WithRelationshipsConfig(
			cataloging.RelationshipsConfig{
				PackageFileOwnership:                          true,
				PackageFileOwnershipOverlap:                   true,
				ExcludeBinaryPackagesWithFileOwnershipOverlap: true,
			},
		).
		// add your own cataloger to the mix
		WithCatalogers(
			pkgcataloging.NewAlwaysEnabledCatalogerReference(
				customcat.NewCustomCataloger(),
			),
		)

	s, err := syft.CreateSBOM(context.Background(), src, cfg)
	if err != nil {
		panic(err)
	}

	return *s
}
