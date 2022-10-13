/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"github.com/falcosecurity/plugins/build/oci/pkg/output"
	"github.com/falcosecurity/plugins/build/registry/pkg/registry"
	"github.com/falcosecurity/plugins/build/registry/pkg/registry/distribution"
	"github.com/spf13/cobra"
	"os"
)

const (
	defaultTableSubTag = "<!-- REGISTRY -->"
)

func loadRegistryFromFile(fname string) (*registry.Registry, error) {
	file, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return registry.Load(file)
}

func doCheck(fileName string) error {
	registry, err := loadRegistryFromFile(fileName)
	if err != nil {
		return err
	}
	return registry.Validate()
}

func doUpdateIndex(registryFile, ociArtifactsFile, indexFile string) error {
	registry, err := loadRegistryFromFile(registryFile)
	if err != nil {
		return err
	}

	ociEntries := output.New()
	if err := ociEntries.Read(ociArtifactsFile); err != nil {
		return err
	}

	if err := registry.Validate(); err != nil {
		return err
	}
	return distribution.UpsertIndex(registry, ociEntries, indexFile)
}

func main() {
	checkCmd := &cobra.Command{
		Use:                   "check <filename>",
		Short:                 "Verify the correctness of a plugin registry YAML file",
		Args:                  cobra.ExactArgs(1),
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			return doCheck(args[0])
		},
	}
	updateIndexCmd := &cobra.Command{
		Use:                   "update-index <registryFilename> <ociArtifactsFilename> <indexFilename>",
		Short:                 "Update an index file for artifacts distribution using registry data",
		Args:                  cobra.ExactArgs(3),
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			return doUpdateIndex(args[0], args[1], args[2])
		},
	}

	rootCmd := &cobra.Command{
		Use:     "registry",
		Version: "0.2.0",
	}
	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(updateIndexCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}
}
