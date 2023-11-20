package main

import "os"

// Build identnfier is used for identifying different build sub steps
type BuildIdentifier int

const (
	BuildId_Unknown         BuildIdentifier = 0
	BuildId_GitPull         BuildIdentifier = 1
	BuildId_CompileBin      BuildIdentifier = 2
	BuildId_CompileObj      BuildIdentifier = 3
	BuildId_CreateStaticLib BuildIdentifier = 4
	BuildId_ExternalBuild   BuildIdentifier = 5
	BuildId_LocalBuild      BuildIdentifier = 6
)

type TargetDefinition struct {
	// The type of the target
	Type string
	// Determine if the `target`'s artifacts need to be refreshed.
	// The artifacts need to be refreshed if the files it depends on have a different
	// hash compared to the file hashes in the `cache`.
	compute_build_step_refresh func(target *TargetConfig, cache *BuildCache) bool
	// Similar to `compute_build_step_refresh` but for the sub steps of a build step.
	// The key of the map is the unique idenrifier of the build sub step and the value
	// is the function that determines whether or not the sub step needs to be refreshed.
	compute_build_sub_step_refresh map[BuildIdentifier]func(dctx *DoContext, target *TargetConfig) bool
}

var target_definitions = map[string]TargetDefinition{
	"static":  {Type: "static", compute_build_step_refresh: compute_source_refresh, compute_build_sub_step_refresh: make(map[BuildIdentifier]func(dctx *DoContext, target *TargetConfig) bool)},
	"dynamic": {Type: "dynamic", compute_build_step_refresh: compute_source_refresh, compute_build_sub_step_refresh: make(map[BuildIdentifier]func(dctx *DoContext, target *TargetConfig) bool)},
	"binary":  {Type: "binary", compute_build_step_refresh: compute_source_refresh, compute_build_sub_step_refresh: make(map[BuildIdentifier]func(dctx *DoContext, target *TargetConfig) bool)},
	"external": {
		Type:                       "external",
		compute_build_step_refresh: force_refresh,
		compute_build_sub_step_refresh: map[BuildIdentifier]func(dctx *DoContext, target *TargetConfig) bool{
			BuildId_GitPull: should_refresh_git_pull,
		},
	},
}

func force_refresh(target *TargetConfig, cache *BuildCache) bool {
	return true
}

func should_refresh_git_pull(dctx *DoContext, target *TargetConfig) bool {
	git_pull_path := get_git_pull_path(dctx, target.Git, target.Hash)
	// TODO: This only checks that the expected destionation of the git repo exists.
	// Add a check to make sure that the remote for this repo is the one specified in the config
	// and also that it is checked out to the right commit hash.
	if stat, err := os.Stat(git_pull_path); err == nil && stat.IsDir() {
		return false
	}
	return true
}

func compute_source_refresh(target *TargetConfig, cache *BuildCache) bool {
	tcache, is_cached := cache.CachedBuildStep[target.Name]
	if !is_cached {
		return true
	}

	var files []string = append(target.Hdrs, target.Srcs...)
	for _, filename := range files {
		filehash, is_hashed := tcache.FileHashes[filename]
		if !is_hashed {
			return true
		}
		curr_md5, err := compute_md5(filename)
		if err != nil {
			// Couldnt compute md5 hash, so refresh the build.
			return true
		}
		if !bytearr_equal(filehash, curr_md5) {
			return true
		}
	}

	// Check if the list of dependencies changed.
	if len(target.Deps) != len(tcache.Target.Deps) {
		return true
	}
	var cache_deps map[string]bool = make(map[string]bool)
	for _, cdep := range tcache.Target.Deps {
		cache_deps[cdep] = true
	}
	for _, depname := range target.Deps {
		_, hasdep := cache_deps[depname]
		if !hasdep {
			return true
		}
	}

	// Check if the artifacts exist.
	for _, artifact := range tcache.Artifacts {
		if fa, is_fa := artifact.GetArtifact().Get().(*FileArtifact); is_fa && fa.Exists() {
			return true
		}
	}
	return false
}

func (t *TargetDefinition) CheckBuildSubstepRefresh(ctx *DoContext, substep_id BuildIdentifier, target *TargetConfig) bool {
	if substep_id == 0 {
		panic("invalid build substep identifier")
	}
	refresh_fn, has_refresh := t.compute_build_sub_step_refresh[substep_id]
	if !has_refresh {
		return true // needs refresh
	}
	return refresh_fn(ctx, target)
}
