package main

import (
	"os"
	"path/filepath"
)

// External build config is used to identify an artifact as a project repo
// located in `Dir` and shouldb be built with the tools defined by `BuildConfig`,
// i.e. Make, CMake, Configure-Make.
type ExternalBuildArtifact struct {
	Dir         string          `json:"dir"`
	BuildConfig BuildConfigType `json:"build_config"`
}

// Artifact for identifying a directory.
type DirectoryArtifact struct {
	Dir string `json:"dir"`
}

// Artifact for defining a git repository that needs to be imported.
type GitInputArtifact struct {
	Url  string `json:"url"`
	Hash string `json:"hash"`
}

// A vague file artifact is a file artifact that has a filename
// but unspecified location. Certain actions require the generation of a
// output file but the location of the generated file is undetermined.
// A vague file artifact can be promoted to a file artifact once its
// location is determined.
type VagueFileArtifact struct {
	Fname string `json:"fname"`
}

// Promtoe a vague file artifact to a file artifact when its location is found.
// Then replace the artifacts implementation to be a FileArtifact instead of a
// VagueFileArtifact.
func (vfa *VagueFileArtifact) PromoteAndReplace(dirname string, a *Artifact) {
	var cvfa *VagueFileArtifact
	var ok bool
	if cvfa, ok = a.impl.(*VagueFileArtifact); !ok {
		return
	}
	if cvfa != vfa {
		return
	}
	a.impl = create_file_artifact_parts(dirname, vfa.Fname)
}

type FileArtifact struct {
	// The directory that the artifact is stored in.
	Dir string `json:"dir"`
	// The filename of the artifact within the directory.
	Fname string `json:"fname"`
}

func (a *FileArtifact) Fullpath() string {
	return filepath.Join(a.Dir, a.Fname)
}

func (a *FileArtifact) Exists() bool {
	_, err := os.Stat(a.Fullpath())
	return err == nil
}

// An artifact is a product of a build step.
type Artifact struct {
	impl interface{}
}

func (art *Artifact) Get() interface{} { return art.impl }

func create_file_artifact(path string) *Artifact {
	return create_file_artifact_parts(filepath.Dir(path), filepath.Base(path))
}

func create_file_artifact_parts(dir, base string) *Artifact {
	file_artifact := &FileArtifact{
		Dir:   dir,
		Fname: base,
	}
	return &Artifact{
		impl: file_artifact,
	}
}

func create_vague_file_artifact(fname string) *Artifact {
	vague_fa := &VagueFileArtifact{
		Fname: fname,
	}
	return &Artifact{
		impl: vague_fa,
	}
}

func create_git_input_artifact(giturl, hash string) *Artifact {
	git_fa := &GitInputArtifact{
		Url:  giturl,
		Hash: hash,
	}
	return &Artifact{
		impl: git_fa,
	}
}

func create_directory_artifact(dir string) *Artifact {
	dir_fa := &DirectoryArtifact{
		Dir: dir,
	}
	return &Artifact{
		impl: dir_fa,
	}
}

func create_external_build_artifact(dir string, config BuildConfigType) *Artifact {
	ext_fa := &ExternalBuildArtifact{
		Dir:         dir,
		BuildConfig: config,
	}
	return &Artifact{
		impl: ext_fa,
	}
}
