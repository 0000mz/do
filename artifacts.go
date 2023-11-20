package main

import (
	"fmt"
	"os"
	"path/filepath"
)

type CacheableArtifactType int

const (
	CAT_Undefined     CacheableArtifactType = 0
	CAT_ExternalBuild CacheableArtifactType = 1
	CAT_Directory     CacheableArtifactType = 2
	CAT_GitInput      CacheableArtifactType = 3
	CAT_VagueFile     CacheableArtifactType = 4
	CAT_File          CacheableArtifactType = 5
)

type CacheableArtifact struct {
	ArtifactType CacheableArtifactType

	BuildConfig BuildConfigType
	Dir         string
	Url         string
	Hash        string
	Fname       string
}

func (ca *CacheableArtifact) GetArtifact() *Artifact {
	switch ca.ArtifactType {
	case CAT_Undefined:
		panic("Cannot convert undefined cacheable artifact to actual artifact")
	case CAT_ExternalBuild:
		return &Artifact{Impl: (&ExternalBuildArtifact{}).Populate(ca)}
	case CAT_Directory:
		return &Artifact{Impl: (&DirectoryArtifact{}).Populate(ca)}
	case CAT_GitInput:
		return &Artifact{Impl: (&GitInputArtifact{}).Populate(ca)}
	case CAT_VagueFile:
		return &Artifact{Impl: (&VagueFileArtifact{}).Populate(ca)}
	case CAT_File:
		return &Artifact{Impl: (&FileArtifact{}).Populate(ca)}
	}
	panic(fmt.Sprintf("No conversion from cacheable artifact to artifact for artifact type %d", ca.ArtifactType))
}

// External build config is used to identify an artifact as a project repo
// located in `Dir` and shouldb be built with the tools defined by `BuildConfig`,
// i.e. Make, CMake, Configure-Make.
type ExternalBuildArtifact struct { // ext
	Dir         string          `json:"ext_dir"`
	BuildConfig BuildConfigType `json:"ext_build_config"`
}

func (a *ExternalBuildArtifact) GetCacheableArtiact() *CacheableArtifact {
	return &CacheableArtifact{
		Dir:         a.Dir,
		BuildConfig: a.BuildConfig,

		ArtifactType: CAT_ExternalBuild,
	}
}

func (a *ExternalBuildArtifact) Populate(ca *CacheableArtifact) *ExternalBuildArtifact {
	a.Dir = ca.Dir
	a.BuildConfig = ca.BuildConfig
	return a
}

// Artifact for identifying a directory.
type DirectoryArtifact struct { // da
	Dir string `json:"da_dir"`
}

func (a *DirectoryArtifact) GetCacheableArtiact() *CacheableArtifact {
	return &CacheableArtifact{
		Dir:          a.Dir,
		ArtifactType: CAT_Directory,
	}
}

func (a *DirectoryArtifact) Populate(ca *CacheableArtifact) *DirectoryArtifact {
	a.Dir = ca.Dir
	return a
}

// Artifact for defining a git repository that needs to be imported.
type GitInputArtifact struct { // gia
	Url  string `json:"gia_url"`
	Hash string `json:"gia_hash"`
}

func (a *GitInputArtifact) GetCacheableArtiact() *CacheableArtifact {
	return &CacheableArtifact{
		Url:          a.Url,
		Hash:         a.Hash,
		ArtifactType: CAT_GitInput,
	}
}

func (a *GitInputArtifact) Populate(ca *CacheableArtifact) *GitInputArtifact {
	a.Url = ca.Url
	a.Hash = ca.Hash
	return a
}

// A vague file artifact is a file artifact that has a filename
// but unspecified location. Certain actions require the generation of a
// output file but the location of the generated file is undetermined.
// A vague file artifact can be promoted to a file artifact once its
// location is determined.
type VagueFileArtifact struct { // vfa
	Fname string `json:"vfa_fname"`
}

func (a *VagueFileArtifact) GetCacheableArtiact() *CacheableArtifact {
	return &CacheableArtifact{
		Fname:        a.Fname,
		ArtifactType: CAT_VagueFile,
	}
}

func (a *VagueFileArtifact) Populate(ca *CacheableArtifact) *VagueFileArtifact {
	a.Fname = ca.Fname
	return a
}

// Promtoe a vague file artifact to a file artifact when its location is found.
// Then replace the artifacts implementation to be a FileArtifact instead of a
// VagueFileArtifact.
func (vfa *VagueFileArtifact) PromoteAndReplace(dirname string, a *Artifact) {
	// panic(fmt.Sprintf("Promoting lib: dir = %s, libname = %s", dirname, vfa.Fname))
	var cvfa *VagueFileArtifact
	var ok bool
	if cvfa, ok = a.Impl.(*VagueFileArtifact); !ok {
		return
	}
	if cvfa != vfa {
		return
	}
	new_fa := create_file_artifact_parts(dirname, vfa.Fname)
	a.Impl = new_fa.Impl
}

type FileArtifact struct { // fa
	// The directory that the artifact is stored in.
	Dir string `json:"fa_dir"`
	// The filename of the artifact within the directory.
	Fname string `json:"fa_fname"`
}

func (a *FileArtifact) GetCacheableArtiact() *CacheableArtifact {
	return &CacheableArtifact{
		Fname:        a.Fname,
		Dir:          a.Dir,
		ArtifactType: CAT_File,
	}
}

func (a *FileArtifact) Populate(ca *CacheableArtifact) *FileArtifact {
	a.Fname = ca.Fname
	a.Dir = ca.Dir
	return a
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
	Impl interface{}
}

func (art *Artifact) Get() interface{} { return art.Impl }

func (art *Artifact) GetCacheableArtiact() *CacheableArtifact {
	var ca *CacheableArtifact = nil
	switch art.Impl.(type) {
	case *ExternalBuildArtifact:
		ca = art.Impl.(*ExternalBuildArtifact).GetCacheableArtiact()
	case *DirectoryArtifact:
		ca = art.Impl.(*DirectoryArtifact).GetCacheableArtiact()
	case *GitInputArtifact:
		ca = art.Impl.(*GitInputArtifact).GetCacheableArtiact()
	case *VagueFileArtifact:
		ca = art.Impl.(*VagueFileArtifact).GetCacheableArtiact()
	case *FileArtifact:
		ca = art.Impl.(*FileArtifact).GetCacheableArtiact()
	}
	if ca == nil {
		panic(fmt.Sprintf("Cannot get cacheable artifact for unknown type: %#v", art.Impl))
	}
	if ca.ArtifactType == CAT_Undefined {
		panic(fmt.Sprintf("Undefined artifact type: %#v", ca.ArtifactType))
	}
	return ca
}

func create_file_artifact(path string) *Artifact {
	return create_file_artifact_parts(filepath.Dir(path), filepath.Base(path))
}

func create_file_artifact_parts(dir, base string) *Artifact {
	file_artifact := &FileArtifact{
		Dir:   dir,
		Fname: base,
	}
	return &Artifact{
		Impl: file_artifact,
	}
}

func create_vague_file_artifact(fname string) *Artifact {
	vague_fa := &VagueFileArtifact{
		Fname: fname,
	}
	return &Artifact{
		Impl: vague_fa,
	}
}

func create_git_input_artifact(giturl, hash string) *Artifact {
	git_fa := &GitInputArtifact{
		Url:  giturl,
		Hash: hash,
	}
	return &Artifact{
		Impl: git_fa,
	}
}

func create_directory_artifact(dir string) *Artifact {
	dir_fa := &DirectoryArtifact{
		Dir: dir,
	}
	return &Artifact{
		Impl: dir_fa,
	}
}

func create_external_build_artifact(dir string, config BuildConfigType) *Artifact {
	ext_fa := &ExternalBuildArtifact{
		Dir:         dir,
		BuildConfig: config,
	}
	return &Artifact{
		Impl: ext_fa,
	}
}

func get_artifact_type(a *Artifact) string {
	switch a.Impl.(type) {
	case *FileArtifact:
		return "FileArtifact"
	case *VagueFileArtifact:
		return "VagueFileArtifact"
	case *DirectoryArtifact:
		return "DirectoryArtifact"
	case *ExternalBuildArtifact:
		return "ExternalBuildArtifact"
	case *GitInputArtifact:
		return "GitInputArtifact"
	}
	return "UnknownArtifact"
}
