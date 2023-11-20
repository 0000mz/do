// do - build, execute and test c modules and binaries

package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/fatih/color"
	"github.com/gosuri/uilive"
	"github.com/rs/zerolog"
)

var (
	logger  zerolog.Logger
	logfile *os.File
	dctx    *DoContext
)

// Compile commands compilation database is a JSON file which consists
// of an array of command objects. Each command object specifies one way a
// translation unit is compiled in the project.
// https://clang.llvm.org/docs/JSONCompilationDatabase.html
type CompileCommandsDatabase struct {
	Commands []*CompileCommandEntry `json:"commands"`
}

type CompileCommandEntry struct {
	Directory string   `json:"directory"`
	Arguments []string `json:"arguments"`
	File      []string `json:"file"`
}

type CommandBuilder struct {
	libdirs     map[string]bool
	includedirs map[string]bool
	srcfiles    map[string]bool
	libs        map[string]bool
	compiler    string
	outfile     string
}

func NewCommandBuilder() *CommandBuilder {
	return &CommandBuilder{
		libdirs:     make(map[string]bool),
		includedirs: make(map[string]bool),
		srcfiles:    make(map[string]bool),
		libs:        make(map[string]bool),
	}
}

func (cmd *CommandBuilder) AddLibDir(libdirs ...string) *CommandBuilder {
	for _, libdir := range libdirs {
		if len(libdir) == 0 {
			continue
		}
		cmd.libdirs[libdir] = true
	}
	return cmd
}

func (cmd *CommandBuilder) AddIncludeDirs(includedirs ...string) *CommandBuilder {
	for _, includedir := range includedirs {
		if len(includedir) == 0 {
			continue
		}
		cmd.includedirs[includedir] = true
	}
	return cmd
}

func (cmd *CommandBuilder) AddSrcFiles(srcfiles ...string) *CommandBuilder {
	for _, srcfile := range srcfiles {
		if len(srcfile) == 0 {
			continue
		}
		cmd.srcfiles[srcfile] = true
	}
	return cmd
}

func (cmd *CommandBuilder) AddLibs(libnames ...string) *CommandBuilder {
	for _, libname := range libnames {
		if len(libname) == 0 {
			continue
		}
		cmd.libs[libname] = true
	}
	return cmd
}

func (cmd *CommandBuilder) AddCompiler(compiler string) *CommandBuilder {
	cmd.compiler = compiler
	return cmd
}

func (cmd *CommandBuilder) AddOutput(output string) *CommandBuilder {
	cmd.outfile = output
	return cmd
}

type BuildMode int

const (
	// Set the compiler to produce an executable binary.
	BuildModeExe BuildMode = 1
	// Set the compiler to produce object files.
	BuildModeCompile BuildMode = 2
)

func (cmd *CommandBuilder) Build(mode BuildMode, compiledb *CompileCommandsDatabase) []string {
	cmdlst := []string{cmd.compiler}

	var comp_entry CompileCommandEntry = CompileCommandEntry{}
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	comp_entry.Directory = cwd

	switch mode {
	case BuildModeExe:
		cmdlst = append(cmdlst, "-o")
	case BuildModeCompile:
		cmdlst = append(cmdlst, "-c", "-o")
	}

	cmdlst = append(cmdlst, cmd.outfile)
	for inputfile := range cmd.srcfiles {
		cmdlst = append(cmdlst, inputfile)
		comp_entry.File = append(comp_entry.File, inputfile)
	}
	for includedir := range cmd.includedirs {
		cmdlst = append(cmdlst, "-I", includedir)
	}
	for libdir := range cmd.libdirs {
		cmdlst = append(cmdlst, "-L", libdir)
	}
	for lib := range cmd.libs {
		cmdlst = append(cmdlst, fmt.Sprintf("-l:%s", lib))
	}

	// Update the compile database with this command.
	comp_entry.Arguments = cmdlst
	compiledb.Commands = append(compiledb.Commands, &comp_entry)
	return cmdlst
}

type ActionState struct {
	action_type string
	action_name string
	active      bool
}

type ActionStateWriter struct {
	// The number of state io to maange at a time.
	state_io_ct int
	writer      *uilive.Writer

	// Keep tracks of the builds in progress.
	actions map[string]*ActionState
	io_mu   *sync.Mutex

	last_write_time time.Time
	enabled         bool
}

func NewActionStateWriter(state_ct int, enabled bool) *ActionStateWriter {
	return &ActionStateWriter{
		state_io_ct: state_ct,
		actions:     make(map[string]*ActionState),
		io_mu:       &sync.Mutex{},
		enabled:     enabled,
	}
}

func (io *ActionStateWriter) Start() {
	if !io.enabled {
		return
	}
	io.writer = uilive.New()
	io.writer.Start()
	io.update_action_state_io()
}

func (io *ActionStateWriter) Stop(update_state bool) {
	if io.writer == nil {
		return
	}
	if update_state {
		io.update_action_state_io()
	}
	io.writer.Stop()
}

func (io *ActionStateWriter) AddAction(action_id, action_type, action_name string) {
	if io.writer == nil {
		return
	}
	io.io_mu.Lock()
	io.actions[action_id] = &ActionState{
		action_type: action_type,
		action_name: action_name,
		active:      true,
	}
	io.io_mu.Unlock()
	io.update_action_state_io()
}

func (io *ActionStateWriter) SetActionFinished(action_id string) {
	if io.writer == nil {
		return
	}
	io.io_mu.Lock()
	action_state, has_action := io.actions[action_id]
	io.io_mu.Unlock()
	if has_action {
		action_state.active = false
		io.update_action_state_io()
	}
}

func (io *ActionStateWriter) active_build_ct() int {
	ct := 0
	for _, act := range io.actions {
		if act.active {
			ct++
		}
	}
	return ct
}

func (io *ActionStateWriter) total_builds() int {
	return len(io.actions)
}

func (io *ActionStateWriter) update_action_state_io() {
	if io.writer == nil {
		panic("io writer not started.")
	}
	io.io_mu.Lock()
	defer io.io_mu.Unlock()

	io_sleep_dur := time.Millisecond * 5
	io_diff := time.Since(io.last_write_time)

	sleep_dur_us := io_sleep_dur.Microseconds() - io_diff.Microseconds()
	if sleep_dur_us > 0 {
		var sleep_dur time.Duration = time.Microsecond * time.Duration(sleep_dur_us)
		time.Sleep(sleep_dur)
	}

	cyan := color.New(color.FgCyan).SprintFunc()
	grn := color.New(color.FgHiGreen).SprintFunc()

	active_ct := io.active_build_ct()
	total_ct := io.total_builds()

	counter_clr := cyan(fmt.Sprintf("[%d/%d]", (total_ct - active_ct), total_ct))
	msg := fmt.Sprintf("%s Actions completed\n", counter_clr)
	// Add the active builds to the message
	for _, act := range io.actions {
		if act.active {
			msg += grn(fmt.Sprintf("\t%s: %s\n", act.action_type, act.action_name))
		}
	}

	fmt.Fprint(io.writer, msg)
	io.last_write_time = time.Now()
}

func filter[T any](t []T, f func(T) bool) []T {
	var u []T = make([]T, 0)
	for _, el := range t {
		if f(el) {
			u = append(u, el)
		}
	}
	return u
}

func apply[U any, V any](iterable []U, fx func(U) V) []V {
	var v []V = make([]V, 0)
	for _, u := range iterable {
		v = append(v, fx(u))
	}
	return v
}

func is_file(filename string) bool {
	stat, err := os.Stat(filename)
	if err != nil {
		return false
	}
	return !stat.IsDir()
}

func compute_md5(filename string) ([]byte, error) {
	filedat, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	md5sum := md5.Sum(filedat)

	return md5sum[:], nil
}

// Return the first non-nil error amongst a collection of errors.
// If all errors are nil, return nil.
func errset(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func bytearr_equal(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func get_git_pull_path(dctx *DoContext, giturl, hash string) string {
	projname := filepath.Base(giturl)
	return filepath.Join(dctx.builddir_path, "external", fmt.Sprintf("%s-%s", projname, hash))
}

func create_git_pull_buildstep(t *TargetConfig) (*BuildSubStep, error) {

	if len(t.Git) == 0 || len(t.Hash) == 0 {
		return nil, fmt.Errorf("no git remote or hash specified for git pull buildstep")
	}

	export_dir := get_git_pull_path(dctx, t.Git, t.Hash)
	bss := &BuildSubStep{
		inputs:      []*Artifact{create_git_input_artifact(t.Git, t.Hash)},
		outputs:     []*Artifact{create_directory_artifact(export_dir)},
		action_fn:   pull_git_action,
		name:        t.Git,
		identifier:  BuildId_GitPull,
		action_type: "downloading",
	}
	return bss, nil
}

type TargetConfig struct {
	Name string `json:"name"`

	// List of source files and header files for this target to build.
	// These files will be checked against to compare diffs between previous
	// builds to determine whether to issue a rebuild of the target.
	Srcs []string `json:"srcs"`
	Hdrs []string `json:"hdrs"`

	// External dependency target configuraton
	Git    string `json:"git"`
	Hash   string `json:"hash"`
	Config string `json:"config"`

	// List of targets that the target depends on.
	// These targets need to be built before the current target can be
	// built.
	Deps []string `json:"deps"`
	// The target type that should be build.
	// For library, this can be "static" or "dynamic".
	// For binary, set to "binary".
	// For external, set to "external".
	Type string `json:"-"`

	// For external dependencies, this will list the artifacts produced.
	// During the build step of external dependencies, these files must be extracted
	// if the build succeeds and used as input to the next step of the build.
	OutStatic  []string `json:"out_static"`
	OutDynamic []string `json:"out_dynamic"`
	// Relative path to all of the include directories from a project. These will
	// be added to the compile commands of the target linking against this remote
	// dependency.
	IncludeDirs []string `json:"include_dirs"`
	LibDirs     []string `json:"lib_dirs"`

	// For local targets, specify the path to the local project.
	Location string `json:"location"`

	id string
}

// Validate that all of the information in the target is valid.
// For file information, check that the file exists.
func (t *TargetConfig) Validate() error {
	files := append(t.Srcs, t.Hdrs...)

	for _, fname := range files {
		if !is_file(fname) {
			return fmt.Errorf("not a file: %s", fname)
		}
	}
	return nil
}

// Constuct a build tree for th is target.
// The build tree should properly construct the build step for each
// unit that needs to be built in order for this specific target to
// successfully build.
func (t *TargetConfig) ConstructBuildTree(dctx *DoContext, tp *TargetParser) (*BuildStep, error) {

	// Construct the build subtree for the dependants
	var deps_buildsteps []*BuildStep = make([]*BuildStep, 0)
	for _, depname := range t.Deps {
		depcfg, err := tp.FindTarget(depname)
		if err != nil {
			return nil, err
		}
		dep_buildstep, err := depcfg.ConstructBuildTree(dctx, tp)
		if err != nil {
			return nil, err
		}
		deps_buildsteps = append(deps_buildsteps, dep_buildstep)
	}

	var err error
	var bs *BuildStep
	switch t.Type {
	case "static":
		bs, err = t.static_build_step(dctx)
	case "dynamic":
		return nil, fmt.Errorf("dynamic build unimplemented")
	case "binary":
		bs, err = t.binary_build_step(dctx)
	case "external":
		bs, err = t.external_build_step(dctx)
	case "local":
		bs, err = t.local_build_step(dctx)
	default:
		return nil, fmt.Errorf("unknown target type: %s", t.Type)
	}

	if err != nil {
		return nil, err
	}
	if bs == nil {
		panic("Build step not set during construction of build tree.")
	}

	// Set initial refresh state for build steps and build sub steps.
	bs.needs_refresh = true
	var substep *BuildSubStep = bs.steps
	for substep != nil {
		substep.needs_refresh = true
		substep = substep.next
	}

	// Check if any of the files this target depends on have changed.
	target_def, has_target_definition := target_definitions[t.Type]
	if has_target_definition {
		bs.needs_refresh = target_def.compute_build_step_refresh(t, dctx.init_build_cache)
	}
	logger.Debug().Msgf("Build Step %s: needs refresh = %v", t.Name, bs.needs_refresh)

	// If the build step is not cached, check if build sub-steps are cached.
	if bs.needs_refresh {
		var substep *BuildSubStep = bs.steps
		for substep != nil {
			substep.needs_refresh = target_def.CheckBuildSubstepRefresh(dctx, substep.identifier, t)
			logger.Debug().Msgf("Build Step %s, sub step %v: needs refresh = %v", t.Name, substep.identifier, substep.needs_refresh)
			substep = substep.next
		}
	}

	bs.target_config = t
	bs.dependants = deps_buildsteps
	// Set the parent for for each of the deps to the bs
	for _, dep := range bs.dependants {
		// If the dependant needs to be refreshed, then so does the parent,
		// regardless of what its previous value was.
		if dep.needs_refresh {
			bs.needs_refresh = true
		}

		dep.parent = bs
		dep.promotion_fn = func(curr_bs *BuildStep) bool {
			dctx.build_tree_state_mu.Lock()
			defer dctx.build_tree_state_mu.Unlock()

			if curr_bs.parent == nil {
				return false
			}

			return len(filter(
				apply(
					curr_bs.parent.dependants,
					func(bs *BuildStep) bool { return bs.build_complete },
				),
				func(complete bool) bool { return !complete })) == 0
		}
	}

	dctx.action_state_writer.AddAction(t.id, "build", t.Name)
	return bs, nil
}

func (t *TargetConfig) ComputeFileHashes() (map[string][]byte, error) {

	var hashes map[string][]byte = make(map[string][]byte)
	var files []string = append(t.Srcs, t.Hdrs...)

	for _, filename := range files {
		md5sum, err := compute_md5(filename)
		if err != nil {
			return nil, err
		}
		hashes[filename] = md5sum
	}
	return hashes, nil
}

func NewBuildStep() *BuildStep {
	return &BuildStep{
		promotion_fn:   func(_ *BuildStep) bool { return false },
		build_complete: false,
		needs_refresh:  false,
	}
}

func (t *TargetConfig) binary_build_step(dctx *DoContext) (*BuildStep, error) {
	binfils_bs := &BuildSubStep{
		inputs:      apply(t.Srcs, create_file_artifact),
		outputs:     []*Artifact{create_file_artifact_parts(dctx.builddir_path, t.Name)},
		action_fn:   build_binary_action,
		name:        t.Name,
		identifier:  BuildId_CompileBin,
		action_type: "compiling",
	}

	bs := NewBuildStep()
	bs.steps = binfils_bs

	return bs, nil
}

func (t *TargetConfig) static_build_step(dctx *DoContext) (*BuildStep, error) {
	// Static build takes 2 steps:
	// Step 1: build the object files with the compiler.
	// Step 2: Use ar to product the library from the produced object fles.

	var objfile string = fmt.Sprintf("%s.o", t.Name)
	objfile_bss := &BuildSubStep{
		inputs:      apply(t.Srcs, create_file_artifact),
		outputs:     []*Artifact{create_file_artifact_parts(dctx.builddir_path, objfile)},
		action_fn:   build_object_action,
		name:        objfile,
		identifier:  BuildId_CompileObj,
		action_type: "compiling",
	}

	var libname string = fmt.Sprintf("%s.a", t.Name)
	libfile_bss := &BuildSubStep{
		inputs:      objfile_bss.outputs,
		outputs:     []*Artifact{create_file_artifact_parts(dctx.builddir_path, libname)},
		action_fn:   produce_static_lib_action,
		name:        libname,
		identifier:  BuildId_CreateStaticLib,
		action_type: "linking",
	}
	objfile_bss.next = libfile_bss

	bs := NewBuildStep()
	bs.steps = objfile_bss

	return bs, nil
}

func get_target_outlib_arifacts(t *TargetConfig) []*Artifact {
	return apply(
		append(t.OutStatic, t.OutDynamic...),
		create_vague_file_artifact,
	)
}

func (t *TargetConfig) external_build_step(dctx *DoContext) (*BuildStep, error) {
	// External build steps:
	// 1. Pull the remote source.
	// 2. Build the pulled source.

	git_pull_bss, err := create_git_pull_buildstep(t)
	if err != nil {
		return nil, err
	}

	if len(t.Config) == 0 {
		return nil, fmt.Errorf("no config provided for external build")
	}

	build_config, err := get_external_build_config_type(t.Config)
	if err != nil {
		return nil, err
	}
	external_build_action_fn, has_build_config := external_build_steps[build_config]
	if !has_build_config {
		return nil, fmt.Errorf("build config not found for \"%s\"", t.Config)
	}

	if len(git_pull_bss.outputs) != 1 {
		panic("git pull build step should only have 1 output")
	}

	dirart, is_dirart := git_pull_bss.outputs[0].Get().(*DirectoryArtifact)
	if !is_dirart {
		panic("expected external build artifact as first output")
	}

	var project_pulldir string = dirart.Dir
	external_build_bss := &BuildSubStep{
		inputs:  []*Artifact{create_external_build_artifact(project_pulldir, build_config)},
		outputs: get_target_outlib_arifacts(t),
		action_fn: func(bs *BuildStep, bss *BuildSubStep, dc *DoContext) (*bytes.Buffer, error) {
			return external_build_action_fn(project_pulldir, bs, bss, dc)
		},
		action_type: "building",
		name:        fmt.Sprintf("running %s on %s", t.Config, t.Name),
		identifier:  BuildId_ExternalBuild,
	}
	git_pull_bss.next = external_build_bss

	bs := NewBuildStep()
	bs.steps = git_pull_bss
	return bs, nil
}

func (t *TargetConfig) local_build_step(dctx *DoContext) (*BuildStep, error) {

	local_repo_bss := &BuildSubStep{
		inputs:      []*Artifact{},
		outputs:     get_target_outlib_arifacts(t),
		action_type: "importing",
		name:        fmt.Sprintf("local library %s", t.Name),
		identifier:  BuildId_LocalBuild,
		action_fn: func(bs *BuildStep, bss *BuildSubStep, dc *DoContext) (*bytes.Buffer, error) {
			var proj_location string = t.Location
			if stat, err := os.Stat(proj_location); err != nil || !stat.IsDir() {
				return nil, fmt.Errorf("invalid directory: %s", proj_location)
			}

			// Set the output libs
			var libout map[string]string = make(map[string]string)
			for _, libname := range append(t.OutDynamic, t.OutStatic...) {
				libout[libname] = ""
			}

			for _, libdir := range t.LibDirs {
				full_libdir := filepath.Join(proj_location, libdir)
				for libfile := range libout {
					full_libpath := filepath.Join(full_libdir, libfile)

					logger.Debug().Msgf("DBG libpath: %s", full_libpath)
					stat, err := os.Stat(full_libpath)
					if err == nil && !stat.IsDir() {
						libout[libfile] = full_libpath
					}
				}
			}

			for libname, libpath := range libout {
				// Check if any libs could not be found.
				if len(libpath) == 0 {
					return nil, fmt.Errorf("failed to find lib: %s", libname)
				}

				// Add an output artifact for this build sub step
				bss.outputs = append(bss.outputs, create_file_artifact_parts(filepath.Dir(libpath), libname))
			}

			set_include_dirs(proj_location, bs, bss)
			return nil, nil
		},
	}

	bs := NewBuildStep()
	bs.steps = local_repo_bss

	return bs, nil
}

type TargetParser struct {
	targets map[string]TargetConfig
}

func NewTargetParser(config_file string) (*TargetParser, error) {
	stat, err := os.Stat(config_file)
	if err != nil {
		return nil, err
	}
	if stat.IsDir() {
		return nil, fmt.Errorf("config file is a directory: %s", config_file)
	}

	filedata, err := os.ReadFile(config_file)
	if err != nil {
		return nil, err
	}

	type BuildConfig struct {
		Targets map[string]TargetConfig
	}
	var targetcfg BuildConfig
	_, err = toml.Decode(string(filedata), &targetcfg)
	if err != nil {
		return nil, err
	}

	tparser := TargetParser{
		targets: make(map[string]TargetConfig),
	}
	for tname, tinfo := range targetcfg.Targets {
		tinfo.Name = tname
		tparser.targets[tname] = tinfo
	}
	return &tparser, nil
}

// Find the target with the given `target_name`.
// Return the target info associated with the target name, or an error if the target
// cannot be found.
func (t *TargetParser) FindTarget(target_name string) (*TargetConfig, error) {
	for tname, tcfg := range t.targets {
		if tname == target_name {
			if len(tcfg.id) == 0 {
				tcfg.id = make_unique_id()
			}
			return &tcfg, nil
		}
	}
	return nil, fmt.Errorf("no target found with name: %s", target_name)
}

type SubStepAction int64

type BuildSubStep struct {
	inputs  []*Artifact
	outputs []*Artifact

	// Name and action type to describe the build sub step.
	// This is used for logging the actions taking place.
	name        string
	action_type string
	// This identifier must be unique within a build step's set of build sub-steps.
	identifier BuildIdentifier

	action_fn func(*BuildStep, *BuildSubStep, *DoContext) (*bytes.Buffer, error)
	next      *BuildSubStep
	// Similar to BuildStep.needs_refresh, but for the sub step.
	needs_refresh bool
}

func (bss *BuildSubStep) Build(bs *BuildStep, dctx *DoContext) (*bytes.Buffer, error) {
	var err error = nil
	var action_id string = make_unique_id()
	dctx.action_state_writer.AddAction(action_id, bss.action_type, bss.name)
	defer func() {
		if err == nil {
			dctx.action_state_writer.SetActionFinished(action_id)
		}
	}()

	if bss.needs_refresh {
		stderr, err := bss.action_fn(bs, bss, dctx)
		if err != nil {
			return stderr, err
		}
		// Update the cache with the output artifacts from this build sub-step
		dctx.build_tree_state_mu.Lock()
		err = dctx.end_build_cache.UpdateBuildSubStepCacheArtifacts(bs.target_config, bss)
		dctx.build_tree_state_mu.Unlock()
		return nil, err
	} else {
		// Get the output artifacts from the build sub-step cache.
		logger.Info().Msgf("%s-%v: using build sub-step cache", bs.target_config.Name, bss.identifier)
		err = func() error {
			dctx.build_tree_state_mu.Lock()
			defer dctx.build_tree_state_mu.Unlock()
			cached_artifacts, err := dctx.init_build_cache.GetCachedBuildSubstepArtifacts(bs.target_config, bss.identifier)
			if err != nil {
				bss.outputs = append(bss.outputs, cached_artifacts...)
				err = dctx.end_build_cache.UpdateBuildSubStepCacheArtifacts(bs.target_config, bss)
			}
			return err
		}()
		return nil, err
	}
}

// Build step define how to build a specific transition unit
// and has information on the artifacts produced from the build step.
// It also contains the children that need to be built before this step
// can properly be built.
type BuildStep struct {

	// The list of artifacts produced by the build step.
	// This is populated after the build step is executed.
	output_artifacts []*Artifact
	steps            *BuildSubStep
	dependants       []*BuildStep
	parent           *BuildStep
	// The promotion function will determine whether or not a build step can
	// spawn the parent build step after it is complete. This is to facilitate
	// the auto delegation of build actions starting from the leaf of the build
	// tree up to the root of the build tree.
	promotion_fn   func(*BuildStep) bool
	build_complete bool
	target_config  *TargetConfig
	// Determine if a build step needs to be rebuilt if any of the files it depends
	// on has changed or any of the files its dependencies depend on have changed.
	needs_refresh bool
}

func (bs *BuildStep) Build(dctx *DoContext, errch chan error, stderrch chan *bytes.Buffer, completech chan bool) {
	logger.Info().Msgf("Running build step: %s", bs.target_config.Name)
	func() {
		dctx.build_tree_state_mu.Lock()
		defer dctx.build_tree_state_mu.Unlock()
		if dctx.build_cancelled {
			return
		}
	}()

	// Check if this build step needs to be refreshed. If not, mark the build as
	// complete.
	if bs.needs_refresh {
		logger.Info().Msgf("%s: refreshing build", bs.target_config.Name)
		var bss *BuildSubStep = bs.steps

		for i, artifact := range bss.inputs {
			logger.Debug().Msgf("input artifact [%d] for build: %s-%v: %#v", i, bs.target_config.Name, bss.identifier, artifact.Impl)
		}

		for bss != nil {
			stderr, err := bss.Build(bs, dctx)
			if err != nil {
				errch <- err
				stderrch <- stderr
				return
			}
			if bss.next == nil {
				bs.output_artifacts = bss.outputs
			}
			bss = bss.next
		}
	} else {
		// Get the output artifacts from the build cache.
		logger.Info().Msgf("%s: using build step cache", bs.target_config.Name)
		func() {
			dctx.build_tree_state_mu.Lock()
			defer dctx.build_tree_state_mu.Unlock()

			cached, is_cached := dctx.init_build_cache.CachedBuildStep[bs.target_config.Name]
			if !is_cached {
				panic("BuildStep marked as cached but no cache entry found.")
			}
			bs.output_artifacts = apply(cached.Artifacts, func(ca *CacheableArtifact) *Artifact { return ca.GetArtifact() })
			for i, artifact := range bs.output_artifacts {
				logger.Debug().Msgf("cached build step -> %s: Output artifact[%d](type = %s): %#v", bs.target_config.Name, i, get_artifact_type(artifact), artifact.Impl)
			}
		}()
	}

	// Build complete. Update the cache.
	hashes, err := bs.target_config.ComputeFileHashes()
	if err != nil {
		errch <- err
		stderrch <- nil
		return
	}

	func() {
		dctx.build_tree_state_mu.Lock()
		defer dctx.build_tree_state_mu.Unlock()

		if dctx.build_cancelled {
			return
		}
		bs.build_complete = true

		target_cache := dctx.end_build_cache.GetBuildCacheForTarget(bs.target_config)
		target_cache.FileHashes = hashes
		target_cache.Artifacts = apply(bs.output_artifacts, func(a *Artifact) *CacheableArtifact { return a.GetCacheableArtiact() })
	}()

	dctx.action_state_writer.SetActionFinished(bs.target_config.id)

	// Check if this build can be promoted to the next level of the tree.
	if bs.promotion_fn(bs) {
		logger.Debug().Msgf("Promoting build to next level -> %s", bs.parent.target_config.Name)
		go bs.parent.Build(dctx, errch, stderrch, completech)
	}

	// Check if this is the last step of the build tree.
	// If so, mark the full build as complete.
	if bs.parent == nil {
		completech <- true
	}
}

// Execute the build tree recursively, starting from the leafs of the tree
// up to the root of the tree.
func run_build_tree(root *BuildStep, dctx *DoContext) error {
	var leafs []*BuildStep = make([]*BuildStep, 0)

	// Traverse the tree to find the leafs of the build tree.
	var q []*BuildStep
	q = append(q, root)

	for len(q) > 0 {
		next := q[0]
		q = q[1:]

		if len(next.dependants) == 0 {
			leafs = append(leafs, next)
		} else {
			q = append(q, next.dependants...)
		}
	}

	var errch chan error = make(chan error)
	var stderrch chan *bytes.Buffer = make(chan *bytes.Buffer)
	var completech chan bool = make(chan bool)
	for _, leaf := range leafs {
		go leaf.Build(dctx, errch, stderrch, completech)
	}

	// Wait for all the builds to complete or an error to occur.
	select {
	case build_error := <-errch:
		{
			dctx.build_tree_state_mu.Lock()
			dctx.build_cancelled = true
			dctx.build_tree_state_mu.Unlock()
		}

		// There must be a stderr byte buffer in the `stderrch`, otherwise panic.
		select {
		case stderrbuf := <-stderrch:
			if stderrbuf != nil {
				fmt.Printf("Error during build:\n%s\n", stderrbuf)
			}
		default:
			panic("No stderr buffer received")
		}

		return build_error
	case build_complete := <-completech:
		if !build_complete {
			panic("Unexpected build_complete value.")
		}
	}
	return nil
}

// Build the requested target.
func build(dctx *DoContext, args []string) error {
	var target_name string

	if len(args) == 0 {
		return fmt.Errorf("no target name provided")
	}
	target_name = args[0]

	var config_file string = "build.toml"
	tp, err := NewTargetParser(config_file)
	if err != nil {
		return err
	}
	tinfo, err := tp.FindTarget(target_name)
	if err != nil {
		return err
	}

	err = tinfo.Validate()
	if err != nil {
		return err
	}

	var build_succeeded bool = false
	dctx.action_state_writer.Start()
	// On stop, update the io writer if the build succeeded. That way
	// the io build state does not interfere with the failed build io.
	defer dctx.action_state_writer.Stop(build_succeeded)

	btree, err := tinfo.ConstructBuildTree(dctx, tp)
	if err != nil {
		return err
	}

	err = run_build_tree(btree, dctx)
	// nolint:staticcheck
	build_succeeded = err != nil
	if err != nil {
		return err
	}

	// Serialize the compile database to an output file.
	compile_db_file := filepath.Join(dctx.builddir_path, "compile_commands.json")
	err = write_json_to_file(compile_db_file, dctx.compile_database)
	if err != nil {
		return err
	}

	// Save the new cache.
	return dctx.RefreshCache()
}

func clean(dctx *DoContext) error {
	return errset(os.RemoveAll(dctx.builddir_path), os.RemoveAll(dctx.cachedir_path))
}

// Check if the program's argument list contains the specified argname prefixed
// with two dashes: i.e. --argname
func has_bool_arg(argname string) bool {
	for _, arg := range os.Args[1:] {
		if arg == fmt.Sprintf("--%s", argname) {
			return true
		}
	}
	return false
}

// Get the value of a kv arg in the form "--key=value". Return the value if the
// kv arg exists. Otherwise, return an error.
func get_arg_value(argkey string) (string, error) {
	for _, arg := range os.Args[1:] {
		parts := strings.Split(arg, "=")
		if len(parts) < 2 || parts[0] != fmt.Sprintf("--%s", argkey) {
			continue
		}
		return strings.Join(parts[1:], "="), nil
	}
	return "", fmt.Errorf("no kv arg for key: %s", argkey)
}

type Toolchain struct {
	build_binary_cmd_fn     func(*DoContext, *BuildStep, *BuildSubStep) []string
	compile_object_cmd_fn   func(*DoContext, *BuildStep, *BuildSubStep) []string
	build_static_lib_cmd_fn func(*DoContext, *BuildStep, *BuildSubStep) []string
}

func NewGccToolchain() *Toolchain {

	apply_common_args := func(bs *BuildStep, cmdb *CommandBuilder) *CommandBuilder {
		// Collect the artifacts from the dependants and append it to the command.
		// This assumes that every dependant build step produces a static library.
		var target_name string = bs.target_config.Name
		var artifacts []*Artifact = make([]*Artifact, 0)
		for i, dep_bs := range bs.dependants {
			for j, dep_art := range dep_bs.output_artifacts {
				logger.Debug().Msgf("for target %s: dep[%d] output artifact[%d] = %#v", target_name, i, j, dep_art.Impl)
			}
			artifacts = append(artifacts, dep_bs.output_artifacts...)
		}

		for _, artifact := range artifacts {
			var action_committed bool = false
			if fa, is_fa := artifact.Get().(*FileArtifact); is_fa && len(fa.Fname) > 0 {
				logger.Debug().Msgf("for target %s: setting file artifact as lib: %#v", target_name, *fa)
				cmdb = cmdb.AddLibDir(fa.Dir).AddLibs(fa.Fname)
				action_committed = true
			}
			if da, is_da := artifact.Get().(*DirectoryArtifact); is_da && len(da.Dir) > 0 {
				logger.Debug().Msgf("for target %s: setting directory artifact as include dir: %#v", target_name, *da)
				cmdb = cmdb.AddIncludeDirs(da.Dir)
				action_committed = true
			}

			if !action_committed {
				logger.Error().Msgf("for target %s: No action committed for artifact: %v", target_name, artifact.Impl)
			}
		}
		return cmdb
	}

	return &Toolchain{
		build_binary_cmd_fn: func(dctx *DoContext, bs *BuildStep, bss *BuildSubStep) []string {
			outbin := bss.outputs[0]
			// TODO: Appending exe to the produced binary so that windows will know how to handle the file.
			// This is not portable and is only windows specific. Abstract this away so that the filename
			// decision is more intuitive based on the operating system and the type of object being built.
			exepath := fmt.Sprintf("%s.exe", outbin.Get().(*FileArtifact).Fullpath())

			cmdb := NewCommandBuilder().
				AddCompiler("gcc").
				AddOutput(exepath).
				AddSrcFiles(apply(bss.inputs, func(a *Artifact) string {
					fa, is_fa := a.Get().(*FileArtifact)
					if !is_fa {
						return ""
					}
					return fa.Fullpath()
				})...)

			cmdb = apply_common_args(bs, cmdb)
			return cmdb.Build(BuildModeExe, dctx.compile_database)
		},
		compile_object_cmd_fn: func(dctx *DoContext, bs *BuildStep, bss *BuildSubStep) []string {

			outobj, is_fa := bss.outputs[0].Get().(*FileArtifact)
			if !is_fa {
				panic("expected output of object compile to be a file artifact")
			}

			cmdb := NewCommandBuilder().
				AddCompiler("gcc").
				AddOutput(outobj.Fullpath()).
				AddSrcFiles(apply(bss.inputs, func(a *Artifact) string {
					fa, is_fa := a.Get().(*FileArtifact)
					if !is_fa {
						return ""
					}
					return fa.Fullpath()
				})...)

			cmdb = apply_common_args(bs, cmdb)
			return cmdb.Build(BuildModeCompile, dctx.compile_database)
		},
		build_static_lib_cmd_fn: func(dctx *DoContext, bs *BuildStep, bss *BuildSubStep) []string {
			outlib, outlib_is_fa := bss.outputs[0].Get().(*FileArtifact)
			if !outlib_is_fa {
				panic("expected outlib to be a file artifact")
			}
			cmd := []string{"ar", "rcs", outlib.Fullpath()}
			cmd = append(cmd,
				filter(
					apply(bss.inputs, func(a *Artifact) string {
						fa, is_fa := a.Get().(*FileArtifact)
						if !is_fa {
							return ""
						}
						return fa.Fullpath()
					}), func(file string) bool {
						// filter out empty filepaths
						return len(file) > 0
					})...)
			return cmd
		},
	}
}

type BuildSubStepCache struct {
	// Artifacts produced during a build sub-step.
	Artifacts []*CacheableArtifact `json:"artifacts"`
}

func NewBuildSubStepCache() *BuildSubStepCache {
	return &BuildSubStepCache{
		Artifacts: []*CacheableArtifact{},
	}
}

type BuildStepCache struct {
	Target *TargetConfig `json:"target"`
	// For each file defined in the target config store the md5 hash for the file
	// when it was last built. This should be used to compare against to determine
	// whether or not a target needs to be rebuilt.
	FileHashes map[string][]byte `json:"file-hashes"`
	// Cthe location of artifacts produced by the target.
	Artifacts []*CacheableArtifact `json:"build_step_artifacts"`
	// Either full steps can be cached or sub steps can be cached.
	SubSteps map[BuildIdentifier]*BuildSubStepCache `json:"sub_steps"`
}

func NewBuildStepCache(t *TargetConfig) *BuildStepCache {
	return &BuildStepCache{
		Target:   t,
		SubSteps: map[BuildIdentifier]*BuildSubStepCache{},
	}
}

func (bsc *BuildCache) UpdateBuildSubStepCacheArtifacts(t *TargetConfig, bss *BuildSubStep) error {
	target_cache := bsc.GetBuildCacheForTarget(t)
	target_cache.SubSteps[bss.identifier] = NewBuildSubStepCache()

	bssc := target_cache.SubSteps[bss.identifier]
	bssc.Artifacts = apply(bss.outputs, func(a *Artifact) *CacheableArtifact { return a.GetCacheableArtiact() })

	return nil
}

// The build cache stores information about the targets that were built and
// the state of the files that each built target depends on. This is used to determine
// in future builds whether or not a target should be rebuilt and where to find the
// cached artifacts.
type BuildCache struct {
	CachedBuildStep map[string]*BuildStepCache `json:"cached-targets"`
}

// Return the build cache for the given target.
// If a build cache entry does not exist for the target with the given `target_name`,
// a new build cache entry will be created and returned.
func (bc *BuildCache) GetBuildCacheForTarget(t *TargetConfig) *BuildStepCache {
	var target_name string = t.Name
	cbs, has_cbs := bc.CachedBuildStep[target_name]
	if has_cbs {
		return cbs
	}
	bc.CachedBuildStep[target_name] = NewBuildStepCache(t)
	return bc.CachedBuildStep[target_name]
}

func (bc *BuildCache) GetCachedBuildSubstepArtifacts(t *TargetConfig, bss_id BuildIdentifier) ([]*Artifact, error) {
	cbs, has_cbs := bc.CachedBuildStep[t.Name]
	if !has_cbs {
		return nil, fmt.Errorf("cannot get cached build substep for un-cached target: %s", t.Name)
	}
	bssc, has_bssc := cbs.SubSteps[bss_id]
	if !has_bssc {
		return nil, fmt.Errorf("target %s has build cache but no build sub-step cache for build id %v", t.Name, bss_id)
	}
	return apply(bssc.Artifacts, func(ca *CacheableArtifact) *Artifact { return ca.GetArtifact() }), nil
}

func ensure_dir(dirname string) {
	err := os.Mkdir(dirname, os.ModeDir)
	if err != nil && !errors.Is(err, os.ErrExist) {
		panic(err)
	}
	logger.Debug().Msgf("Created core build directory: %s", dirname)
}

func NewBuildCache() *BuildCache {
	return &BuildCache{
		CachedBuildStep: make(map[string]*BuildStepCache, 0),
	}
}

type DoContext struct {
	builddir_path string
	cachedir_path string

	c_toolchain *Toolchain

	// Use this mutex to synchronize the access and modification of build
	// tree state, i.e., build step completion state.
	build_tree_state_mu *sync.Mutex
	build_cancelled     bool
	// The build cache state at the start of the build execution.
	init_build_cache *BuildCache
	// The build cache state at the end of the build execution.
	end_build_cache     *BuildCache
	action_state_writer *ActionStateWriter
	compile_database    *CompileCommandsDatabase
}

func NewDoContext(enable_action_writer bool) *DoContext {
	return &DoContext{
		c_toolchain: NewGccToolchain(),

		build_tree_state_mu: &sync.Mutex{},
		build_cancelled:     false,

		init_build_cache:    NewBuildCache(),
		end_build_cache:     NewBuildCache(),
		action_state_writer: NewActionStateWriter(6, enable_action_writer),
		compile_database:    &CompileCommandsDatabase{Commands: []*CompileCommandEntry{}},
	}
}

// Setup the do-build directory in the root of the project.
// The root of the project expects a build.toml file.
func (dctx *DoContext) SetupCoreDirs() error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	buildfile_path := filepath.Join(cwd, "build.toml")
	if !is_file(buildfile_path) {
		return fmt.Errorf("no buildfile found at %s", buildfile_path)
	}

	dctx.builddir_path = filepath.Join(cwd, ".do-build")
	dctx.cachedir_path = filepath.Join(cwd, ".do-cache")
	ensure_dir(dctx.builddir_path)
	// External directory will be used for storing external dependencies.
	ensure_dir(filepath.Join(dctx.builddir_path, "external"))
	ensure_dir(dctx.cachedir_path)
	return nil
}

func (dctx *DoContext) LoadCache() error {
	cachefile := filepath.Join(dctx.cachedir_path, "cache.json")
	if st, err := os.Stat(cachefile); err != nil || st.IsDir() {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// No cache file, skip
				return nil
			}
			return err
		} else {
			return fmt.Errorf("invalid file type for file: %s", cachefile)
		}
	}

	cachedat, err := os.ReadFile(cachefile)
	if err != nil {
		return err
	}

	var bcache BuildCache
	err = json.Unmarshal(cachedat, &bcache)
	if err != nil {
		return err
	}
	dctx.init_build_cache = &bcache
	return nil
}

func write_json_to_file(outfile string, data interface{}) error {
	out_data, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	f, err := os.OpenFile(outfile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(out_data)
	return err
}

func (dctx *DoContext) RefreshCache() error {
	cachefile := filepath.Join(dctx.cachedir_path, "cache.json")
	return write_json_to_file(cachefile, dctx.end_build_cache)
}

func init() {

	var err error
	var outlog io.Writer = nil
	var loglevel zerolog.Level = zerolog.DebugLevel
	if has_bool_arg("logtostderr") {
		outlog = os.Stderr
	} else {
		logfile, err = os.CreateTemp("", "do-log")
		if err != nil {
			os.Exit(1)
		}
		outlog = bufio.NewWriter(logfile)

		defer func() {
			if loglevel == zerolog.DebugLevel {
				fmt.Printf("Writing logs to: %s\n", logfile.Name())
			}
		}()
	}
	if outlog == nil {
		panic("logger output not set")
	}

	logger = zerolog.New(zerolog.ConsoleWriter{
		Out:        outlog,
		TimeFormat: time.RFC3339,
	})

	if lvl, err := get_arg_value("loglevel"); err == nil {
		switch lvl {
		case "debug":
			loglevel = zerolog.DebugLevel
		case "info":
			loglevel = zerolog.InfoLevel
		case "error":
			loglevel = zerolog.ErrorLevel
		case "warn":
			loglevel = zerolog.WarnLevel
		case "fatal":
			loglevel = zerolog.FatalLevel
		case "panic":
			loglevel = zerolog.PanicLevel
		case "trace":
			loglevel = zerolog.TraceLevel
		case "none":
			loglevel = zerolog.Disabled
		}
	}
	zerolog.SetGlobalLevel(loglevel)
	logger.Info().Msg("Zerolog configured")
}

type SubCommand struct {
	name            string
	usage           string
	check_core_dirs bool
	flagset         *flag.FlagSet
	run_subcommand  func(*DoContext, *SubCommand /* args */, []string) error
}

func run_builld_subcommand(dctx *DoContext, flagset *SubCommand, args []string) error {
	return build(dctx, args)
}

func run_clean_subcommand(dctx *DoContext, flgset *SubCommand, args []string) error {
	return clean(dctx)
}

func run_init_subcommand(dctx *DoContext, flagset *SubCommand, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no project name specified")
	}

	var project_name string = args[0]
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	var project_path string = filepath.Join(cwd, project_name)
	if _, err = os.Stat(project_path); err == nil {
		return fmt.Errorf("file already exists: %s", project_path)
	}

	err = os.Mkdir(project_name, os.ModeDir)
	if err != nil {
		return err
	}

	_, err = os.OpenFile(filepath.Join(project_path, "build.toml"), os.O_RDONLY|os.O_CREATE, 0666)
	if err == nil {
		fmt.Printf("\tProject %s created successfully.\n", color.New(color.FgHiGreen).SprintFunc()(project_name))
		fmt.Printf("\tCheck out the directory: %s", color.New(color.FgHiGreen).SprintfFunc()("cd ./%s", project_name))
	}
	return err
}

func main() {
	var err error

	// TODO(0000mz): Populate the flag set for each subcommand.
	var subcommands []*SubCommand = []*SubCommand{
		{name: "init", usage: "Initialize a new c project.", check_core_dirs: false, flagset: nil, run_subcommand: run_init_subcommand},
		{name: "build", usage: "Build a target.", flagset: nil, check_core_dirs: true, run_subcommand: run_builld_subcommand},
		{name: "clean", usage: "Clean up targets and cache.", check_core_dirs: true, flagset: nil, run_subcommand: run_clean_subcommand},
	}

	fmt.Printf("%s - %s\n", color.New(color.FgHiCyan).SprintFunc()("do"), color.New(color.FgHiGreen).SprintFunc()("c action runner"))
	if len(os.Args) <= 1 || os.Args[1] == "--help" {
		for _, subcmd := range subcommands {
			fmt.Printf("\t%s\t%s\n", color.New(color.FgHiCyan).SprintFunc()(subcmd.name), subcmd.usage)
		}
		return
	}

	var subcommand string = os.Args[1]
	var has_subcommand bool = false
	for _, flaginfo := range subcommands {
		if flaginfo.name == subcommand {
			has_subcommand = true
		}
	}
	if !has_subcommand {
		fmt.Printf("Error: Unknown command: %s\n", subcommand)
		os.Exit(1)
	}

	disable_action_writer := has_bool_arg("disable_action_writer")
	dctx = NewDoContext(!disable_action_writer)

	for _, flaginfo := range subcommands {
		if flaginfo.name == subcommand {
			if flaginfo.check_core_dirs {
				err = dctx.SetupCoreDirs()
				if err != nil {
					panic(err)
				}
				err = dctx.LoadCache()
				if err != nil {
					panic(err)
				}
			}

			err := flaginfo.run_subcommand(dctx, flaginfo, os.Args[2:])

			var exit_code int = 0
			if err != nil {
				exit_code = 1
				fmt.Printf("Error: %v\n", err)
			}
			os.Exit(exit_code)
		}
	}
}
