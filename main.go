// do - build, execute and test c modules and binaries

package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
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

type BuildStateWriter struct {
	// The number of state io to maange at a time.
	state_io_ct int
	writer      *uilive.Writer

	// Keep tracks of the builds in progress.
	builds map[string]bool
	io_mu  *sync.Mutex

	last_write_time time.Time
}

func NewBuildStateWriter(state_ct int) *BuildStateWriter {
	return &BuildStateWriter{
		state_io_ct: state_ct,
		builds:      make(map[string]bool),
		io_mu:       &sync.Mutex{},
	}
}

func (io *BuildStateWriter) Start() {
	io.writer = uilive.New()
	io.writer.Start()
	io.update_build_state_io()
}

func (io *BuildStateWriter) Stop(update_state bool) {
	if io.writer == nil {
		return
	}
	if update_state {
		io.update_build_state_io()
	}
	io.writer.Stop()
}

func (io *BuildStateWriter) AddBuild(build_name string) {
	io.builds[build_name] = false
	io.update_build_state_io()
}

func (io *BuildStateWriter) SetBuildFinished(build_name string) {
	io.builds[build_name] = true
	io.update_build_state_io()
}

func (io *BuildStateWriter) active_build_ct() int {
	ct := 0
	for _, is_finished := range io.builds {
		if !is_finished {
			ct++
		}
	}
	return ct
}

func (io *BuildStateWriter) total_builds() int {
	return len(io.builds)
}

func (io *BuildStateWriter) update_build_state_io() {
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
	for target_name, finished := range io.builds {
		if !finished {
			msg += grn(fmt.Sprintf("\tbuilding: %s\n", target_name))
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

func convert_path_to_artifact(path string) *Artifact {
	return &Artifact{
		Dir:   filepath.Dir(path),
		Fname: filepath.Base(path),
	}
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

// Determine if the `target`'s artifacts need to be refreshed.
// The artifacts need to be refreshed if the files it depends on have a different
// hash compared to the file hashes in the `cache`.
func compute_refresh(target *TargetConfig, cache *BuildCache) bool {
	tcache, is_cached := cache.CachedTargets[target.Name]
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
		if !artifact.Exists() {
			return true
		}
	}

	return false
}

type TargetConfig struct {
	Name string   `json:"name"`
	Srcs []string `json:"srcs"`
	Hdrs []string `json:"hdrs"`
	Deps []string `json:"deps"`
	// The target type that should be build.
	// For library, this can be "static" or "dynamic".
	// For binary, set to "binary".
	Type string `json:"-"`
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
	default:
		return nil, fmt.Errorf("unknown target type: %s", t.Type)
	}

	if err != nil {
		return nil, err
	}
	if bs == nil {
		panic("Build step not set during construction of build tree.")
	}

	// Check if any of the files this target depends on have changed.
	bs.needs_refresh = compute_refresh(t, dctx.init_build_cache)

	bs.target_config = t
	bs.dependants = deps_buildsteps
	// Set the parent for for eahc of the deps to the bs
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

	dctx.build_state_writer.AddBuild(t.Name)
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
		inputs:    apply(t.Srcs, convert_path_to_artifact),
		outputs:   []*Artifact{{Dir: dctx.builddir_path, Fname: t.Name}},
		action_fn: build_binary,
	}

	bs := NewBuildStep()
	bs.steps = binfils_bs

	return bs, nil
}

func (t *TargetConfig) static_build_step(dctx *DoContext) (*BuildStep, error) {
	// Static build takes 2 steps:
	// Step 1: build the object files with the compiler.
	// Step 2: Use ar to product the library from the produced object fles.

	objfile_bs := &BuildSubStep{
		inputs:    apply(t.Srcs, convert_path_to_artifact),
		outputs:   []*Artifact{{Dir: dctx.builddir_path, Fname: fmt.Sprintf("%s.o", t.Name)}},
		action_fn: build_object,
	}

	libfile_bs := &BuildSubStep{
		inputs:    objfile_bs.outputs,
		outputs:   []*Artifact{{Dir: dctx.builddir_path, Fname: fmt.Sprintf("%s.a", t.Name)}},
		action_fn: produce_static_lib,
	}
	objfile_bs.next = libfile_bs

	bs := NewBuildStep()
	bs.steps = objfile_bs

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
	logger.Debug().Msgf("tparser: %#v", tparser)
	return &tparser, nil
}

// Find the target with the given `target_name`.
// Return the target info associated with the target name, or an error if the target
// cannot be found.
func (t *TargetParser) FindTarget(target_name string) (*TargetConfig, error) {
	for tname, tcfg := range t.targets {
		if tname == target_name {
			return &tcfg, nil
		}
	}
	return nil, fmt.Errorf("no target found with name: %s", target_name)
}

type SubStepAction int64

type BuildSubStep struct {
	inputs  []*Artifact
	outputs []*Artifact

	action_fn func(*BuildStep, *BuildSubStep, *DoContext) (*bytes.Buffer, error)
	next      *BuildSubStep
}

func (bss *BuildSubStep) Build(bs *BuildStep, dctx *DoContext) (*bytes.Buffer, error) {
	return bss.action_fn(bs, bss, dctx)
}

func build_binary(bs *BuildStep, bss *BuildSubStep, dctx *DoContext) (*bytes.Buffer, error) {
	if len(bss.outputs) != 1 {
		return nil, fmt.Errorf("incorrect # of outputs for binary build: %d, expects 1", len(bss.outputs))
	}

	// TODO: Appending exe to the produced binary so that windows will know how to handle the file.
	// This is not portable and is only windows specific. Abstract this away so that the filename
	// decision is more intuitive based on the operating system and the type of object being built.
	outbin := bss.outputs[0]
	exepath := fmt.Sprintf("%s.exe", outbin.Fullpath())
	cmd := []string{dctx.c_compiler, "-o", exepath}
	cmd = append(cmd, apply(bss.inputs, func(a *Artifact) string { return a.Fullpath() })...)

	// Collect the artifacts from the dependants and append it to the command.
	// This assumes that every dependant build step produces a static library.
	var static_libs []*Artifact = make([]*Artifact, 0)
	for _, dep_bs := range bs.dependants {
		static_libs = append(static_libs, dep_bs.output_artifacts...)
	}

	for _, static_lib := range static_libs {
		cmd = append(cmd, fmt.Sprintf("-L%s", static_lib.Dir), fmt.Sprintf("-l:%s", static_lib.Fname))
	}

	logger.Debug().Msgf("Binary Build command: %#v", cmd)

	var errb bytes.Buffer
	excmd := exec.Command(cmd[0], cmd[1:]...)
	excmd.Stderr = &errb

	out, err := excmd.Output()
	if err != nil {
		return &errb, err
	}
	logger.Debug().Msgf("Build command output: %s", string(out))
	return nil, nil
}

func build_object(bs *BuildStep, bss *BuildSubStep, dctx *DoContext) (*bytes.Buffer, error) {
	if len(bss.outputs) != 1 {
		return nil, fmt.Errorf("incorrect # of outputs for object build: %d, expects 1", len(bss.outputs))
	}

	outobj := bss.outputs[0]
	cmd := []string{dctx.c_compiler, "-c", "-o", outobj.Fullpath()}
	cmd = append(cmd, apply(bss.inputs, func(a *Artifact) string { return a.Fullpath() })...)

	logger.Debug().Msgf("Object Build command: %#v", cmd)

	var errb bytes.Buffer
	excmd := exec.Command(cmd[0], cmd[1:]...)
	excmd.Stderr = &errb

	out, err := excmd.Output()
	if err != nil {
		return &errb, err
	}
	logger.Debug().Msgf("Build command output: %s", string(out))
	return nil, nil
}

func produce_static_lib(bs *BuildStep, bss *BuildSubStep, dctx *DoContext) (*bytes.Buffer, error) {
	if len(bss.outputs) != 1 {
		return nil, fmt.Errorf("incorrect # of outputs for static lib build: %d, expects 1", len(bss.outputs))
	}

	var outlib *Artifact = bss.outputs[0]
	cmd := []string{dctx.ar, "rcs", outlib.Fullpath()}
	cmd = append(cmd, apply(bss.inputs, func(a *Artifact) string { return a.Fullpath() })...)

	logger.Debug().Msgf("Static Lib Build Command: %#v", cmd)

	var errb bytes.Buffer
	excmd := exec.Command(cmd[0], cmd[1:]...)
	excmd.Stderr = &errb

	out, err := excmd.Output()
	if err != nil {
		return &errb, err
	}
	logger.Debug().Msgf("Build command output: %s", string(out))
	return nil, nil
}

// An artifact is a product of a build step.
type Artifact struct {
	// The directory that the artifact is stored in.
	Dir string `json:"dir"`
	// The filename of the artifact within the directory.
	Fname string `json:"fname"`
}

func (a *Artifact) Exists() bool {
	_, err := os.Stat(a.Fullpath())
	return err == nil
}

func (a *Artifact) Fullpath() string {
	return filepath.Join(a.Dir, a.Fname)
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
		var bss *BuildSubStep = bs.steps
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
		func() {
			dctx.build_tree_state_mu.Lock()
			defer dctx.build_tree_state_mu.Unlock()

			cached, is_cached := dctx.init_build_cache.CachedTargets[bs.target_config.Name]
			if !is_cached {
				panic("BuildStep marked as cached but no cache entry found.")
			}
			bs.output_artifacts = cached.Artifacts
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

		cache_target := &TargetCache{
			Target:     bs.target_config,
			FileHashes: hashes,
			Artifacts:  bs.output_artifacts,
		}

		dctx.end_build_cache.CachedTargets[bs.target_config.Name] = cache_target
	}()

	dctx.build_state_writer.SetBuildFinished(bs.target_config.Name)

	// Check if this build can be promoted to the next level of the tree.
	if bs.promotion_fn(bs) {
		logger.Debug().Msg("Promoting build to next level.")
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
	logger.Debug().Msgf("Target info: %#v", tinfo)

	err = tinfo.Validate()
	if err != nil {
		return err
	}

	var build_succeeded bool = false
	dctx.build_state_writer.Start()
	// On stop, update the io writer if the build succeeded. That way
	// the io build state does not interfere with the failed build io.
	defer dctx.build_state_writer.Stop(build_succeeded)

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

type TargetCache struct {
	Target *TargetConfig `json:"target"`
	// For each file defined in the target config store the md5 hash for the file
	// when it was last built. This should be used to compare against to determine
	// whether or not a target needs to be rebuilt.
	FileHashes map[string][]byte `json:"file-hashes"`
	// Cthe location of artifacts produced by the target.
	Artifacts []*Artifact `json:"artifacts"`
}

// The build cache stores information about the targets that were built and
// the state of the files that each built target depends on. This is used to determine
// in future builds whether or not a target should be rebuilt and where to find the
// cached artifacts.
type BuildCache struct {
	CachedTargets map[string]*TargetCache `json:"cached-targets"`
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
		CachedTargets: make(map[string]*TargetCache, 0),
	}
}

type DoContext struct {
	builddir_path string
	cachedir_path string

	c_compiler string
	ar         string

	// Use this mutex to synchronize the access and modification of build
	// tree state, i.e., build step completion state.
	build_tree_state_mu *sync.Mutex
	build_cancelled     bool
	// The build cache state at the start of the build execution.
	init_build_cache *BuildCache
	// The build cache state at the end of the build execution.
	end_build_cache    *BuildCache
	build_state_writer *BuildStateWriter
}

func NewDoContext() *DoContext {
	return &DoContext{
		c_compiler: "gcc",
		ar:         "ar",

		build_tree_state_mu: &sync.Mutex{},
		build_cancelled:     false,

		init_build_cache:   NewBuildCache(),
		end_build_cache:    NewBuildCache(),
		build_state_writer: NewBuildStateWriter(6),
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

func (dctx *DoContext) RefreshCache() error {
	new_cache_data, err := json.MarshalIndent(dctx.end_build_cache, "", "  ")
	if err != nil {
		return err
	}

	cachefile := filepath.Join(dctx.cachedir_path, "cache.json")
	f, err := os.OpenFile(cachefile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(new_cache_data)
	if err != nil {
		return err
	}
	return err
}

func init() {

	var err error
	var outlog io.Writer = nil
	var loglevel zerolog.Level = zerolog.DebugLevel
	if has_bool_arg("logtostderr") {
		outlog = os.Stderr
	} else {
		logfile, err = os.CreateTemp("", "")
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
}

func main() {
	if len(os.Args) <= 1 {
		// TODO: Print the help menu
		return
	}

	action := os.Args[1]
	fmt.Printf("%s %s\n", color.New(color.FgCyan).SprintFunc()("do"), color.New(color.FgGreen).SprintFunc()(action))

	dctx = NewDoContext()

	var err error
	err = dctx.SetupCoreDirs()
	if err != nil {
		panic(err)
	}
	err = dctx.LoadCache()
	if err != nil {
		panic(err)
	}

	switch action {
	case "build":
		err = build(dctx, os.Args[2:])
	case "clean":
		err = clean(dctx)
	default:
		err = fmt.Errorf("unknown action: %s", action)
	}

	logger.Info().Msgf("err = %v", err)
	exit_code := 0
	if err != nil {
		exit_code = 1
	}

	os.Exit(exit_code)
}
