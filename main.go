// do - build, execute and test c modules and binaries

package main

import (
	"bufio"
	"bytes"
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
	"github.com/rs/zerolog"
)

var (
	logger  zerolog.Logger
	logfile *os.File
	dctx    *DoContext
)

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
		dir:   filepath.Dir(path),
		fname: filepath.Base(path),
	}
}

func is_file(filename string) bool {
	stat, err := os.Stat(filename)
	if err != nil {
		return false
	}
	return !stat.IsDir()
}

type TargetConfig struct {
	Name string
	Srcs []string
	Hdrs []string
	Deps []string
	// The target type that should be build.
	// For library, this can be "static" or "dynamic".
	// For binary, set to "binary".
	Type string
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

	bs.dependants = deps_buildsteps
	// Set the parent for for eahc of the deps to the bs
	for _, dep := range bs.dependants {
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
	return bs, nil
}

func NewBuildStep() *BuildStep {
	return &BuildStep{
		promotion_fn:   func(_ *BuildStep) bool { return false },
		build_complete: false,
	}
}

func (t *TargetConfig) binary_build_step(dctx *DoContext) (*BuildStep, error) {
	binfils_bs := &BuildSubStep{
		inputs:    apply(t.Srcs, convert_path_to_artifact),
		outputs:   []*Artifact{{dir: dctx.builddir_path, fname: t.Name}},
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
		outputs:   []*Artifact{{dir: dctx.builddir_path, fname: fmt.Sprintf("%s.o", t.Name)}},
		action_fn: build_object,
	}

	libfile_bs := &BuildSubStep{
		inputs:    objfile_bs.outputs,
		outputs:   []*Artifact{{dir: dctx.builddir_path, fname: fmt.Sprintf("%s.a", t.Name)}},
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

	action_fn func(*BuildStep, *BuildSubStep, *DoContext) (error, *bytes.Buffer)
	next      *BuildSubStep
}

func (bss *BuildSubStep) Build(bs *BuildStep, dctx *DoContext) (error, *bytes.Buffer) {
	return bss.action_fn(bs, bss, dctx)
}

func build_binary(bs *BuildStep, bss *BuildSubStep, dctx *DoContext) (error, *bytes.Buffer) {
	if len(bss.outputs) != 1 {
		return fmt.Errorf("incorrect # of outputs for binary build: %d, expects 1", len(bss.outputs)), nil
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
		cmd = append(cmd, fmt.Sprintf("-L%s", static_lib.dir), fmt.Sprintf("-l:%s", static_lib.fname))
	}

	logger.Debug().Msgf("Binary Build command: %#v", cmd)

	var errb bytes.Buffer
	excmd := exec.Command(cmd[0], cmd[1:]...)
	excmd.Stderr = &errb

	out, err := excmd.Output()
	if err != nil {
		return err, &errb
	}
	logger.Debug().Msgf("Build command output: %s", string(out))
	fmt.Printf("%s: %s\n", color.New(color.FgCyan).SprintFunc()("Binary built"), color.New(color.FgGreen).SprintFunc()(outbin.Fullpath()))
	return nil, nil
}

func build_object(bs *BuildStep, bss *BuildSubStep, dctx *DoContext) (error, *bytes.Buffer) {
	if len(bss.outputs) != 1 {
		return fmt.Errorf("incorrect # of outputs for object build: %d, expects 1", len(bss.outputs)), nil
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
		return err, &errb
	}
	logger.Debug().Msgf("Build command output: %s", string(out))
	fmt.Printf("%s: %s\n", color.New(color.FgCyan).SprintFunc()("Object built"), color.New(color.FgGreen).SprintFunc()(outobj.Fullpath()))
	return nil, nil
}

func produce_static_lib(bs *BuildStep, bss *BuildSubStep, dctx *DoContext) (error, *bytes.Buffer) {
	if len(bss.outputs) != 1 {
		return fmt.Errorf("incorrect # of outputs for static lib build: %d, expects 1", len(bss.outputs)), nil
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
		return err, &errb
	}
	logger.Debug().Msgf("Build command output: %s", string(out))
	fmt.Printf("%s: %s\n", color.New(color.FgCyan).SprintFunc()("Static library built"), color.New(color.FgGreen).SprintFunc()(outlib.Fullpath()))
	return nil, nil
}

// An artifact is a product of a build step.
type Artifact struct {
	// The directory that the artifact is stored in.
	dir string
	// The filename of the artifact within the directory.
	fname string
}

func (a *Artifact) Fullpath() string {
	return filepath.Join(a.dir, a.fname)
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
}

func (bs *BuildStep) Build(dctx *DoContext, errch chan error, stderrch chan *bytes.Buffer, completech chan bool) {
	{
		dctx.build_tree_state_mu.Lock()
		if dctx.build_cancelled {
			return
		}
		dctx.build_tree_state_mu.Unlock()
	}

	var bss *BuildSubStep = bs.steps
	for bss != nil {
		err, stderr := bss.Build(bs, dctx)
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

	{
		dctx.build_tree_state_mu.Lock()
		bs.build_complete = true
		if dctx.build_cancelled {
			return
		}
		dctx.build_tree_state_mu.Unlock()
	}

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

	fmt.Printf("Build Tree Completed!")
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

	btree, err := tinfo.ConstructBuildTree(dctx, tp)
	if err != nil {
		return err
	}

	err = run_build_tree(btree, dctx)
	if err != nil {
		return err
	}
	return nil
}

func clean(dctx *DoContext) error {
	return os.RemoveAll(dctx.builddir_path)
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

type DoContext struct {
	builddir_path string
	c_compiler    string
	ar            string

	// Use this mutex to synchronize the access and modification of build
	// tree state, i.e., build step completion state.
	build_tree_state_mu *sync.Mutex
	build_cancelled     bool
}

// Setup the do-build directory in the root of the project.
// The root of the project expects a build.toml file.
func setup_core_dirs(dctx *DoContext) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	buildfile_path := filepath.Join(cwd, "build.toml")
	if !is_file(buildfile_path) {
		return fmt.Errorf("no buildfile found at %s", buildfile_path)
	}

	dctx.builddir_path = filepath.Join(cwd, ".do-build")
	err = os.Mkdir(dctx.builddir_path, os.ModeDir)
	if err != nil {
		return err
	}
	logger.Debug().Msgf("Created core build directory: %s", dctx.builddir_path)
	return nil
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

	dctx = &DoContext{
		c_compiler: "gcc",
		ar:         "ar",

		build_tree_state_mu: &sync.Mutex{},
		build_cancelled:     false,
	}
	setup_core_dirs(dctx)

	var err error
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
