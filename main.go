// do - build, execute and test c modules and binaries

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/fatih/color"
	"github.com/rs/zerolog"
)

var (
	logger zerolog.Logger
	logfile *os.File
	dctx *DoContext
)

func is_file(filename string) bool {
	stat, err := os.Stat(filename)
	if  err != nil {
		return false
	}
	return !stat.IsDir()
}

type TargetConfig struct {
	Name string
	Srcs []string
	Hdrs []string
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
func (t *TargetConfig) ConstructBuildTree(dctx *DoContext) (*BuildStep, error) {
	// TODO: Handle build dependencies.

	switch (t.Type) {
	case "static":
		return t.static_build_step(dctx)
	case "dynamic":
		return nil, fmt.Errorf("Dynamic build unimplemented.")	
	case "binary":
	default:
	}
	return nil, fmt.Errorf("Unknown target type: %s", t.Type)
}

func (t *TargetConfig) static_build_step(dctx *DoContext) (*BuildStep, error) {
	// Static build takes 2 steps:
	// Step 1: build the object files with the compiler.
	// Step 2: Use ar to product the library from the produced object fles.

	objfile_bs := &BuildSubStep{
		inputs: t.Srcs,
		outputs: []string{filepath.Join(dctx.builddir_path, fmt.Sprintf("%s.o", t.Name))},
		action: ProduceObject,
	}

	libfile_bs := &BuildSubStep{
		inputs: objfile_bs.outputs,
		outputs: []string{filepath.Join(dctx.builddir_path, fmt.Sprintf("%s.a", t.Name))},
		action: UseArToProduceStaticLib,
	}
	objfile_bs.next = libfile_bs

	bs := &BuildStep{
		steps: objfile_bs,
	}
	return bs, nil
}

type TargetParser struct {
	targets map[string]TargetConfig
}

func NewTargetParser(config_file string) (*TargetParser, error) {
stat, err := os.Stat(config_file)
	if  err != nil {
		return nil, err
	}
	if stat.IsDir() {
		return nil, fmt.Errorf("Config file is a directory: %s", config_file)
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
	return nil, fmt.Errorf("No target found with name: %s", target_name)
}

type SubStepAction int64
const (
	ProduceObject SubStepAction = 0
	UseArToProduceStaticLib = 1
)

type BuildSubStep struct {
	inputs []string
	outputs []string
	action SubStepAction
	next *BuildSubStep
}

func (bss *BuildSubStep) Build(dctx *DoContext) error {
	switch bss.action {
	case ProduceObject:
		return bss.build_object(dctx)
	case UseArToProduceStaticLib:
		return bss.produce_static_lib(dctx)
	}
	return fmt.Errorf("Unimplemented build step action: %v", bss.action)
}

func (bss *BuildSubStep) build_object(dctx *DoContext) error {
	if len(bss.outputs) != 1 {
		return fmt.Errorf("Incorrect # of outputs for object build: %d, expects 1", len(bss.outputs))
	}
	
	outobj := bss.outputs[0]
	cmd := []string {dctx.c_compiler, "-c", "-o", outobj}
	cmd = append(cmd, bss.inputs...)

	logger.Debug().Msgf("Object Build command: %#v", cmd)

	excmd := exec.Command(cmd[0], cmd[1:]...)
	out, err := excmd.Output()
	if err != nil {
		return err
	}
	logger.Debug().Msgf("Build command output: %s", string(out))
	fmt.Printf("%s: %s\n", color.New(color.FgCyan).SprintFunc()("Object built"),  color.New(color.FgGreen).SprintFunc()(outobj))
	return nil
}

func (bss *BuildSubStep) produce_static_lib(dctx *DoContext) error {
	if len(bss.outputs) != 1 {
		return fmt.Errorf("Incorrect # of outputs for static lib build: %d, expects 1", len(bss.outputs))
	}

	outlib := bss.outputs[0]
	cmd := []string {dctx.ar, "rcs", outlib}
	cmd = append(cmd, bss.inputs...)

	logger.Debug().Msgf("Static Lib Build Command: %#v", cmd)
	
	excmd := exec.Command(cmd[0], cmd[1:]...)
	out, err := excmd.Output()
	if err != nil {
		return err
	}
	logger.Debug().Msgf("Build command output: %s", string(out))
	fmt.Printf("%s: %s\n", color.New(color.FgCyan).SprintFunc()("Static library built"),  color.New(color.FgGreen).SprintFunc()(outlib))
	return nil
}

// Build step define how to build a specific transition unit
// and has information on the artifacts produced from the build step.
// It also contains the children that need to be built before this step
// can properly be built.
type BuildStep struct {

	// The list of artifacts produced by the build step.
	// This is populated after the build step is executed.
	output_artifacts_path []string
	steps *BuildSubStep
	dependants *[]BuildStep
}

func (bs *BuildStep) Build(dctx *DoContext) error {
	if bs.steps == nil {
		return fmt.Errorf("Nothing to build")
	}

	var err error
	var bss *BuildSubStep = bs.steps
	for bss != nil {
		err = bss.Build(dctx)
		if err != nil {
			return err
		}
		bss = bss.next
	}
	return nil	
}

// Build the requested target.
func build(dctx *DoContext, args []string) error {
	var target_name string

	if len(args) == 0 {
		return fmt.Errorf("No target name provided.")
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

	btree, err := tinfo.ConstructBuildTree(dctx)
	if err != nil {
		return err
	}

	err = btree.Build(dctx)
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
func has_bool_arg (argname string) bool {
	for _, arg := range os.Args[1:] {
		if arg == fmt.Sprintf("--%s", argname) {
			return true
		}
	}
	return false
}

// Get the value of a kv arg in the form "--key=value". Return the value if the
// kv arg exists. Otherwise, return an error.
func get_arg_value (argkey string) (string, error) {
	for _, arg := range os.Args[1:] {
		parts := strings.Split(arg, "=")
		if len(parts) < 2 || parts[0] != fmt.Sprintf("--%s", argkey)	{
			continue
		}
		return strings.Join(parts[1:], "="), nil
	}
	return "", fmt.Errorf("No kv arg for key: %s", argkey)
}

type DoContext struct {
	builddir_path string
	c_compiler string
	ar string
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
		return fmt.Errorf("No buildfile found at %s", buildfile_path)
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
		Out: outlog,
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
	fmt.Printf("%s %s\n", color.New(color.FgCyan).SprintFunc()("do"),  color.New(color.FgGreen).SprintFunc()(action))

	dctx = &DoContext{
		c_compiler: "gcc",
		ar: "ar",
	}
	setup_core_dirs(dctx)
	
	var err error
	switch action {
	case "build":
		err = build(dctx, os.Args[2:])
	case "clean":
		err = clean(dctx)
	default:
		err = fmt.Errorf("Unknown action: %s\n", action)
	}

	logger.Info().Msgf("err = %v", err)
	exit_code := 0
	if err != nil {
		exit_code = 1
	}

	os.Exit(exit_code)
}