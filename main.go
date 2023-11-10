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
)

func is_file(filename string) bool {
	stat, err := os.Stat(filename)
	if  err != nil {
		return false
	}
	return !stat.IsDir()
}

type TargetConfig struct {
	Srcs []string
	Hdrs []string
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

// Return the build command for building the specified target.
func (t *TargetConfig) BuildCmd() []string {
	var cmd []string = []string{"gcc"}
	return append(cmd, t.Srcs...)
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

// Build the requested target.
func build(args []string) error {
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

	buildcmd := tinfo.BuildCmd()
	logger.Debug().Msgf("Build command for target %s: %s", target_name, buildcmd)

	builddir, err := os.MkdirTemp("", "")
	if err != nil {
		return err
	}
	outexe := fmt.Sprintf("%s/a", builddir)
	logger.Info().Msgf("Building target to file: %s", outexe)
	buildcmd = append(buildcmd, "-o")
	buildcmd = append(buildcmd, outexe)

	cmd := exec.Command(buildcmd[0], buildcmd[1:]...)
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	logger.Debug().Msgf("Build command output: %s", string(out))

	fmt.Printf("%s: %s\n", color.New(color.FgCyan).SprintFunc()("Build Output"),  color.New(color.FgGreen).SprintFunc()(filepath.Join(outexe)))

	return nil
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

	var err error
	switch action {
	case "build":
		err = build(os.Args[2:])
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