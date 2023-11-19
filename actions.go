package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// These action functions are used to commit a build [sub]step.
// A build action has the following function signiature:
//	func build_binary_action(
//     bs *BuildStep, bss *BuildSubStep, dctx *DoContext) (*bytes.Buffer, error)
//
// On success, the build action returns nothing (both return values are nil).
// If an error occurs during the build action, an optional stderr buffer is returned as the
// first parameter and a required error is returned as the second param.
// The stderr buffer is received from a call to a subprocess command and should hold any error
// output from the command's execution.

func build_binary_action(bs *BuildStep, bss *BuildSubStep, dctx *DoContext) (*bytes.Buffer, error) {
	if len(bss.outputs) != 1 {
		return nil, fmt.Errorf("incorrect # of outputs for binary build: %d, expects 1", len(bss.outputs))
	}

	cmd := dctx.c_toolchain.build_binary_cmd_fn(dctx, bs, bss)
	logger.Debug().Msgf("Binary Build command: %#v", cmd)

	stdout, stderr, err := run_command(cmd)
	if err != nil {
		return stderr, err
	}

	logger.Debug().Msgf("Build command output: %s", string(stdout))
	return nil, nil
}

func build_object_action(bs *BuildStep, bss *BuildSubStep, dctx *DoContext) (*bytes.Buffer, error) {
	if len(bss.outputs) != 1 {
		return nil, fmt.Errorf("incorrect # of outputs for object build: %d, expects 1", len(bss.outputs))
	}

	cmd := dctx.c_toolchain.compile_object_cmd_fn(dctx, bs, bss)
	logger.Debug().Msgf("Object Build command: %#v", cmd)

	stdout, stderr, err := run_command(cmd)
	if err != nil {
		return stderr, err
	}

	logger.Debug().Msgf("Build command output: %s", string(stdout))
	return nil, nil
}

func produce_static_lib_action(bs *BuildStep, bss *BuildSubStep, dctx *DoContext) (*bytes.Buffer, error) {
	if len(bss.outputs) != 1 {
		return nil, fmt.Errorf("incorrect # of outputs for static lib build: %d, expects 1", len(bss.outputs))
	}

	cmd := dctx.c_toolchain.build_static_lib_cmd_fn(dctx, bs, bss)

	logger.Debug().Msgf("Static Lib Build Command: %#v", cmd)
	stdout, stderr, err := run_command(cmd)
	if err != nil {
		return stderr, err
	}
	logger.Debug().Msgf("Build command output: %s", string(stdout))
	return nil, nil
}

func pull_git_action(bs *BuildStep, bss *BuildSubStep, dc *DoContext) (*bytes.Buffer, error) {
	if len(bss.inputs) != 1 {
		return nil, fmt.Errorf("expected only 1 input for git-pull action, received %d", len(bss.inputs))
	}
	if len(bss.outputs) != 1 {
		return nil, fmt.Errorf("expected only 1 output for git-pull action, received %d", len(bss.outputs))
	}

	var github_repo string = bss.inputs[0].Url
	var commit_hash string = bss.inputs[0].Fname
	var destination string = bss.outputs[0].Dir

	// TODO(0000mz): If the repo is already downloaded, skip pulling it again.
	if _, err := os.Stat(destination); err == nil {
		err := os.RemoveAll(destination)
		if err != nil {
			return nil, err
		}
	}

	stdout, stderr, err := run_command([]string{"git", "clone", github_repo, destination})
	if err != nil {
		return stderr, err
	}

	logger.Debug().Msgf("Stdout command output: %s", string(stdout))

	_, stderr, err = run_command_dir([]string{"git", "checkout", commit_hash}, destination)
	if err != nil {
		return stderr, err
	}
	return nil, nil
}

// External build step used for building projects with for the specific type: i.e. make, configure-make, etc...
// @params
//   - [0] project directory: The root directory path of the project that needs to be built.
var external_build_steps = map[string]func(project_dir string, bs *BuildStep, bss *BuildSubStep, dc *DoContext) (*bytes.Buffer, error){
	"make": run_make_action,
}

func get_all_all_external_build_configs() []string {
	var configs []string = []string{}
	for k := range external_build_steps {
		configs = append(configs, k)
	}
	return configs
}

func run_make_action(project_dir string, bs *BuildStep, bss *BuildSubStep, dc *DoContext) (*bytes.Buffer, error) {

	var nb_jobs int = 24

	_, stderr, err := run_command_dir([]string{"make", fmt.Sprintf("-j%d", nb_jobs)}, project_dir)
	if err != nil {
		return stderr, err
	}

	// Iterate through the files in the project directory recursively and find all files within the
	// output list.
	// If an output is not found, an error will be returned.
	var outputs_files map[string]bool = make(map[string]bool)
	for _, el := range bss.outputs {
		logger.Debug().Msgf("Expecting file to be produced from \"make\": %s", el.Fname)
		outputs_files[el.Fname] = false
	}
	nb_found := 0

	err = filepath.Walk(project_dir, func(path string, info os.FileInfo, err error) error {
		var base string = filepath.Base(path)
		base_found, has_base := outputs_files[base]
		if has_base {
			if base_found {
				return fmt.Errorf("output file found multiple times: %s [fullpath: %s]", base, path)
			}
			logger.Info().Msgf("[make] Found file in project directory: fname = %s, path = %s", base, path)
			outputs_files[base] = true

			// Modify the output artifact directory to point to this directory so that the static link step knows the right directory
			// to link from.
			for _, artifact := range bss.outputs {
				if base == artifact.Fname {
					artifact.Dir = filepath.Dir(path)
					break
				}
			}
			nb_found++
		}
		if nb_found == len(outputs_files) {
			// All artifacts found, do not need to continue walking the directory.
			return io.EOF
		}
		return nil
	})

	if err != nil && err != io.EOF {
		return nil, err
	}
	if nb_found != len(outputs_files) {
		var not_found string = ""
		for outfile, found := range outputs_files {
			if !found {
				not_found = fmt.Sprintf("%s %s", not_found, outfile)
			}
		}
		logger.Info().Msgf("Failed to find artifacts: %s", not_found)
		return nil, fmt.Errorf("failed to find following output files: %s", not_found)
	}

	// Any include directory should be added as an artifact so that it can be added to the upstream
	// compile commands.
	for _, relative_include_dir := range bs.target_config.IncludeDirs {
		full_include_dir := filepath.Join(project_dir, relative_include_dir)
		logger.Info().Msgf("Adding include path as artifact: %s", full_include_dir)
		bss.outputs = append(bss.outputs, &Artifact{IncludeDir: full_include_dir})
	}
	return nil, nil
}
