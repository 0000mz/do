package main

import (
	"bytes"
	"fmt"
	"os"
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

	fmt.Printf("Make command succeeded for %s, TODO: Check make output", project_dir)
	return nil, nil
}
