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
		panic(fmt.Sprintf("expected only 1 input for git-pull action, received %d", len(bss.inputs)))
	}
	if len(bss.outputs) != 1 {
		panic(fmt.Sprintf("expected only 1 output for git-pull action, received %d", len(bss.outputs)))
	}

	var outdir_artifact *DirectoryArtifact
	var git_artifact *GitInputArtifact

	git_artifact, is_ga := bss.inputs[0].Get().(*GitInputArtifact)
	if !is_ga {
		panic("Expected inputs[0] to be a git input artifact")
	}
	outdir_artifact, is_da := bss.outputs[0].Get().(*DirectoryArtifact)
	if !is_da {
		panic("Expected outputs[0] to be a directory artifact")
	}

	// TODO(0000mz): If the repo is already downloaded, skip pulling it again.
	if _, err := os.Stat(outdir_artifact.Dir); err == nil {
		err := os.RemoveAll(outdir_artifact.Dir)
		if err != nil {
			return nil, err
		}
	}

	stdout, stderr, err := run_command([]string{"git", "clone", git_artifact.Url, outdir_artifact.Dir})
	if err != nil {
		return stderr, err
	}

	logger.Debug().Msgf("Stdout command output: %s", string(stdout))

	_, stderr, err = run_command_dir([]string{"git", "checkout", git_artifact.Hash}, outdir_artifact.Dir)
	if err != nil {
		return stderr, err
	}
	return nil, nil
}

type BuildConfigType int

const (
	Buildconfig_Undefined BuildConfigType = 0
	BuildConfig_Make      BuildConfigType = 1
	BuildConfig_CMake     BuildConfigType = 2
	BuildConfig_HdrOnly   BuildConfigType = 3
)

func get_external_build_config_type(config_name string) (BuildConfigType, error) {
	switch config_name {
	case "make":
		return BuildConfig_Make, nil
	case "cmake":
		return BuildConfig_CMake, nil
	case "headeronly":
		return BuildConfig_HdrOnly, nil
	}
	return Buildconfig_Undefined, fmt.Errorf("unknown external build config type: %s", config_name)
}

// External build step used for building projects with for the specific type: i.e. make, configure-make, etc...
// @params
//   - [0] project directory: The root directory path of the project that needs to be built.
var external_build_steps = map[BuildConfigType]func(project_dir string, bs *BuildStep, bss *BuildSubStep, dc *DoContext) (*bytes.Buffer, error){
	BuildConfig_Make:    run_make_action,
	BuildConfig_CMake:   run_cmake_action,
	BuildConfig_HdrOnly: run_headeronly_action,
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
	for _, artifact := range bss.outputs {
		vague_file, is_vfa := artifact.Get().(*VagueFileArtifact)
		if is_vfa {
			logger.Debug().Msgf("Expecting file to be produced from \"make\": %s", vague_file.Fname)
			outputs_files[vague_file.Fname] = false
		}
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
				vfa, is_vfa := artifact.Get().(*VagueFileArtifact)
				if is_vfa && vfa.Fname == base {
					vfa.PromoteAndReplace(filepath.Dir(path), artifact)
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
	set_include_dirs(project_dir, bs, bss)
	return nil, nil
}

func run_cmake_action(project_dir string, bs *BuildStep, bss *BuildSubStep, dc *DoContext) (*bytes.Buffer, error) {
	return nil, fmt.Errorf("unimpl")
}

func run_headeronly_action(project_dir string, bs *BuildStep, bss *BuildSubStep, dc *DoContext) (*bytes.Buffer, error) {
	set_include_dirs(project_dir, bs, bss)
	return nil, nil
}

func set_include_dirs(project_dir string, bs *BuildStep, bss *BuildSubStep) {
	for _, relative_include_dir := range bs.target_config.IncludeDirs {
		full_include_dir := filepath.Join(project_dir, relative_include_dir)
		logger.Info().Msgf("Adding include path as artifact: %s", full_include_dir)
		bss.outputs = append(bss.outputs, create_directory_artifact(full_include_dir))
	}
}
