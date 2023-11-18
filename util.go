package main

import (
	"bytes"
	"fmt"
	"os/exec"

	"github.com/google/uuid"
)

// Run the command specified by the `command_lst`.
// If `dir` is a non-empty string, the command ill be executed from that directory.
// @return
//   - [0] stdout of command
//   - [1] stderr of command
//   - [2] error received from running the command
func run_command(command_lst []string) ([]byte, *bytes.Buffer, error) {
	return run_command_dir(command_lst, "")
}

func run_command_dir(command_lst []string, dir string) ([]byte, *bytes.Buffer, error) {
	if len(command_lst) == 0 {
		return nil, nil, fmt.Errorf("no commands provided")
	}

	var stderr bytes.Buffer
	excmd := exec.Command(command_lst[0], command_lst[1:]...)
	excmd.Stderr = &stderr
	if len(dir) > 0 {
		excmd.Dir = dir
	}

	stdout, err := excmd.Output()
	if err != nil {
		return stdout, &stderr, err
	}
	return stdout, nil, nil
}

func make_unique_id() string {
	return uuid.New().String()
}
