package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPullGitAction(t *testing.T) {
	var github_repo string = "https://github.com/omen23/ffmpeg-ffnvcodec-explanation.git"
	var hash string = "df88b76854a258b8f76b15ba9db2ffc43a08f1b0"

	outdir, err := os.MkdirTemp("", "git-pull-action")
	require.NoError(t, err)
	defer func() {
		fmt.Printf("Cleaning up temp dir: %s\n", outdir)
		os.RemoveAll(outdir)
	}()

	bss := BuildSubStep{
		inputs:  []*Artifact{{Url: github_repo, Fname: hash}},
		outputs: []*Artifact{{Dir: outdir}},
	}
	bs := BuildStep{
		steps: &bss,
	}

	stderr, err := pull_git_action(&bs, &bss, nil)
	assert.Nil(t, stderr, stderr.String())
	assert.NoError(t, err)
}
