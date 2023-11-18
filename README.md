# do - c builder

This project can be used for building your c targets and run tests.
`do` uses TOML config file for configuring targets.

## Configuring Build Target
```toml
[Targets.my_lib]
Type = "static"
Srcs = ["my_lib.c"]
Hdrs = ["my_lib.h"]

[Targets.my_bin]
Type = "binary"
Srcs = ["main.c"]
Deps = ["my_lib"] # Add the library above as a dependency
```

Running `do build my_bin` will first build `my_lib` and then build `my_bin`, linking the
output of `my_lib` with it.

`do` constructs a build tree, and builds all the dependencies in parallel and handles caching
of artifacts.`

### Roadmap
- Import and build external dependencies that are configured with CMake, Make and Configure Make.
- Create test runner.