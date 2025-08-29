# App-Launcher

Helper app for TheCube CORE that launches apps with optional Landlock sandboxing.

## Features

- Connects to the CORE daemon over a Unix domain socket to fetch an application's
  launch specification.
- Applies Landlock rules to restrict filesystem access before executing the
  application.
- Parses JSON messages using [nlohmann/json](https://github.com/nlohmann/json).

## Building

The project uses CMake and requires a C++17 compiler. On Debian/Ubuntu systems
install the dependencies with:

```bash
apt-get update && apt-get install -y build-essential cmake nlohmann-json3-dev
```

Then build the binary:

```bash
cmake -S . -B build
cmake --build build
```

The executable will be placed in `build/app-launcher`.

## Usage

```
./app-launcher --app <id> [--no-landlock] [--trace]
```

- `--app <id>`: Identifier of the application to launch (required).
- `--no-landlock`: Disable Landlock sandboxing even if supported.
- `--trace`: Log extra information about the launch process.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

