# gwatch
Tracing read/write accesses to global variable. Work only for **linux/ARM64**. <br>
`testBinary` - contains test binary sources. 

## Setup
The best way to run this application is to use Docker.

### Build
```bash
  docker build -t gwatch-runner . 
```
### Run
```bash
  docker run --rm gwatch-runner ./gwatch --var variable --exec /gwatch/build/TestAppVariableAccess
```

## gwatch manual
You can obtain it manually by running:
```bash
  docker run --rm gwatch-runner ./gwatch -h 
```
### Allowed options:
```
-h [ --help ]         Show help message 
--var arg             Variable name 
--exec arg            Executable path

('-- arg1 arg2 ... argn' to pass n arguments to executable)
Example:
  ./gwatch --var variable --exec /gwatch/build/TestAppVariableAccess -- arg1 arg2
```
