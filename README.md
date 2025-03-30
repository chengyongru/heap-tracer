# Heap tracer

## dependency

```sh
sudo apt install libbsd-dev libunwind-dev
```

## compile
```
mkdir build && cd build && cmake ..
```

## use
Run the executable with: `LD_PRELOAD=PATH/TO/libmalloc.so ./myexecutable`

or in GDB with: `set exec-wrapper env 'LD_PRELOAD=./libmalloc.so'`

## output -> stderr

### malloc
```
[malloc] id=0, rea_size=72712, alloc_size=72704, [0x5555555592a0-0x55555556aea8]
```
### free
```
[ free ] id=7
```
