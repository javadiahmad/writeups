---
title:  Teaser Dragon CTF
date:  2018-09-30
tags:
  - C
categories:
  - Writeups
excerpt: "production only"
---


# Pwn

## Production

Source code:

```cpp
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <unistd.h>

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace globals {
  std::vector<int> records;
}  // namespace globals

static void set_limits() {
  struct rlimit rlim;

  rlim.rlim_cur = rlim.rlim_max = 0;
  setrlimit(RLIMIT_CORE, &rlim);
  
  rlim.rlim_cur = rlim.rlim_max = 2;
  setrlimit(RLIMIT_CPU, &rlim);

  rlim.rlim_cur = rlim.rlim_max = 64 * 1024;
  setrlimit(RLIMIT_FSIZE, &rlim);

  rlim.rlim_cur = rlim.rlim_max = 32;
  setrlimit(RLIMIT_NOFILE, &rlim);
}

static void welcome() {
  printf("Welcome to the Lyrics Explorer!\n");
}

static ssize_t read_line(int fd, char *buffer, size_t size) {
  ssize_t bytes_read = 0;
  while (size > 0) {
    char c;
    ssize_t ret = read(fd, &c, 1);

    if (ret <= 0) {
      break;
    } else if (c == '\n') {
      *buffer = '\0';
      break;
    }

    *buffer++ = c;
    bytes_read++;
    size--;
  }

  return bytes_read;
}

static ssize_t read_line_buffered(int fd, char *buffer, size_t size) {
  if (size == 0) {
    return -1;
  }

  ssize_t ret = read(fd, buffer, size - 1);

  if (ret <= 0) {
    return ret;
  }

  buffer[ret] = '\0';

  for (ssize_t i = 0; i < ret; i++) {
    if (buffer[i] == '\0') {
      buffer[i] = '.';
    } else if (buffer[i] == '\n') {
      buffer[i] = '\0';
      lseek(fd, -(ret - i - 1), SEEK_CUR);
      return i;
    }
  }

  return ret;
}

static int load_int() {
  char buffer[32] = { 0 };
  
  ssize_t bytes_read = read_line(STDIN_FILENO, buffer, sizeof(buffer));
  if (bytes_read <= 0) {
    return 0;
  }

  return atoi(buffer);
}

static bool sanitize_path(char *buffer) {
  if (strstr(buffer, "../") != NULL) {
    return false;
  }

  return true;
}

static bool list_files(const char *path, std::vector<std::string> *files) {
  files->clear();

  DIR *dir;
  struct dirent *ent;
  if ((dir = opendir (path)) != NULL) {
    while ((ent = readdir (dir)) != NULL) {
      if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
        continue;
      }

      files->push_back(ent->d_name);
    }
    closedir (dir);
    return true;
  } else {
    perror ("[-] Error");
    return false;
  }
}

static bool list_bands() {
  std::vector<std::string> bands;
  if (!list_files("./data", &bands)) {
    return false;
  }

  for (const auto& band : bands) {
    printf("%s\n", band.c_str());
  }

  return true;
}

static bool list_songs() {
  char buffer[32] = { /* zero padding */ };

  printf("Band: ");
  read_line(STDIN_FILENO, buffer, sizeof(buffer));

  // Never trust user input!!
  if (!sanitize_path(buffer)) {
    printf("[-] Nice try!\n");
    return false;
  }

  char path[48] = "./data/";
  strncat(path, buffer, sizeof(path) - 7);

  std::vector<std::string> songs;
  if (!list_files(path, &songs)) {
    return false;
  }

  for (const auto& song : songs) {
    printf("%s\n", song.c_str());
  }

  return true;
}

static bool open_lyrics() {
  // Don't allow opening too many lyrics at once.
  if (globals::records.size() >= 16) {
    return false;
  }

  // Load and sanitize user input.
  char band[32];
  printf("Band: ");
  read_line(STDIN_FILENO, band, sizeof(band));

  char song[32];
  printf("Song: ");
  read_line(STDIN_FILENO, song, sizeof(song));

  // Hackers these days...
  if (!sanitize_path(band) || !sanitize_path(song)) {
    printf("[-] Nice try!\n");
    return false;
  }

  // Form the final path of the lyrics in our database.
  char path[128];
  snprintf(path, sizeof(path), "./data/%s/%s", band, song);

  // Open the path, make sure that it's a file (and not e.g. directory), and
  // save the file descriptor.
  int fd1 = open(path, O_RDONLY);
  if (fd1 == -1) {
    return false;
  }

  struct stat st;
  if (fstat(fd1, &st) != 0 || !S_ISREG(st.st_mode)) {
    return false;
  }

  globals::records.push_back(fd1);

  // Better safe then sorry. Make sure that the path also doesn't point to a
  // symbolic link.
  int fd2 = open(path, O_RDONLY | O_NOFOLLOW);
  if (fd2 == -1) {
    printf("[-] Detected attempt to open a symbolic link!\n");

    // Some kind of attack detected?
    return true;
  }
  close(fd2);

  // Extra check to protect the flag.
  if (strstr(path, "flag") != NULL) {
    printf("[-] Not today\n");

    close(globals::records.back());
    globals::records.pop_back();
    return false;
  }

  printf("[+] Opened the lyrics as new record %zu\n",
         globals::records.size() - 1);

  return true;
}

static bool read_lyrics() {
  printf("Record ID: ");
  int idx = load_int();

  if (idx < 0 || idx >= globals::records.size()) {
    return false;
  }

  char buffer[4096];
  ssize_t bytes_read = read_line_buffered(globals::records[idx],
                                          buffer, sizeof(buffer));

  // Let's make sure we're not disclosing any sensitive data due to potential
  // bugs in the program.
  if (bytes_read > 0) {
    if (strstr(buffer, "DrgnS")) {
      printf("[-] Attack detected and stopped!\n");

      assert(close(globals::records[idx]) == 0);
      memmove(&globals::records[idx], &globals::records[idx + 1],
              (globals::records.size() - idx - 1) * sizeof(int));
      globals::records.pop_back();
      return true;
    }
  }

  printf("%s\n", buffer);
  return true;
}

static bool write_lyrics() {
  // This feature is not fully tested, let's hope that it works...

  printf("Record ID: ");
  int idx = load_int();

  if (idx < 0 || idx >= globals::records.size()) {
    return false;
  }

  printf("Data length: ");
  int length = load_int();

  if (length < 0 || length > 1024) {
    return false;
  }

  char buffer[1024];
  printf("Data: ");
  size_t bytes_read = read(STDIN_FILENO, buffer, length);

  assert(bytes_read == length);

  if (write(globals::records[idx], buffer, bytes_read) != bytes_read) {
    return false;
  }

  return true;
}

static bool close_record() {
  printf("Record ID: ");
  int idx = load_int();

  if (idx < 0 || idx >= globals::records.size()) {
    return false;
  }

  close(globals::records[idx]);
  memmove(&globals::records[idx], &globals::records[idx + 1],
          (globals::records.size() - idx - 1) * sizeof(int));
  globals::records.pop_back();

  return true;
}

int main() {
  // Disable stdout/stderr buffering.
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  // Set some safe limits on the resources used by the process.
  set_limits();

  // Print the welcome message.
  welcome();

  // Main program loop.
  while (1) {
    char buffer[32] = { 0 };

    printf("Command> ");
    read_line(STDIN_FILENO, buffer, sizeof(buffer));

    if (!strcmp(buffer, "bands")) {
      if (!list_bands()) {
        break;
      }
    } else if (!strcmp(buffer, "songs")) {
      if (!list_songs()) {
        break;
      }
    } else if (!strcmp(buffer, "open")) {
      if (!open_lyrics()) {
        break;
      }
    } else if (!strcmp(buffer, "read")) {
      if (!read_lyrics()) {
        break;
      }
    } else if (!strcmp(buffer, "write")) {
      if (!write_lyrics()) {
        break;
      }
    } else if (!strcmp(buffer, "close")) {
      if (!close_record()) {
        break;
      }
    } else if (!strcmp(buffer, "exit")) {
      break;
    } else {
      printf("[-] Unknown command\n");
      break;
    }
  }

  printf("Bye!\n");

  return 0;
}
```

THe first interesting point is about `sanitize_path`, which sanitizes `../` to prevent file traverse. However, it does not prevent `..`. We can use `..` to list previous directory:
```
Command> songs
Band: ..
lyrics
data
lyrics.cc
flag
```

We cannot find any bugs in source code then. But as the title reminds us (`Production`). The production level program might not be exactly the same as the source code. After a few testing, we can find that the server does not have `assert` statement.

Now we still have two problems. The first one is how to open flag since it contains **DrgnS**. And the second one is how to open flag file while `if (strstr(path, "flag") != NULL)`. 


### Open Bypass

When the binary detects **Drgns**, the program will skip rather than close it. The program uses `setrlimit(RLIMIT_NOFILE, &rlim);` to restrict to maximum of opening file to 32. Since **lyrics** executable file in `../` directory must contain `Drgns` string, we can trigger the bug but reading the executable.

Now, let's look at `open_lyrics` function. It has a logic bug - it will check paths once and then open a file once and put the `fd` into `records`. But then it will open the file again before checking the flag. If we manage a way to prevent open the second opening, we can bypass the check.
```c
  int fd1 = open(path, O_RDONLY);
  if (fd1 == -1) {
    return false;
  }
  struct stat st;
  if (fstat(fd1, &st) != 0 || !S_ISREG(st.st_mode)) {
    return false;
  }
  globals::records.push_back(fd1);
  int fd2 = open(path, O_RDONLY | O_NOFOLLOW);
  if (fd2 == -1) {
    printf("[-] Detected attempt to open a symbolic link!\n");
    return true;
  }
  close(fd2);
  if (strstr(path, "flag") != NULL) {
    printf("[-] Not today\n");

    close(globals::records.back());
    globals::records.pop_back();
    return false;
  }
```

Let's open 31 files then call the functiom. The first steps will turn the `fd` to **32**. Then, the second `open` to check symlinks will fail since we execeed the maxinum of `fd`. It means that we can bypass flag check.

### Read Bypass

We can open a song first. Then, we read it until last line. Then, we read the `flag` file. Flag will be loaded to `buffer`. Since it contains `DrgnS`, the function will return and do not print buffer. We read the previous song again. Since `bytes_read`  equals to 0, the `read_line_buffered` will not change buffer to other content (it keeps the flag content). Also, `if (bytes_read > 0) {` will skips the content check and print our buffer directly.

No script cause I test it manually for hours.

## Fast Storage

TODO...