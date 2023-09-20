# Skiddyana Pwnz and the Loom of Fate
## Code overview
The challenge provides us with a binary file. After i put it into IDA, i got some functions here

First, we have `main`:

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char s1[32]; // [rsp+0h] [rbp-240h] BYREF
  char v4[516]; // [rsp+20h] [rbp-220h] BYREF
  char s[8]; // [rsp+224h] [rbp-1Ch] BYREF
  int v6; // [rsp+22Ch] [rbp-14h]
  char *s2; // [rsp+230h] [rbp-10h]
  char *v8; // [rsp+238h] [rbp-8h]

  s2 = "thisisnotthepassword";
  v8 = "Drink your ovaltine";
  printf("\x1B[0;33m");
  printf(
    "  ____  _    _     _     _                           ____                     \n"
    " / ___|| | _(_) __| | __| |_   _  __ _ _ __   __ _  |  _ \\__      ___ __  ____\n"
    " \\___ \\| |/ / |/ _` |/ _` | | | |/ _` | '_ \\ / _` | | |_) \\ \\ /\\ / / '_ \\|_  /\n"
    "  ___) |   <| | (_| | (_| | |_| | (_| | | | | (_| | |  __/ \\ V  V /| | | |/ / \n"
    " |____/|_|\\_\\_|\\__,_|\\__,_|\\__, |\\__,_|_| |_|\\__,_| |_|     \\_/\\_/ |_| |_/___|\n"
    "                           |___/                                              \n"
    "                                 _   _   _                                    \n"
    "                  __ _ _ __   __| | | |_| |__   ___                           \n"
    "                 / _` | '_ \\ / _` | | __| '_ \\ / _ \\                          \n"
    "                | (_| | | | | (_| | | |_| | | |  __/                          \n"
    "                 \\__,_|_| |_|\\__,_|  \\__|_| |_|\\___|                          \n"
    "                                                                              \n"
    "     _                                   __   _____     _                     \n"
    "    | |    ___   ___  _ __ ___     ___  / _| |  ___|_ _| |_ ___               \n"
    "    | |   / _ \\ / _ \\| '_ ` _ \\   / _ \\| |_  | |_ / _` | __/ _ \\              \n"
    "    | |__| (_) | (_) | | | | | | | (_) |  _| |  _| (_| | ||  __/              \n"
    "    |_____\\___/ \\___/|_| |_| |_|  \\___/|_|   |_|  \\__,_|\\__\\___|              \n"
    "     ");
  printf("\x1B[0m");
  putchar(10);
  while ( 1 )
  {
    while ( 1 )
    {
      printf("\n\n=============================================================================");
      printf(
        "\n"
        "Choose your next move:\n"
        "\n"
        "1) Enter the room of the loom\n"
        "2) Read the wall of prophecy\n"
        "3) Enter the room of the fates\n"
        "4) leave\n"
        "\n"
        "> ");
      fgets(s, 8, _bss_start);
      v6 = atoi(s);
      if ( v6 != 1 )
        break;
      v8 = loomRoom(v8, v4);
    }
    switch ( v6 )
    {
      case 2:
        puts("\n\nYou look to the grand wall in front of you.\nA prophecy is etched into the stone and looks ancient : \n");
        printf("%s", v8);
        putchar(10);
        break;
      case 3:
        puts("\n\nBefore you is a large stone door. As you behold it, you hear a voice inside of your head.");
        printf("\n\nSpeak the unpronouncable phrase to pass to the room of fates : \n\n> ");
        fgets(s1, 26, _bss_start);
        s1[strlen(s1) - 1] = 0;
        if ( !strcmp(s1, s2) )
          fatesRoom(v8);
        else
          puts("\nThe door does not open, the voice is silent.");
        break;
      case 4:
        exit(0);
      default:
        puts("\nYou get confused and try to walk in a direction that doesn't exist. It doesn't work.");
        break;
    }
  }
}
```
The program will print out a menu. If we choose 1 it call `loomRoom` function (i will explaint it later ). 2 to read content stored in `v8` (v8 is an address containing the content we entered in `loomroom`). 3 to call `fateRoom` and 4 to exit.

Next to `loomRoom`:
```c
char *__fastcall loomRoom(char *a1, char *a2)
{
  char src[8]; // [rsp+10h] [rbp-120h] BYREF
  __int64 v4[31]; // [rsp+18h] [rbp-118h] BYREF
  char s[8]; // [rsp+11Ch] [rbp-14h] BYREF
  int v6; // [rsp+124h] [rbp-Ch]
  char *dest; // [rsp+128h] [rbp-8h]

  dest = a1;
  *(_QWORD *)src = 0LL;
  memset(v4, 0, sizeof(v4));
  puts("\n\n=============================================================================\n");
  printf(
    "You enter the room of the loom, and see the loom of fate before you. You can etch a prophecy into the futre, or leav"
    "e the future alone.\n"
    "1) Prophesize\n"
    "2) Leave\n"
    "\n"
    "> ");
  fgets(s, 8, _bss_start);
  v6 = atoi(s);
  if ( v6 == 1 )
  {
    fgets(src, 0x11E, _bss_start);
    if ( strlen(src) <= 0x100 )
    {
      dest = a2;
      strcpy(a2, src);
    }
    else
    {
      puts("\nWhoa whoa, slow down, that's too much prophecy. Life needs some mystery.");
    }
  }
  return dest;
}
``` 