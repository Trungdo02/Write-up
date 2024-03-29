#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define FEED_OPTION 1
#define VIEW_OPTION 2
#define QUIT_OPTION 3
#define MAX_NAME_LEN 16
#define BIN_COUNT 10
#define BIN_SIZE 4
#define FLAG_SQUIRREL_NAME "santa"

// Structs

typedef struct map_entry {
    char name[16];
    size_t weight;
} map_entry;

typedef struct map_data {
    size_t bin_sizes[10];
    map_entry bins[10][4];
} map_data; 

typedef struct map {
    map_data *data;
    map_data local;
} map;

// Globals

map flag_map = {0};

// Functions

size_t hash_string(char *string) {
    size_t hash = 0;
    size_t len = strlen(string);
    if (len > 16)
        return 0;

    for (size_t i = 0; i < len; i++) {
        hash += string[i] * 31;
    }
    return hash;
}

void get_max_weight(map *m, char *key) {
    // TODO: implement
    // I figured I would just leave the stub in!
}

/*
tạo flag với hash key là santa
*/

void increment(map *m, char *key, size_t amount) {
    size_t hash = hash_string(key);
    if (hash == 0)
        return;

    size_t index = hash % 10;

    for (size_t i = 0; i <= 10; i++) {
        map_entry *entry = &m->data->bins[index][i];

        // Increment existing   
        if (strncmp(entry->name, key, 16) == 0) {
            entry->weight += amount;
            printf("Squirrel %s has weight %zu lbs\n", entry->name, entry->weight);
            return;
        }

        // Create newx  
        if (i == m->data->bin_sizes[index]) {
            strncpy(entry->name, key, 16);
            entry->weight += amount;
            if (key != "santa") printf("New squirrel %s has weight %zu lbs\n", entry->name, entry->weight);
            m->data->bin_sizes[index]++;
            // TODO: enforce that new weight does not exceed the "presidential chonk!"
            get_max_weight(&flag_map, "santa");
            return;
        }
    }
}

void print(map *map, char *key) {
    size_t hash = hash_string(key);
    if (hash == 0)
        return;

    size_t index = hash % 10;

    for (size_t i = 0; i < map->data->bin_sizes[index]; i++) {
        map_entry *entry = &map->data->bins[index][i];

        if (strncmp(entry->name, key, 16) != 0) continue;

        printf("Squirrel %s has weight %zu lbs\n", entry->name, entry->weight);
        return;
    }
}

void init_flag_map() {
    FILE *flag_file = fopen("flag.txt", "r");
    if (flag_file == NULL) {
        puts("File not found!");
        exit(1);
    }

    char flag_text[0x100];
    fgets(flag_text, sizeof(flag_text), flag_file);
    long flag_weight = strtol(flag_text, NULL, 10);

    flag_map.data = &flag_map.local;
    increment(&flag_map, "santa", flag_weight);

    fclose(flag_file);
}

size_t i = 0;
long option = 0;
char *end_ptr = NULL;
char option_input[0x8] = {0};
char name_input[16] = {0};

void loop() {
    map m = {0};
    m.data = &m.local;

    while (i < 5) {
        puts("==============================");
        puts("What would you like to do?");
        puts("1. Feed your favorite squirrel");
        puts("2. View squirrel weight");
        puts("3. Quit");
        fputs("> ", stdout);

        fgets(option_input, sizeof(option_input), stdin);
        option = strtol(option_input, &end_ptr, 10);
        if (errno) {    
            puts("Invalid option!");
            continue;
        }

        if (option == 1) {
            ++i;

            fputs("Enter their name: ", stdout);
            fgets(name_input, sizeof(name_input), stdin);

            fputs("Enter the amount to feed them: ", stdout);
            fgets(option_input, sizeof(option_input), stdin);
            option = strtol(option_input, &end_ptr, 10);
            if (errno) {
                puts("Invalid option!");
                continue;
            }

            increment(&m, name_input, option);

        } else if (option == 2) {
            fputs("Enter their name: ", stdout);

            fgets(name_input, sizeof(name_input), stdin);

            print(&m, name_input);

        } else if (option == 3) {
            break;

        } else {
            puts("Invalid option!");
        }
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    puts("Welcome to the Michigan squirrel feeding simulator!");

    init_flag_map();

    loop();
}
