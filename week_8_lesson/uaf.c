#include "stdio.h"
#include "stdlib.h"
#include "unistd.h"
#include "string.h"
#include "stdbool.h"

struct user {
    long long uid;
    long long gid;
    char* name;
    char* group;
    char* bio;
};

bool logged_in = false;
struct user* u;

void edit();
void delete();

void new() {
    if (logged_in) {
        free(u->name);
        free(u->group);
        free(u);
    }
    if (!u) { u = malloc(sizeof(struct user)); }
    u->bio = malloc(0x480);
    u->group = malloc(0x10);
    u->name = malloc(0x10);
    edit();
    logged_in = true;
}

void edit() {
    if (u) {
        puts("Enter a name:");
        fgets(u->name, 0x10, stdin);
        char* c = strchr(u->name, '\n');
        if (c) { *c = '\0'; }
        puts("Enter a group:");
        fgets(u->group, 0x10, stdin);
        c = strchr(u->group, '\n');
        if (c) { *c = '\0'; }
        puts("Enter a uid:");
        char buf[0x10];
        fgets(buf, 0x10, stdin);
        u->uid = strtoll(buf, NULL, 10);
        puts("Enter a gid:");
        buf[0x10];
        fgets(buf, 0x10, stdin);
        u->gid = strtoll(buf, NULL, 10);
        puts("Enter a bio:");
        fgets(u->bio, 0x480, stdin);
        c = strchr(u->bio, '\n');
        if (c) { *c = '\0'; }
    } else {
        puts("No current user");
    }
}

void print() {
    if (u) {
        printf("User: %s, group: %s, uid: %lld, gid: %lld\nBio: %s",
            u->name, u->group, u->uid, u->gid, u->bio);
    } else {
        puts("No current user");
    }
}

void delete() {
    if (u) {
        free(u->bio);
        free(u->group);
        free(u->name);
        free(u);
    } else {
        puts("No current user");
    }
    logged_in = false;
}

long menu() {
    puts("Please enter an option:");
    puts(" 1. New user");
    puts(" 2. Edit user");
    puts(" 3. Print user");
    puts(" 4. Delete user");
    printf(" > ");
    fflush(stdout);
    char buf[0x10];
    fgets(buf, 0x10, stdin);
    return strtol(buf, NULL, 10);
}
int main() {
    setvbuf(stderr, NULL, _IOLBF, 0);
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stdin, NULL, _IOLBF, 0);
    while (1) {
        long choice = menu();
        switch (choice) {
        case 1:
            new();
            break;
        case 2:
            edit();
            break;
        case 3:
            print();
            break;
        case 4:
            delete();
            break;
        default:
            break;
        }
    }
    return 0;
}
