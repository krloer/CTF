#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

const char* win()
{
    char flag_buf[0x100];
    int fd = open("flag.txt", O_RDONLY);
    if (fd > 0)
        read(fd, flag_buf, 0x100);
    else
        puts("You made it! Unfortunately the flag file couldn't be opened. Please contact an Admin!");
    return strdup(flag_buf);
}

class Animal
{
    public:
    virtual const char* GetSpecies() = 0;

    int m_dataLength = 0;
    char* m_data;
};

Animal* rooms[8];

class Cat : public Animal
{
    public:
    const char* GetSpecies() override
    {
        return "Cat";
    }
};

class Dog : public Animal
{
    public:
    const char* GetSpecies() override
    {
        return "Dog";
    }
};

void alarmen_gikk(int sig)
{
    if (sig == SIGALRM)
        _exit(0);
}

void init()
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stdin, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    signal(SIGALRM, alarmen_gikk);
    alarm(60);
}

void menu()
{
    puts("Welcome to Cyberlandslaget Pet Hotel");
    puts("1. Check in");
    puts("2. Register data");
    puts("3. Show registration");
    puts("4. Delete data");
    puts("5. Exit");
    printf("> ");
}

int getInt()
{
    char buffy[8];
    fgets(buffy, 8, stdin);
    return atoi(buffy);
}

int ChooseRoom()
{
    puts("Choose Room no. (0-7)");
    printf("> ");
    int roomNo = getInt();
    if (roomNo < 0 || roomNo > 7)
    {
        puts("That room doesn't exist!");
        return -1;
    }
    return roomNo;
}

void CheckIn()
{
    int roomNo = ChooseRoom();
    if (roomNo < 0)
        return;

    puts("What kind of pet do you have?");
    puts("1. Cat");
    puts("2. Dog");
    printf("> ");
    int choice = getInt();
    switch(choice)
    {
        default:
            puts("Sorry! Not supported!");
            return;
        case 1:
            rooms[roomNo] = new Cat();
            break;
        case 2:
            rooms[roomNo] = new Dog();
            break;
    }

}

void RegisterData()
{
    int roomNo = ChooseRoom();
    if (rooms[roomNo] == nullptr)
        return;

    if (rooms[roomNo]->m_data == nullptr)
    {
        puts("Length of data:");
        printf("> ");
        int dataLength = getInt();
        if (dataLength < 0 || dataLength > 255)
        {
            puts("Requested size out of bounds!");
            return;
        }

        rooms[roomNo]->m_dataLength = dataLength;
        rooms[roomNo]->m_data = (char*)malloc(dataLength);
    }

    puts("Enter data:");
    printf("> ");
    fgets(rooms[roomNo]->m_data, rooms[roomNo]->m_dataLength, stdin);
}

void ViewRoom()
{
    int roomNo = ChooseRoom();
    if (roomNo < 0)
        return;

    const char* species = rooms[roomNo]->GetSpecies();

    printf("In room no. %d there currently lives a %s.\n", roomNo, species);
    if (rooms[roomNo]->m_data != nullptr)
    {
        puts("We have registered the following data on the guest:");
        puts(rooms[roomNo]->m_data);
    }
}

void DeleteData()
{
    int roomNo = ChooseRoom();
    if (rooms[roomNo] == nullptr)
        return;

    free(rooms[roomNo]->m_data);
}

int main(int, char**)
{
    int choice = 0;
    init();
    while(true)
    {
        menu();
        choice = getInt();
        switch(choice)
        {
            default:
                puts("Invalid choice!");
                break;
            case 1:
                CheckIn();
                break;
            case 2:
                RegisterData();
                break;
            case 3:
                ViewRoom();
                break;
            case 4:
                DeleteData();
                break;
            case 5:
                exit(0);
        }
    }
}

