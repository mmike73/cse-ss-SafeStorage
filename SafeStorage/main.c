#include "includes.h"
#include "Commands.h"


/*
 * @brief       You must not modify this file or this project (SafeStorage).
 *              All changes made to this file should only be for testing that you have fixed all vulnerabilities.
 *
 *              Your main responsibility will be to implement the missing functionality in SafeStorageLib.
 *              All new files will be created in the SafeStorageLib project.
 *
 *              In this file, you must identify all vulnerabilities.
 *              A file named "vulnerabilities.txt" will be delivered alongside the project.
 *              The file will list the identified vulnerabilities, the line(s) where they are found, their impact, and how to fix them.
 *
 * @note        For bonus points, you can use SAL: https://learn.microsoft.com/en-us/cpp/code-quality/understanding-sal?view=msvc-170
 *              To run SAL: right-click on the entire solution Solution 'SafeStorage' (2 of 2 projects),
 *                          go to "Analyze and Code Cleanup",
 *                          and select "Run Code Analysis on Solution."
 *              You can add SAL annotations to all functions (both existing ones and those you will create).
 *
 * @note        FIXES (vulnerabilities.txt V-01..V-12):
 *              - bounded token reader replaces all unbounded scanf("%s");
 *              - EOF/oversized input no longer spins or reuses stale arguments;
 *              - passwords are no longer printed and are wiped after use;
 *              - handler statuses are checked and reported;
 *              - string comparison and uint16_t conversions are checked.
 *              No command grammar or functional behaviour was changed.
 */

typedef enum _SS_READ_RESULT
{
    SS_READ_OK = 1,
    SS_READ_EOF = 0,
    SS_READ_TOO_LONG = -1,
    SS_READ_ERROR = -2
} SS_READ_RESULT;

static BOOL
IsSpaceCharacter(
    int Character
)
{
    return Character == ' ' || Character == '\t' || Character == '\r' ||
           Character == '\n' || Character == '\v' || Character == '\f';
}

/*
 * Read one whitespace-delimited token into Buffer.
 *
 * SECURITY (FIX V-01/V-02): never writes more than Cap-1 bytes. An overlong
 * token is fully drained and reported, so its tail cannot be parsed as a new
 * command (a classic scanf("%s") bypass). EOF is explicit, so the main loop
 * cannot spin forever (FIX V-05) or use uninitialized arguments
 * (FIX V-03/V-09).
 */
static SS_READ_RESULT
ReadToken(
    _Out_writes_(Cap) char* Buffer,
    _In_ size_t Cap
)
{
    int character;
    size_t length = 0;
    BOOL tooLong = FALSE;

    if (Buffer == NULL || Cap == 0)
    {
        return SS_READ_ERROR;
    }
    Buffer[0] = '\0';

    do
    {
        character = fgetc(stdin);
    } while (character != EOF && IsSpaceCharacter(character));

    if (character == EOF)
    {
        return ferror(stdin) ? SS_READ_ERROR : SS_READ_EOF;
    }

    while (character != EOF && !IsSpaceCharacter(character))
    {
        if (length + 1 < Cap)
        {
            Buffer[length] = (char)character;
            length++;
        }
        else
        {
            tooLong = TRUE;
        }
        character = fgetc(stdin);
    }

    Buffer[length] = '\0';

    if (tooLong)
    {
        return SS_READ_TOO_LONG;
    }

    return SS_READ_OK;
}

static uint16_t
Length16(
    _In_z_ const char* Text
)
{
    size_t length = strlen(Text);

    /* V-06: never silently truncate a size_t into a uint16_t. */
    if (length > (size_t)UINT16_MAX)
    {
        return UINT16_MAX;
    }
    return (uint16_t)length;
}

static void
ReportStatus(
    _In_z_ const char* Command,
    _In_ NTSTATUS Status
)
{
    if (NT_SUCCESS(Status))
    {
        printf("%s succeeded\r\n", Command);
    }
    else
    {
        printf("%s failed with status 0x%08x\r\n", Command,
               (unsigned int)Status);
    }
}

static void
PrintHelp()
{
    printf("Available commands:\r\n");
    printf("\t> register <username> <password>\r\n");
    printf("\t> login <username> <password>\r\n");
    printf("\t> logout\r\n");
    printf("\t> store <source file path> <submission name>\r\n");
    printf("\t> retrieve <submission name> <destination file path>\r\n");
    printf("\t> exit\r\n");
}

int CDECL
main(void)
{
    char command[10] = { 0 };
    char arg1[MAX_PATH] = { 0 };
    char arg2[MAX_PATH] = { 0 };

    NTSTATUS status = SafeStorageInit();
    if (!NT_SUCCESS(status))
    {
        printf("SafeStorageInit failed with status 0x%x \r\n",
               (unsigned int)status);
        return -1;
    }

    PrintHelp();
    for (;;)
    {
        SS_READ_RESULT readResult;

        printf("Enter your command: \r\n");
        readResult = ReadToken(command, sizeof(command));
        if (readResult == SS_READ_EOF)
        {
            printf("\r\n");
            break;
        }
        if (readResult != SS_READ_OK)
        {
            printf("Invalid or oversized input. Try again! \r\n");
            if (feof(stdin) || ferror(stdin))
            {
                break;
            }
            continue;
        }

        /* FIX V-08: exact, NUL-terminated comparison (no sizeof memcmp). */
        if (strcmp(command, "register") == 0)
        {
            if (ReadToken(arg1, sizeof(arg1)) != SS_READ_OK ||
                ReadToken(arg2, sizeof(arg2)) != SS_READ_OK)
            {
                printf("Invalid or oversized username/password. \r\n");
                if (feof(stdin) || ferror(stdin))
                {
                    break;
                }
                continue;
            }

            /* FIX V-04/V-10: never print the password; wipe it afterwards. */
            printf("register with username [%s] \r\n", arg1);
            status = SafeStorageHandleRegister(arg1, Length16(arg1),
                                               arg2, Length16(arg2));
            ReportStatus("register", status);
            SecureZeroMemory(arg2, sizeof(arg2));
        }
        else if (strcmp(command, "login") == 0)
        {
            if (ReadToken(arg1, sizeof(arg1)) != SS_READ_OK ||
                ReadToken(arg2, sizeof(arg2)) != SS_READ_OK)
            {
                printf("Invalid or oversized username/password. \r\n");
                if (feof(stdin) || ferror(stdin))
                {
                    break;
                }
                continue;
            }

            printf("login with username [%s] \r\n", arg1);
            status = SafeStorageHandleLogin(arg1, Length16(arg1),
                                            arg2, Length16(arg2));
            ReportStatus("login", status);
            SecureZeroMemory(arg2, sizeof(arg2));
        }
        else if (strcmp(command, "logout") == 0)
        {
            printf("logout \r\n");
            status = SafeStorageHandleLogout();
            ReportStatus("logout", status);
        }
        else if (strcmp(command, "store") == 0)
        {
            if (ReadToken(arg1, sizeof(arg1)) != SS_READ_OK ||
                ReadToken(arg2, sizeof(arg2)) != SS_READ_OK)
            {
                printf("Invalid or oversized paths. \r\n");
                if (feof(stdin) || ferror(stdin))
                {
                    break;
                }
                continue;
            }

            printf("store with source file path [%s] submission name [%s] \r\n",
                   arg1, arg2);
            status = SafeStorageHandleStore(arg2, Length16(arg2),
                                            arg1, Length16(arg1));
            ReportStatus("store", status);
        }
        else if (strcmp(command, "retrieve") == 0)
        {
            if (ReadToken(arg1, sizeof(arg1)) != SS_READ_OK ||
                ReadToken(arg2, sizeof(arg2)) != SS_READ_OK)
            {
                printf("Invalid or oversized paths. \r\n");
                if (feof(stdin) || ferror(stdin))
                {
                    break;
                }
                continue;
            }

            printf("retrieve with submission name [%s] destination file path [%s] \r\n",
                   arg1, arg2);
            status = SafeStorageHandleRetrieve(arg1, Length16(arg1),
                                               arg2, Length16(arg2));
            ReportStatus("retrieve", status);
        }
        else if (strcmp(command, "exit") == 0)
        {
            printf("Bye Bye! \r\n");
            break;
        }
        else
        {
            printf("Unknown command. Try again! \r\n");
        }
    }

    SafeStorageDeinit();
    return 0;
}
